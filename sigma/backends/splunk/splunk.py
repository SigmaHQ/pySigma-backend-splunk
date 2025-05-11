import re
from sigma.conversion.state import ConversionState
from sigma.modifiers import SigmaRegularExpression
from sigma.rule import SigmaRule, SigmaDetection
from sigma.conversion.base import TextQueryBackend, DeferredQueryExpression
from sigma.conversion.deferred import DeferredTextQueryExpression
from sigma.conditions import (
    ConditionFieldEqualsValueExpression,
    ConditionOR,
    ConditionAND,
    ConditionNOT,
    ConditionItem,
)
from sigma.types import SigmaCompareExpression, SigmaString
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError, SigmaError
from sigma.pipelines.splunk.splunk import (
    splunk_sysmon_process_creation_cim_mapping,
    splunk_windows_registry_cim_mapping,
    splunk_windows_file_event_cim_mapping,
    splunk_web_proxy_cim_mapping,
)
import sigma
from typing import Any, Callable, ClassVar, Dict, List, Optional, Pattern, Tuple, Union


class SplunkDeferredRegularExpression(DeferredTextQueryExpression):
    template = 'regex {field}{op}"{value}"'
    operators = {
        True: "!=",
        False: "=",
    }
    default_field = "_raw"


class SplunkDeferredORRegularExpression(DeferredTextQueryExpression):
    field_counts = {}
    default_field = "_raw"
    operators = {
        True: "!=",
        False: "=",
    }

    def __init__(self, state, field, arg) -> None:
        self.add_field(field)
        field_condition = self.get_field_condition(field)
        field_match = self.get_field_match(field)
        self.template = 'rex field={{field}} "(?<{field_match}>{{value}})"\n| eval {field_condition}=if(isnotnull({field_match}), "true", "false")'.format(
            field_match=field_match, field_condition=field_condition
        )
        return super().__init__(state, field, arg)

    @staticmethod
    def clean_field(field):
        # splunk does not allow dots in regex group, so we need to clean variables
        return re.sub(".*\\.", "", field)

    @classmethod
    def add_field(cls, field):
        cls.field_counts[field] = (
            cls.field_counts.get(field, 0) + 1
        )  # increment the field count

    @classmethod
    def get_field_suffix(cls, field):
        index_suffix = cls.field_counts.get(field, "")
        if index_suffix == 1:
            index_suffix = ""
        return index_suffix

    @classmethod
    def construct_field_variable(cls, field, variable):
        cleaned_field = cls.clean_field(field)
        index_suffix = cls.get_field_suffix(field)
        return f"{cleaned_field}{variable}{index_suffix}"

    @classmethod
    def get_field_match(cls, field):
        return cls.construct_field_variable(field, "Match")

    @classmethod
    def get_field_condition(cls, field):
        return cls.construct_field_variable(field, "Condition")

    @classmethod
    def reset(cls):
        cls.field_counts = {}


class SplunkDeferredFieldRefExpression(DeferredTextQueryExpression):
    template = "where {op}'{field}'='{value}'"
    operators = {
        True: "NOT ",
        False: "",
    }
    default_field = "_raw"


class SplunkBackend(TextQueryBackend):
    """Splunk SPL backend."""

    name: ClassVar[str] = (
        "Splunk SPL & tstats data model queries"  # A descriptive name of the backend
    )
    formats: ClassVar[Dict[str, str]] = (
        {  # Output formats provided by the backend as name -> description mapping. The name should match to finalize_output_<name>.
            "default": "Plain SPL queries",
            "savedsearches": "Plain SPL in a savedsearches.conf file",
            "data_model": "Data model queries with tstats",
        }
    )
    requires_pipeline: ClassVar[bool] = (
        True  # Does the backend requires that a processing pipeline is provided?
    )

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionOR,
        ConditionAND,
    )
    group_expression: ClassVar[str] = "({expr})"

    bool_values = {True: "true", False: "false"}
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = " "
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="

    field_quote: ClassVar[str] = '"'
    field_quote_pattern: ClassVar[Pattern] = re.compile(r"^[\w.]+$")

    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    add_escaped: ClassVar[str] = "\\"

    re_expression: ClassVar[str] = "{regex}"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ('"',)

    cidr_expression: ClassVar[str] = '{field}="{value}"'

    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_equals_field_expression: ClassVar[str] = "{field2}"
    field_null_expression: ClassVar[str] = "NOT {field}=*"

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = True
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[Optional[str]] = "IN"
    list_separator: ClassVar[str] = ", "
    field_exists_expression: ClassVar[str] = "{field}=*"
    field_not_exists_expression: ClassVar[str] = "NOT {field}=*"

    unbound_value_str_expression: ClassVar[str] = "{value}"
    unbound_value_num_expression: ClassVar[str] = "{value}"
    unbound_value_re_expression: ClassVar[str] = "{value}"

    deferred_start: ClassVar[str] = "\n| "
    deferred_separator: ClassVar[str] = "\n| "
    deferred_only_query: ClassVar[str] = "*"

    # Correlations
    correlation_methods: ClassVar[Dict[str, str]] = {
        "stats": "Correlation using stats command (more efficient, static time window)",
        # "transaction": "Correlation using transaction command (less efficient, sliding time window",
    }
    default_correlation_method: ClassVar[str] = "stats"
    default_correlation_query: ClassVar[str] = {
        "stats": "{search}\n\n{aggregate}\n\n{condition}"
    }

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_search_multi_rule_expression: ClassVar[str] = "| multisearch\n{queries}"
    correlation_search_multi_rule_query_expression: ClassVar[str] = (
        '[ search {query} | eval event_type="{ruleid}"{normalization} ]'
    )
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = "\n"

    correlation_search_field_normalization_expression: ClassVar[str] = (
        " | rename {field} as {alias}"
    )
    correlation_search_field_normalization_expression_joiner: ClassVar[str] = ""

    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| bin _time span={timespan}\n| stats count as event_count by _time{groupby}",
    }
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| bin _time span={timespan}\n| stats dc({field}) as value_count by _time{groupby}",
    }
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| bin _time span={timespan}\n| stats dc(event_type) as event_type_count by _time{groupby}",
    }

    timespan_mapping: ClassVar[Dict[str, str]] = {
        "M": "mon",
    }

    groupby_expression: ClassVar[Dict[str, str]] = {"stats": " {fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"stats": "{field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"stats": " "}

    event_count_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| search event_count {op} {count}"
    }
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| search value_count {op} {count}"
    }
    temporal_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| search event_type_count {op} {count}"
    }

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        min_time: str = "-30d",
        max_time: str = "now",
        query_settings: Callable[[SigmaRule], Dict[str, str]] = lambda x: {},
        output_settings: Dict = {},
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.query_settings = query_settings
        self.output_settings = {
            "dispatch.earliest_time": min_time,
            "dispatch.latest_time": max_time,
        }
        self.output_settings.update(output_settings)

    @staticmethod
    def _generate_settings(settings):
        """Format a settings dict into newline separated k=v string. Escape multi-line values."""
        output = ""
        for k, v in settings.items():
            output += f"\n{k} = " + " \\\n".join(
                v.split("\n")
            )  # cannot use \ in f-strings
        return output

    def convert_condition_field_eq_val_re(
        self,
        cond: ConditionFieldEqualsValueExpression,
        state: "sigma.conversion.state.ConversionState",
    ) -> SplunkDeferredRegularExpression:
        """Defer regular expression matching to pipelined regex command after main search expression."""

        if cond.parent_condition_chain_contains(ConditionOR):
            # adding the deferred to the state
            SplunkDeferredORRegularExpression(
                state,
                cond.field,
                super().convert_condition_field_eq_val_re(cond, state),
            ).postprocess(None, cond)

            cond_true = ConditionFieldEqualsValueExpression(
                SplunkDeferredORRegularExpression.get_field_condition(cond.field),
                SigmaString("true"),
            )
            # returning fieldX=true
            return super().convert_condition_field_eq_val_str(cond_true, state)
        return SplunkDeferredRegularExpression(
            state, cond.field, super().convert_condition_field_eq_val_re(cond, state)
        ).postprocess(None, cond)

    def convert_condition_field_eq_field(
        self,
        cond: ConditionFieldEqualsValueExpression,
        state: "sigma.conversion.state.ConversionState",
    ) -> SplunkDeferredFieldRefExpression:
        """Defer FieldRef matching to pipelined with `where` command after main search expression."""
        if cond.parent_condition_chain_contains(ConditionOR):
            raise SigmaFeatureNotSupportedByBackendError(
                "ORing FieldRef matching is not yet supported by Splunk backend",
                source=cond.source,
            )
        return SplunkDeferredFieldRefExpression(
            state, cond.field, super().convert_condition_field_eq_field(cond, state)
        ).postprocess(None, cond)

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Union[str, DeferredQueryExpression],
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> Union[str, DeferredQueryExpression]:

        if state.has_deferred():
            deferred_regex_or_expressions = []
            no_regex_oring_deferred_expressions = []

            for index, deferred_expression in enumerate(state.deferred):

                if type(deferred_expression) == SplunkDeferredORRegularExpression:
                    deferred_regex_or_expressions.append(
                        deferred_expression.finalize_expression()
                    )
                else:
                    no_regex_oring_deferred_expressions.append(deferred_expression)

            if len(deferred_regex_or_expressions) > 0:
                SplunkDeferredORRegularExpression.reset()  # need to reset class for potential future conversions
                # remove deferred oring regex expressions from the state
                # as they will be taken into account by the super().finalize_query
                state.deferred = no_regex_oring_deferred_expressions

                return super().finalize_query(
                    rule,
                    self.deferred_start
                    + self.deferred_separator.join(deferred_regex_or_expressions)
                    + "\n| search "
                    + query,
                    index,
                    state,
                    output_format,
                )

        return super().finalize_query(rule, query, index, state, output_format)

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        table_fields = " | table " + ",".join(rule.fields) if rule.fields else ""
        return query + table_fields

    def finalize_query_savedsearches(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        clean_title = rule.title.translate(
            {ord(c): None for c in "[]"}
        )  # remove brackets from title
        query_settings = self.query_settings(rule)
        query_settings["description"] = (
            rule.description.strip() if rule.description else ""
        )
        query_settings["search"] = query + (
            "\n| table " + ",".join(rule.fields) if rule.fields else ""
        )

        return f"\n[{clean_title}]" + self._generate_settings(query_settings)

    def finalize_output_savedsearches(self, queries: List[str]) -> str:
        return (
            f"\n[default]"
            + self._generate_settings(self.output_settings)
            + "\n"
            + "\n".join(queries)
        )

    def finalize_query_data_model(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        data_model = None
        data_set = None
        cim_fields = None
        if rule.logsource.product and rule.logsource.category:
            if rule.logsource.product == "windows":
                if rule.logsource.category == "process_creation":
                    data_model = "Endpoint"
                    data_set = "Processes"
                    cim_fields = " ".join(
                        splunk_sysmon_process_creation_cim_mapping.values()
                    )
                elif rule.logsource.category in [
                    "registry_add",
                    "registry_delete",
                    "registry_event",
                    "registry_set",
                ]:
                    data_model = "Endpoint"
                    data_set = "Registry"
                    cim_fields = " ".join(splunk_windows_registry_cim_mapping.values())
                elif rule.logsource.category == "file_event":
                    data_model = "Endpoint"
                    data_set = "Filesystem"
                    cim_fields = " ".join(
                        splunk_windows_file_event_cim_mapping.values()
                    )
            elif rule.logsource.product == "linux":
                if rule.logsource.category == "process_creation":
                    data_model = "Endpoint"
                    data_set = "Processes"
                    cim_fields = " ".join(
                        splunk_sysmon_process_creation_cim_mapping.values()
                    )

        elif rule.logsource.category == "proxy":
            data_model = "Web"
            data_set = "Proxy"
            cim_fields = " ".join(splunk_web_proxy_cim_mapping.values())

        try:
            data_model_set = state.processing_state["data_model_set"]
        except KeyError:
            raise SigmaFeatureNotSupportedByBackendError(
                "No data model specified by processing pipeline"
            )

        if not data_model_set:
            raise SigmaFeatureNotSupportedByBackendError(
                "No data set specified by processing pipeline"
            )

        if "." in data_model_set:
            parts = data_model_set.split(".")
            if len(parts) != 2 or not all(parts):
                raise SigmaFeatureNotSupportedByBackendError(
                    "Expected format 'data_model.data_set', but got: {}".format(data_model_set)
                )
            data_set = parts[1]

        try:
            fields = " ".join(state.processing_state["fields"])
        except KeyError:
            raise SigmaFeatureNotSupportedByBackendError(
                "No fields specified by processing pipeline"
            )

        return f"""| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel={data_model_set} where {query} by {fields}
| `drop_dm_object_name({data_set})`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace(
            "\n", " "
        )

    def finalize_output_data_model(self, queries: List[str]) -> List[str]:
        return queries
