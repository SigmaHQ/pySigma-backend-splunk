import re
from sigma.conversion.state import ConversionState
from sigma.modifiers import SigmaRegularExpression
from sigma.rule import SigmaRule, SigmaDetection
from sigma.conversion.base import TextQueryBackend
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
)
import sigma
from typing import Any, Callable, ClassVar, Dict, List, Optional, Pattern, Tuple


class SplunkDeferredRegularExpression(DeferredTextQueryExpression):
    template = 'regex {field}{op}"{value}"'
    operators = {
        True: "!=",
        False: "=",
    }
    default_field = "_raw"


class SplunkDeferredCIDRExpression(DeferredTextQueryExpression):
    template = 'where {op}cidrmatch("{value}", {field})'
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

    cidr_expression: ClassVar[str] = "{value}"

    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[str] = "{field}!=*"

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = True
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[Optional[str]] = "IN"
    list_separator: ClassVar[str] = ", "

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

    def convert_rule(
        self, rule: SigmaRule, output_format: Optional[str] = None
    ) -> List[Any]:
        """
        Convert a single Sigma rule into the target data structure (usually query, see above).
        """

        print("----------------------------------------------")
        print(rule.detection)
        # detect if there is an ORing regex
        # pprint(rule.detection.parsed_condition[0].parsed)

        def replace_regex(detections: List[SigmaDetection]):
            rex_pipes = []
            eval_pipes = []
            print("enter replace regex")
            print(detections)
            for index_detection in detections.keys():
                detection = rule.detection.detections[index_detection]
                for index_detection_item, detection_item in enumerate(
                    detection.detection_items
                ):
                    for item_value in detection_item.value:
                        if isinstance(item_value, SigmaRegularExpression):

                            # 1. fill prefix
                            match_name = detection_item.field + "Match"  # CamlCase
                            condition_name = detection_item.field + "Condition"
                            rex_pipes.append(
                                f'| rex field={detection_item.field} "(?<{match_name}>{item_value.regexp})"'
                            )
                            eval_pipes.append(
                                f'| eval {condition_name}=if(isnotnull({match_name}), "true", "false")'
                            )
                            # 2. replace exp value (SigmaRegularExpression -> str)

                            detection_item.field = condition_name
                            detection_item.value = [SigmaString("true")]
                            detection_item.modifiers = []
                            detections[index_detection].detection_items[
                                index_detection_item
                            ] = detection_item
                            print(f"after replacement")
                            print(detections)

                    query_prefix = " ".join(rex_pipes) + " " + " ".join(eval_pipes)
            return query_prefix, detections

        try:
            self.last_processing_pipeline = (
                self.backend_processing_pipeline
                + self.processing_pipeline
                + self.output_format_processing_pipeline[
                    output_format or self.default_format
                ]
            )

            error_state = "applying processing pipeline on"
            self.last_processing_pipeline.apply(rule)  # 1. Apply transformations

            # 2. Convert conditions
            error_state = "converting"
            states = [
                ConversionState(
                    processing_state=dict(self.last_processing_pipeline.state)
                )
                for _ in rule.detection.parsed_condition
            ]
            import copy

            rule_copy = copy.deepcopy(rule)
            queries = []
            for index, cond in enumerate(rule.detection.parsed_condition):
                try:
                    queries.append(self.convert_condition(cond.parsed, states[index]))
                except SigmaFeatureNotSupportedByBackendError:

                    query_prefix, detections = replace_regex(
                        rule_copy.detection.detections
                    )
                    rule_fixed = rule_copy
                    rule_fixed.detection.detections = detections
                    queries.append(
                        query_prefix
                        + " | search "
                        + self.convert_condition(
                            rule_fixed.detection.parsed_condition[index].parsed,
                            states[index],
                        )
                    )

            error_state = "finalizing query for"
            finalized_queries = [  # 3. Postprocess generated query
                self.finalize_query(
                    rule,
                    query,
                    index,
                    states[index],
                    output_format or self.default_format,
                )
                for index, query in enumerate(queries)
            ]
            rule.set_conversion_result(finalized_queries)
            if rule._output:
                return finalized_queries
            else:
                return []
        except SigmaError as e:
            if self.collect_errors:
                self.errors.append((rule, e))
                return []
            else:
                raise e
        except (
            Exception
        ) as e:  # enrich all other exceptions with Sigma-specific context information
            msg = f" (while {error_state} rule {str(rule.source)})"
            if len(e.args) > 1:
                e.args = (e.args[0] + msg,) + e.args[1:]
            else:
                e.args = (e.args[0] + msg,)
            raise

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
            raise SigmaFeatureNotSupportedByBackendError(
                "ORing regular expressions is not yet supported by Splunk backend",
                source=cond.source,
            )
        return SplunkDeferredRegularExpression(
            state, cond.field, super().convert_condition_field_eq_val_re(cond, state)
        ).postprocess(None, cond)

    def convert_condition_field_eq_val_cidr(
        self,
        cond: ConditionFieldEqualsValueExpression,
        state: "sigma.conversion.state.ConversionState",
    ) -> SplunkDeferredCIDRExpression:
        """Defer CIDR network range matching to pipelined where cidrmatch command after main search expression."""
        if cond.parent_condition_chain_contains(ConditionOR):
            raise SigmaFeatureNotSupportedByBackendError(
                "ORing CIDR matching is not yet supported by Splunk backend",
                source=cond.source,
            )
        return SplunkDeferredCIDRExpression(
            state, cond.field, super().convert_condition_field_eq_val_cidr(cond, state)
        ).postprocess(None, cond)

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

        try:
            data_model_set = state.processing_state["data_model_set"]
        except KeyError:
            raise SigmaFeatureNotSupportedByBackendError(
                "No data model specified by processing pipeline"
            )

        try:
            data_set = data_model_set.split(".")[1]
        except IndexError:
            raise SigmaFeatureNotSupportedByBackendError(
                "No data set specified by processing pipeline"
            )

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
