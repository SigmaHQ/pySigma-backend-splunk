import re
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredTextQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR
from sigma.types import SigmaCompareExpression
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.pipelines.splunk.splunk import splunk_sysmon_process_creation_cim_mapping, splunk_windows_registry_cim_mapping, splunk_windows_file_event_cim_mapping
import sigma
from typing import ClassVar, Dict, List, Optional, Pattern, Tuple

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
    group_expression : ClassVar[str] = "({expr})"

    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = " "
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = "="

    field_quote: ClassVar[str] = '"'
    field_quote_pattern: ClassVar[Pattern] = re.compile("^[\w.]+$")

    str_quote : ClassVar[str] = '"'
    escape_char : ClassVar[str] = "\\"
    wildcard_multi : ClassVar[str] = "*"
    wildcard_single : ClassVar[str] = "*"
    add_escaped : ClassVar[str] = "\\"

    re_expression : ClassVar[str] = "{regex}"
    re_escape_char : ClassVar[str] = "\\"
    re_escape : ClassVar[Tuple[str]] = ('"',)

    cidr_expression : ClassVar[str] = "{value}"

    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = "{field}!=*"

    convert_or_as_in : ClassVar[bool] = True
    convert_and_as_in : ClassVar[bool] = False
    in_expressions_allow_wildcards : ClassVar[bool] = True
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"
    or_in_operator : ClassVar[Optional[str]] = "IN"
    list_separator : ClassVar[str] = ", "

    unbound_value_str_expression : ClassVar[str] = '"{value}"'
    unbound_value_num_expression : ClassVar[str] = '{value}'
    unbound_value_re_expression : ClassVar[str] = '{value}'

    deferred_start : ClassVar[str] = "\n| "
    deferred_separator : ClassVar[str] = "\n| "
    deferred_only_query : ClassVar[str] = "*"

    def __init__(self, processing_pipeline: Optional["sigma.processing.pipeline.ProcessingPipeline"] = None, collect_errors: bool = False, min_time : str = "-30d", max_time : str = "now", **kwargs):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.min_time = min_time or "-30d"
        self.max_time = max_time or "now"

    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression, state : "sigma.conversion.state.ConversionState") -> SplunkDeferredRegularExpression:
        """Defer regular expression matching to pipelined regex command after main search expression."""
        if cond.parent_condition_chain_contains(ConditionOR):
            raise SigmaFeatureNotSupportedByBackendError("ORing regular expressions is not yet supported by Splunk backend", source=cond.source)
        return SplunkDeferredRegularExpression(state, cond.field, super().convert_condition_field_eq_val_re(cond, state)).postprocess(None, cond)

    def convert_condition_field_eq_val_cidr(self, cond : ConditionFieldEqualsValueExpression, state : "sigma.conversion.state.ConversionState") -> SplunkDeferredCIDRExpression:
        """Defer CIDR network range matching to pipelined where cidrmatch command after main search expression."""
        if cond.parent_condition_chain_contains(ConditionOR):
            raise SigmaFeatureNotSupportedByBackendError("ORing CIDR matching is not yet supported by Splunk backend", source=cond.source)
        return SplunkDeferredCIDRExpression(state, cond.field, super().convert_condition_field_eq_val_cidr(cond, state)).postprocess(None, cond)

    def finalize_query_savedsearches(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        clean_title = rule.title.translate({ord(c): None for c in "[]"})      # remove brackets from title
        escaped_query = " \\\n".join(query.split("\n"))      # escape line ends for multiline queries
        return f"""
[{clean_title}]
search = {escaped_query}"""

    def finalize_output_savedsearches(self, queries: List[str]) -> str:
        return f"""
[default]
dispatch.earliest_time = {self.min_time}
dispatch.latest_time = {self.max_time}
""" + "\n".join(queries)

    def finalize_query_data_model(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        data_model = None
        data_set = None
        cim_fields = None
        if rule.logsource.product and rule.logsource.category:
            if rule.logsource.product == "windows":
                if rule.logsource.category == "process_creation":
                    data_model = 'Endpoint'
                    data_set = 'Processes'
                    cim_fields = " ".join(splunk_sysmon_process_creation_cim_mapping.values())
                elif rule.logsource.category in ["registry_add", "registry_delete", "registry_event", "registry_set"]:
                    data_model = 'Endpoint'
                    data_set = 'Registry'
                    cim_fields = " ".join(splunk_windows_registry_cim_mapping.values())
                elif rule.logsource.category == "file_event":
                    data_model = 'Endpoint'
                    data_set = 'Filesystem'
                    cim_fields = " ".join(splunk_windows_file_event_cim_mapping.values())
            elif rule.logsource.product == "linux":
                if rule.logsource.category == "process_creation":
                    data_model = 'Endpoint'
                    data_set = 'Processes'
                    cim_fields = " ".join(splunk_sysmon_process_creation_cim_mapping.values())

        try:
            data_model_set = state.processing_state["data_model_set"]
        except KeyError:
            raise SigmaFeatureNotSupportedByBackendError("No data model specified by processing pipeline")

        try:
            data_set = data_model_set.split(".")[1]
        except IndexError:
            raise SigmaFeatureNotSupportedByBackendError("No data set specified by processing pipeline")

        try:
            fields = " ".join(state.processing_state["fields"])
        except KeyError:
            raise SigmaFeatureNotSupportedByBackendError("No fields specified by processing pipeline")

        return f"""| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel={data_model_set} where {query} by {fields}
| `drop_dm_object_name({data_set})`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace("\n", " ")

    def finalize_output_data_model(self, queries: List[str]) -> List[str]:
        return queries