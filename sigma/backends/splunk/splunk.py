import re
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredTextQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR, ConditionAND, ConditionNOT, ConditionItem
from sigma.types import SigmaCompareExpression
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.pipelines.splunk.splunk import splunk_sysmon_process_creation_cim_mapping, splunk_windows_registry_cim_mapping, splunk_windows_file_event_cim_mapping
import sigma
from typing import Callable, ClassVar, Dict, List, Optional, Pattern, Tuple

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
    name : ClassVar[str] = "Splunk SPL & tstats data model queries"               # A descriptive name of the backend
    formats : ClassVar[Dict[str, str]] = {                # Output formats provided by the backend as name -> description mapping. The name should match to finalize_output_<name>.
        "default": "Plain SPL queries",
        "savedsearches": "Plain SPL in a savedsearches.conf file",
        "data_model": "Data model queries with tstats",
        "savedsearches_accelerated_data_model": "Accelerated data model queries with tstats in a savedsearches.conf file"
    }
    requires_pipeline : ClassVar[bool] = True             # Does the backend requires that a processing pipeline is provided?

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionOR, ConditionAND)
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

    unbound_value_str_expression : ClassVar[str] = '{value}'
    unbound_value_num_expression : ClassVar[str] = '{value}'
    unbound_value_re_expression : ClassVar[str] = '{value}'

    deferred_start : ClassVar[str] = "\n| "
    deferred_separator : ClassVar[str] = "\n| "
    deferred_only_query : ClassVar[str] = "*"

    def __init__(self, processing_pipeline: Optional["sigma.processing.pipeline.ProcessingPipeline"] = None, collect_errors: bool = False, min_time : str = "-30d", max_time : str = "now", query_settings : Callable[[SigmaRule], Dict[str, str]] = lambda x: {}, output_settings : Dict = {}, **kwargs):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.query_settings = query_settings
        self.output_settings = {"dispatch.earliest_time": min_time, "dispatch.latest_time": max_time}
        self.output_settings.update(output_settings)

    @staticmethod
    def _generate_settings(settings):
        """Format a settings dict into newline separated k=v string. Escape multi-line values."""
        output = ""
        for k, v in settings.items():
            output += f"\n{k} = " + " \\\n".join(v.split("\n"))  # cannot use \ in f-strings
        return output

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

    def finalize_query_default(self, rule : SigmaRule, query : str, index : int, state : ConversionState) -> str:
        table_fields = " | table " + ",".join(rule.fields) if rule.fields else ""
        return query + table_fields

    def finalize_query_savedsearches(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        clean_title = rule.title.translate({ord(c): None for c in "[]"})      # remove brackets from title
        query_settings = self.query_settings(rule)
        query_settings["description"] = rule.description.strip() if rule.description else ""
        query_settings["search"] = query + ("\n| table " + ",".join(rule.fields) if rule.fields else "")

        return f"\n[{clean_title}]" + self._generate_settings(query_settings)

    def finalize_output_savedsearches(self, queries: List[str]) -> str:
        return f"\n[default]" + self._generate_settings(self.output_settings) + "\n" + "\n".join(queries)

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
    
    def finalize_query_savedsearches_accelerated_data_model(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
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


        # Reusing code from finalize_query_savedsearches(), and adding additional fields which are generated by the Save As -> Alert interface in Splunk.
        clean_title = rule.title.translate({ord(c): None for c in "[]"})      # remove brackets from title
        query_settings = self.query_settings(rule)
        query_settings['alert.suppress'] = str(0)
        query_settings['alert.track'] = str(1)
        query_settings['counttype'] = 'number of events'
        query_settings['cron_schedule'] = '0 * * * *'
        query_settings['description'] = rule.description.strip() if rule.description else ""
        query_settings['dispatch.earliest_time'] = '-65m@m'
        query_settings['dispatch.latest_time'] = '-5m@m' 
        query_settings['display.events.fields'] = str(["host","tag::eventtype"]).replace("'",'"') 
        query_settings['display.events.type'] = 'raw'
        query_settings['display.general.type'] = 'statistics'
        query_settings['display.page.search.mode'] = 'fast'
        query_settings['display.page.search.tab'] = 'statistics'
        query_settings['enableSched'] = str(1)
        query_settings['quantity'] = str(0)
        query_settings['relation'] = 'greater than'
        query_settings["search"] = f"""| tstats summariesonly=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel={data_model_set} where {query} by {fields}
| `drop_dm_object_name({data_set})`
| convert timeformat="%F %X" ctime(firstTime) ctime(lastTime)
""".replace("\n", " ")

        return f"\n[{clean_title}]" + self._generate_settings(query_settings)

    def finalize_output_savedsearches_accelerated_data_model(self, queries: List[str]) -> List[str]:
        return queries