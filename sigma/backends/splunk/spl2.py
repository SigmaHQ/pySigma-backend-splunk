import re
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import (
    ConditionFieldEqualsValueExpression,
    ConditionOR,
    ConditionAND,
    ConditionNOT,
    ConditionItem,
)
from sigma.types import SigmaCompareExpression, SigmaString
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
import sigma
from typing import Any, ClassVar, Dict, List, Optional, Pattern, Tuple, Union


class SplunkSPL2Backend(TextQueryBackend):
    """Splunk SPL2 backend."""

    name: ClassVar[str] = "Splunk SPL2 queries"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain SPL2 queries",
        "module": "SPL2 module output with $result = FROM ... assignments",
    }
    requires_pipeline: ClassVar[bool] = True

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionOR,
        ConditionAND,
    )
    group_expression: ClassVar[str] = "({expr})"

    bool_values = {True: "true", False: "false"}
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="

    field_quote: ClassVar[str] = "'"
    field_quote_pattern: ClassVar[Pattern] = re.compile(r"^[\w.]+$")

    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "%"
    wildcard_single: ClassVar[str] = "_"
    add_escaped: ClassVar[str] = "%_"

    wildcard_match_expression: ClassVar[str] = "{field} LIKE {value}"

    re_expression: ClassVar[str] = "match({field}, /(?i){regex}/)"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ("/",)

    cidr_expression: ClassVar[str] = '{field}="{value}"'

    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_equals_field_expression: ClassVar[str] = "{field1}={field2}"
    field_null_expression: ClassVar[str] = "{field} IS NULL"

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[Optional[str]] = "IN"
    list_separator: ClassVar[str] = ", "
    field_exists_expression: ClassVar[str] = "{field} IS NOT NULL"
    field_not_exists_expression: ClassVar[str] = "{field} IS NULL"

    unbound_value_str_expression: ClassVar[str] = "{value}"
    unbound_value_num_expression: ClassVar[str] = "{value}"
    unbound_value_re_expression: ClassVar[str] = "{value}"

    deferred_start: ClassVar[str] = "\n| "
    deferred_separator: ClassVar[str] = "\n| "
    deferred_only_query: ClassVar[str] = "*"

    # Use FROM dataset WHERE query pattern
    query_expression: ClassVar[str] = "FROM {state[dataset]} WHERE {query}"
    state_defaults: ClassVar[Dict[str, str]] = {"dataset": "main"}

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        dataset: str = "main",
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.dataset = dataset
        # Override state_defaults with the user-provided dataset
        self.state_defaults = {"dataset": dataset}

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        table_fields = " | table " + ", ".join(rule.fields) if rule.fields else ""
        return query + table_fields

    def finalize_query_module(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        return "$result = " + query

    def finalize_output_module(self, queries: List[str]) -> List[str]:
        return queries
