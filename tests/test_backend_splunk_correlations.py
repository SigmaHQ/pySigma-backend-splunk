from test_backend_splunk import splunk_backend
from sigma.collection import SigmaCollection

def test_event_count_correlation_rule_stats_query(splunk_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
        - fieldD
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert splunk_backend.convert(correlation_rule) == [
        """fieldA="value1" fieldB="value2"

| bin _time span=15m
| stats count as event_count by _time fieldC fieldD

| search event_count >= 10"""
    ]

def test_value_count_correlation_rule_stats_query(splunk_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        lt: 10
        field: fieldD
            """
    )
    assert splunk_backend.convert(correlation_rule) == [
        """fieldA="value1" fieldB="value2"

| bin _time span=15m
| stats dc(fieldD) as value_count by _time fieldC

| search value_count < 10"""
    ]

def test_temporal_correlation_rule_stats_query(splunk_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    aliases:
        field:
            base_rule_1: fieldC
            base_rule_2: fieldD
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    assert splunk_backend.convert(correlation_rule) == [
        """| multisearch
[ search fieldA="value1" fieldB="value2" | eval event_type="base_rule_1" | rename fieldC as field ]
[ search fieldA="value3" fieldB="value4" | eval event_type="base_rule_2" | rename fieldD as field ]

| bin _time span=15m
| stats dc(event_type) as event_type_count by _time fieldC

| search event_type_count >= 2"""]

def test_temporal_extended_correlation_rule_stats_query(splunk_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Base rule 3
name: base_rule_3
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value5
        fieldB: value6
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    aliases:
        field:
            base_rule_1: fieldC
            base_rule_2: fieldD
    group-by:
        - fieldC
    condition: base_rule_1 and base_rule_2 and not base_rule_3
    timespan: 15m
"""
    )
    assert splunk_backend.convert(correlation_rule) == [
        """| multisearch
[ search fieldA="value1" fieldB="value2" | eval event_type="base_rule_1" | rename fieldC as field ]
[ search fieldA="value3" fieldB="value4" | eval event_type="base_rule_2" | rename fieldD as field ]
[ search fieldA="value5" fieldB="value6" | eval event_type="base_rule_3" ]

| bin _time span=15m
| stats values(event_type) as event_types by _time fieldC

| search event_types="base_rule_1"   event_types="base_rule_2"   NOT event_types="base_rule_3\""""]

def test_event_count_correlation_rule_with_regex_deferred(splunk_backend):
    """Test that deferred regex expressions are included in correlation sub-queries."""
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB|re: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
        - base_rule2
    group-by:
        - fieldC
        - fieldD
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert splunk_backend.convert(correlation_rule) == [
        """| multisearch
[ search fieldA="value1" fieldB="value2" | eval event_type="base_rule" ]
[ search fieldA="value1"
| regex fieldB="value2" | eval event_type="base_rule2" ]

| bin _time span=15m
| stats count as event_count by _time fieldC fieldD

| search event_count >= 10"""
    ]

def test_single_rule_correlation_with_regex_deferred(splunk_backend):
    """Test that deferred regex expressions are included in single-rule correlation queries."""
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB|re: value2
    condition: selection
---
title: Single rule correlation
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert splunk_backend.convert(correlation_rule) == [
        """fieldA="value1"
| regex fieldB="value2"

| bin _time span=15m
| stats count as event_count by _time fieldC

| search event_count >= 10"""
    ]

def test_event_count_correlation_rule_with_regex_or_deferred(splunk_backend):
    """Test that deferred OR regex expressions (rex) are included in correlation sub-queries."""
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule2
status: test
logsource:
    category: test
detection:
    sel1:
        fieldA|re: value1
    sel2:
        fieldB|re: value2
    condition: sel1 or sel2
---
title: Correlation
status: test
correlation:
    type: event_count
    rules:
        - base_rule
        - base_rule2
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert splunk_backend.convert(correlation_rule) == [
        """| multisearch
[ search fieldA="value1" fieldB="value2" | eval event_type="base_rule" ]
[ search \n| rex field=fieldA "(?<fieldAMatch>value1)"
| eval fieldACondition=if(isnotnull(fieldAMatch), "true", "false")
| rex field=fieldB "(?<fieldBMatch>value2)"
| eval fieldBCondition=if(isnotnull(fieldBMatch), "true", "false")
| search fieldACondition="true" OR fieldBCondition="true" | eval event_type="base_rule2" ]

| bin _time span=15m
| stats count as event_count by _time fieldC

| search event_count >= 10"""
    ]

def test_correlation_rule_subrule_fields_not_in_output(splunk_backend):
    """Test that sub-rule fields (| table) are not included in correlation queries."""
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
fields:
    - fieldA
    - fieldB
---
title: Correlation
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gte: 10
            """
    )
    result = splunk_backend.convert(correlation_rule)
    assert "table" not in result[0]
    assert result == [
        """fieldA="value1"

| bin _time span=15m
| stats count as event_count by _time fieldC

| search event_count >= 10"""
    ]