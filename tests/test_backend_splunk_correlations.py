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

| search event_type_count >= 2"""
    ]
