from test_backend_splunk import splunk_backend
from sigma.collection import SigmaCollection


def test_correlation_and_subrule_fields_are_deduplicated(splunk_backend):
    collection = SigmaCollection.from_yaml(
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
fields:
    - fieldB
    - fieldC
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldD
    timespan: 15m
    condition:
        gte: 10
        """
    )

    assert splunk_backend.convert(collection) == [
        '''fieldA="value1"

| bin _time span=15m
| stats count as event_count values(fieldA) as fieldA values(fieldB) as fieldB values(fieldC) as fieldC by _time fieldD

| search event_count >= 10'''
    ]


def test_value_count_retains_context_fields(splunk_backend):
    collection = SigmaCollection.from_yaml(
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
    - fieldE
---
title: Correlation
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        gte: 5
        field: fieldD
        """
    )

    assert splunk_backend.convert(collection) == [
        '''fieldA="value1"

| bin _time span=15m
| stats dc(fieldD) as value_count values(fieldA) as fieldA values(fieldE) as fieldE by _time fieldC

| search value_count >= 5'''
    ]


def test_temporal_correlation_retains_context_fields(splunk_backend):
    collection = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
    condition: selection
fields:
    - fieldE
    - fieldC
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldB: value2
    condition: selection
fields:
    - fieldF
    - fieldC
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 15m
        """
    )

    assert splunk_backend.convert(collection) == [
        '''| multisearch
[ search fieldA="value1" | eval event_type="base_rule_1" ]
[ search fieldB="value2" | eval event_type="base_rule_2" ]

| bin _time span=15m
| stats dc(event_type) as event_type_count values(fieldE) as fieldE values(fieldF) as fieldF by _time fieldC

| search event_type_count >= 2'''
    ]
