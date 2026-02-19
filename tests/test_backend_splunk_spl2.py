import pytest
from sigma.backends.splunk import SplunkSPL2Backend
from sigma.collection import SigmaCollection


@pytest.fixture
def spl2_backend():
    return SplunkSPL2Backend()


def test_spl2_and_expression(spl2_backend: SplunkSPL2Backend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
    )
    assert spl2_backend.convert(rule) == [
        'FROM main WHERE fieldA="valueA" AND fieldB="valueB"'
    ]


def test_spl2_or_expression(spl2_backend: SplunkSPL2Backend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
    )
    assert spl2_backend.convert(rule) == [
        'FROM main WHERE fieldA="valueA" OR fieldB="valueB"'
    ]


def test_spl2_and_or_expression(spl2_backend: SplunkSPL2Backend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
    )
    assert spl2_backend.convert(rule) == [
        'FROM main WHERE fieldA IN ("valueA1", "valueA2") AND fieldB IN ("valueB1", "valueB2")'
    ]


def test_spl2_or_and_expression(spl2_backend: SplunkSPL2Backend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
    )
    assert spl2_backend.convert(rule) == [
        'FROM main WHERE (fieldA="valueA1" AND fieldB="valueB1") OR (fieldA="valueA2" AND fieldB="valueB2")'
    ]


def test_spl2_in_expression(spl2_backend: SplunkSPL2Backend):
    assert (
        spl2_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC
                condition: sel
        """
            )
        )
        == ['FROM main WHERE fieldA IN ("valueA", "valueB", "valueC")']
    )


def test_spl2_in_expression_with_wildcards(spl2_backend: SplunkSPL2Backend):
    """Wildcards in IN lists should be converted to individual LIKE expressions."""
    assert (
        spl2_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB*
                        - valueC
                condition: sel
        """
            )
        )
        == ['FROM main WHERE fieldA="valueA" OR fieldA LIKE "valueB%" OR fieldA="valueC"']
    )


def test_spl2_not_expression(spl2_backend: SplunkSPL2Backend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                filter:
                    fieldB: valueB
                condition: sel and not filter
        """
    )
    assert spl2_backend.convert(rule) == [
        'FROM main WHERE fieldA="valueA" AND NOT fieldB="valueB"'
    ]


def test_spl2_wildcard_match(spl2_backend: SplunkSPL2Backend):
    """Wildcards in the middle of a string should use LIKE."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: val*ue
                condition: sel
        """
    )
    assert spl2_backend.convert(rule) == [
        'FROM main WHERE fieldA LIKE "val%ue"'
    ]


def test_spl2_startswith(spl2_backend: SplunkSPL2Backend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: test
                condition: sel
        """
    )
    assert spl2_backend.convert(rule) == [
        'FROM main WHERE fieldA LIKE "test%"'
    ]


def test_spl2_endswith(spl2_backend: SplunkSPL2Backend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: .exe
                condition: sel
        """
    )
    assert spl2_backend.convert(rule) == [
        'FROM main WHERE fieldA LIKE "%.exe"'
    ]


def test_spl2_contains(spl2_backend: SplunkSPL2Backend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: test
                condition: sel
        """
    )
    assert spl2_backend.convert(rule) == [
        'FROM main WHERE fieldA LIKE "%test%"'
    ]


def test_spl2_regex_query(spl2_backend: SplunkSPL2Backend):
    assert (
        spl2_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                condition: sel
        """
            )
        )
        == ['FROM main WHERE match(fieldA, /(?i)foo.*bar/)']
    )


def test_spl2_regex_query_with_other_conditions(spl2_backend: SplunkSPL2Backend):
    assert (
        spl2_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """
            )
        )
        == ['FROM main WHERE match(fieldA, /(?i)foo.*bar/) AND fieldB="foo" AND fieldC="bar"']
    )


def test_spl2_cidr_query(spl2_backend: SplunkSPL2Backend):
    assert (
        spl2_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == ['FROM main WHERE fieldA="192.168.0.0/16"']
    )


def test_spl2_field_name_with_whitespace(spl2_backend: SplunkSPL2Backend):
    assert (
        spl2_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: valueA
                condition: sel
        """
            )
        )
        == ["FROM main WHERE 'field name'=\"valueA\""]
    )


def test_spl2_exists(spl2_backend: SplunkSPL2Backend):
    assert (
        spl2_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|exists: yes
                        fieldB|exists: no
                    condition: sel
            """
            )
        )
        == ['FROM main WHERE fieldA IS NOT NULL AND fieldB IS NULL']
    )


def test_spl2_null_expression(spl2_backend: SplunkSPL2Backend):
    """Test that null values produce IS NULL."""
    assert (
        spl2_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA: null
                    condition: sel
            """
            )
        )
        == ['FROM main WHERE fieldA IS NULL']
    )


def test_spl2_compare_gt(spl2_backend: SplunkSPL2Backend):
    assert (
        spl2_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|gt: 100
                condition: sel
        """
            )
        )
        == ['FROM main WHERE fieldA>100']
    )


def test_spl2_compare_lt(spl2_backend: SplunkSPL2Backend):
    assert (
        spl2_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|lt: 50
                condition: sel
        """
            )
        )
        == ['FROM main WHERE fieldA<50']
    )


def test_spl2_fields_output(spl2_backend: SplunkSPL2Backend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            fields:
                - fieldA
                - fieldB
            detection:
                sel:
                    fieldA: valueA
                condition: sel
        """
    )
    assert spl2_backend.convert(rule) == [
        'FROM main WHERE fieldA="valueA" | table fieldA, fieldB'
    ]


def test_spl2_module_output(spl2_backend: SplunkSPL2Backend):
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                condition: sel
        """
    )
    assert spl2_backend.convert(rule, "module") == [
        '$result = FROM main WHERE fieldA="valueA"'
    ]


def test_spl2_custom_dataset():
    backend = SplunkSPL2Backend(dataset="myindex")
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                condition: sel
        """
    )
    assert backend.convert(rule) == [
        'FROM myindex WHERE fieldA="valueA"'
    ]


def test_spl2_wildcard_escaping_percent(spl2_backend: SplunkSPL2Backend):
    """Literal % characters in values should be escaped."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: 100%done
                condition: sel
        """
    )
    result = spl2_backend.convert(rule)
    assert result == ['FROM main WHERE fieldA="100\\%done"']


def test_spl2_wildcard_escaping_underscore(spl2_backend: SplunkSPL2Backend):
    """Literal _ characters in values should be escaped."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: some_value
                condition: sel
        """
    )
    result = spl2_backend.convert(rule)
    assert result == ['FROM main WHERE fieldA="some\\_value"']


def test_spl2_example_simple_rule(spl2_backend: SplunkSPL2Backend):
    """Test the simple example from the issue."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    ParentImage|endswith: '\\httpd.exe'
                    Image|endswith: '\\cmd.exe'
                condition: sel
        """
    )
    result = spl2_backend.convert(rule)
    assert result == [
        'FROM main WHERE ParentImage LIKE "%\\httpd.exe" AND Image LIKE "%\\cmd.exe"'
    ]


def test_spl2_example_exists_check(spl2_backend: SplunkSPL2Backend):
    """Test the exists check example from the issue."""
    rule = SigmaCollection.from_yaml(
        """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    EventID: 4688
                    SubjectUserName|exists: yes
                filter:
                    TargetUserName|exists: no
                condition: sel and not filter
        """
    )
    result = spl2_backend.convert(rule)
    assert result == [
        'FROM main WHERE EventID=4688 AND SubjectUserName IS NOT NULL AND NOT TargetUserName IS NULL'
    ]


def test_spl2_backend_registration():
    """Test that the backend is properly registered."""
    from sigma.backends.splunk import backends
    assert "splunk_spl2" in backends
    assert backends["splunk_spl2"] is SplunkSPL2Backend
