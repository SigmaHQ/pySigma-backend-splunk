from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
import pytest
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.splunk import splunk_cim_data_model

@pytest.fixture
def splunk_backend():
    return SplunkBackend()

def test_splunk_and_expression(splunk_backend : SplunkBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)

    assert splunk_backend.convert(rule) == ['fieldA="valueA" fieldB="valueB"']

def test_splunk_or_expression(splunk_backend : SplunkBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)
    assert splunk_backend.convert(rule) == ['fieldA="valueA" OR fieldB="valueB"']

def test_splunk_and_or_expression(splunk_backend : SplunkBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)
    assert splunk_backend.convert(rule) == ['fieldA IN ("valueA1", "valueA2") fieldB IN ("valueB1", "valueB2")']

def test_splunk_or_and_expression(splunk_backend : SplunkBackend):
    rule = SigmaCollection.from_yaml("""
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
        """)
    assert splunk_backend.convert(rule) == ['(fieldA="valueA1" fieldB="valueB1") OR (fieldA="valueA2" fieldB="valueB2")']

def test_splunk_in_expression(splunk_backend : SplunkBackend):
    assert splunk_backend.convert(
        SigmaCollection.from_yaml("""
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
                        - valueC*
                condition: sel
        """)
    ) == ['fieldA IN ("valueA", "valueB", "valueC*")']

def test_splunk_field_name_with_whitespace(splunk_backend : SplunkBackend):
    assert splunk_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: valueA
                condition: sel
        """)
    ) == ['"field name"="valueA"']

def test_splunk_regex_query(splunk_backend : SplunkBackend):
    assert splunk_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ["fieldB=\"foo\" fieldC=\"bar\"\n| regex fieldA=\"foo.*bar\""]

def test_splunk_regex_query_implicit_or(splunk_backend : SplunkBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="ORing regular expressions"):
        splunk_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|re:
                            - foo.*bar
                            - boo.*foo
                        fieldB: foo
                        fieldC: bar
                    condition: sel
            """)
        )

def test_splunk_regex_query_explicit_or(splunk_backend : SplunkBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="ORing regular expressions"):
        splunk_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel1:
                        fieldA|re: foo.*bar
                    sel2:
                        fieldB|re: boo.*foo
                    condition: sel1 or sel2
            """)
        )

def test_splunk_single_regex_query(splunk_backend : SplunkBackend):
    assert splunk_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                condition: sel
        """)
    ) == ["*\n| regex fieldA=\"foo.*bar\""]

def test_splunk_cidr_query(splunk_backend : SplunkBackend):
    assert splunk_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr: 192.168.0.0/16
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) == ["fieldB=\"foo\" fieldC=\"bar\"\n| where cidrmatch(\"192.168.0.0/16\", fieldA)"]

def test_splunk_cidr_or(splunk_backend : SplunkBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="ORing CIDR"):
        splunk_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|cidr:
                            - 192.168.0.0/16
                            - 10.0.0.0/8
                        fieldB: foo
                        fieldC: bar
                    condition: sel
            """)
        )

def test_splunk_savedsearch_output(splunk_backend : SplunkBackend):
    rules = """
title: Test 1
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
---
title: Test 2
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: foo
        fieldB: bar
    condition: sel
    """
    assert splunk_backend.convert(SigmaCollection.from_yaml(rules), "savedsearches") == """
[default]
dispatch.earliest_time = -30d
dispatch.latest_time = now

[Test 1]
search = fieldB="foo" fieldC="bar" \\
| regex fieldA="foo.*bar"

[Test 2]
search = fieldA="foo" fieldB="bar\""""

def test_splunk_data_model_process_creation():
    splunk_backend = SplunkBackend(processing_pipeline=splunk_cim_data_model())
    rule = """
title: Test
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: test
    condition: sel
    """
    assert splunk_backend.convert(SigmaCollection.from_yaml(rule), "data_model") == ["""| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
Processes.process="test" by Processes.process Processes.dest Processes.process_current_directory Processes.process_path Processes.process_integrity_level Processes.parent_process
Processes.parent_process_path Processes.parent_process_guid Processes.parent_process_id Processes.process_guid Processes.process_id Processes.user
| `drop_dm_object_name(Processes)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace("\n", " ")]

def test_splunk_data_model_registry_add():
    splunk_backend = SplunkBackend(processing_pipeline=splunk_cim_data_model())
    rule = """
title: Test
status: test
logsource:
    category: registry_add
    product: windows
detection:
    sel:
        TargetObject: test
    condition: sel
    """
    assert splunk_backend.convert(SigmaCollection.from_yaml(rule), "data_model") == ["""| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
Registry.registry_key_name="test" by Registry.dest Registry.registry_value_data Registry.action Registry.process_path Registry.process_guid Registry.process_id Registry.registry_key_name
| `drop_dm_object_name(Registry)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace("\n", " ")]

def test_splunk_data_model_registry_delete():
    splunk_backend = SplunkBackend(processing_pipeline=splunk_cim_data_model())
    rule = """
title: Test
status: test
logsource:
    category: registry_delete
    product: windows
detection:
    sel:
        TargetObject: test
    condition: sel
    """
    assert splunk_backend.convert(SigmaCollection.from_yaml(rule), "data_model") == ["""| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
Registry.registry_key_name="test" by Registry.dest Registry.registry_value_data Registry.action Registry.process_path Registry.process_guid Registry.process_id Registry.registry_key_name
| `drop_dm_object_name(Registry)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace("\n", " ")]

def test_splunk_data_model_registry_event():
    splunk_backend = SplunkBackend(processing_pipeline=splunk_cim_data_model())
    rule = """
title: Test
status: test
logsource:
    category: registry_event
    product: windows
detection:
    sel:
        TargetObject: test
    condition: sel
    """
    assert splunk_backend.convert(SigmaCollection.from_yaml(rule), "data_model") == ["""
| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
Registry.registry_key_name="test" by Registry.dest Registry.registry_value_data Registry.action Registry.process_path Registry.process_guid Registry.process_id Registry.registry_key_name
| `drop_dm_object_name(Registry)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace("\n", "")]

def test_splunk_data_model_registry_event():
    splunk_backend = SplunkBackend(processing_pipeline=splunk_cim_data_model())
    rule = """
title: Test
status: test
logsource:
    category: registry_event
    product: windows
detection:
    sel:
        TargetObject: test
    condition: sel
    """
    assert splunk_backend.convert(SigmaCollection.from_yaml(rule), "data_model") == ["""| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
Registry.registry_key_name="test" by Registry.dest Registry.registry_value_data Registry.action Registry.process_path Registry.process_guid Registry.process_id Registry.registry_key_name
| `drop_dm_object_name(Registry)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace("\n", " ")]

def test_splunk_data_model_registry_set():
    splunk_backend = SplunkBackend(processing_pipeline=splunk_cim_data_model())
    rule = """
title: Test
status: test
logsource:
    category: registry_set
    product: windows
detection:
    sel:
        TargetObject: test
    condition: sel
    """
    assert splunk_backend.convert(SigmaCollection.from_yaml(rule), "data_model") == ["""| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where
Registry.registry_key_name="test" by Registry.dest Registry.registry_value_data Registry.action Registry.process_path Registry.process_guid Registry.process_id Registry.registry_key_name
| `drop_dm_object_name(Registry)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace("\n", " ")]

def test_splunk_data_model_file_event():
    splunk_backend = SplunkBackend(processing_pipeline=splunk_cim_data_model())
    rule = """
title: Test
status: test
logsource:
    category: file_event
    product: windows
detection:
    sel:
        TargetFilename: test
    condition: sel
    """
    assert splunk_backend.convert(SigmaCollection.from_yaml(rule), "data_model") == ["""| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where
Filesystem.file_path="test" by Filesystem.dest Filesystem.file_create_time Filesystem.process_path Filesystem.process_guid Filesystem.process_id Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace("\n", " ")]

def test_splunk_data_model_process_creation_linux():
    splunk_backend = SplunkBackend(processing_pipeline=splunk_cim_data_model())
    rule = """
title: Test
status: test
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        CommandLine: test
    condition: sel
    """
    assert splunk_backend.convert(SigmaCollection.from_yaml(rule), "data_model") == ["""| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where
Processes.process="test" by Processes.process Processes.dest Processes.process_current_directory Processes.process_path Processes.process_integrity_level Processes.parent_process
Processes.parent_process_path Processes.parent_process_guid Processes.parent_process_id Processes.process_guid Processes.process_id Processes.user
| `drop_dm_object_name(Processes)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
""".replace("\n", " ")]

def test_splunk_data_model_no_data_model_specified():
    splunk_backend = SplunkBackend()
    rule = """
title: Test
status: test
logsource:
    product: windows
    service: security
detection:
    sel:
        CommandLine: test
    condition: sel
    """
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="No data model specified"):
        splunk_backend.convert(SigmaCollection.from_yaml(rule), "data_model")