import pytest
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline, splunk_windows_sysmon_acceleration_keywords
from sigma.pipelines.splunk.splunk import windows_service_source_mapping
from sigma.pipelines.sysmon import sysmon_pipeline

@pytest.mark.parametrize(
    ("service", "source"),
    windows_service_source_mapping.items()
)
def test_splunk_windows_pipeline_simple(service, source):
    assert SplunkBackend(processing_pipeline=splunk_windows_pipeline()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                service: {service}
            detection:
                sel:
                    EventID: 123
                    field: value
                condition: sel
        """)
    ) == [f"source=\"{source}\" EventCode=123 field=\"value\""]

def test_splunk_sysmon_process_creation_keyword_acceleration():
    assert SplunkBackend(processing_pipeline=sysmon_pipeline() + splunk_windows_pipeline() + splunk_windows_sysmon_acceleration_keywords()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                service: sysmon
                category: process_creation
            detection:
                sel:
                    field: value
                condition: sel
        """)
    ) == ['"ParentProcessGuid" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 field="value"']

def test_splunk_sysmon_file_creation_keyword_acceleration():
    assert SplunkBackend(processing_pipeline=sysmon_pipeline() + splunk_windows_pipeline() + splunk_windows_sysmon_acceleration_keywords()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                service: sysmon
                category: file_event
            detection:
                sel:
                    field: value
                condition: sel
        """)
    ) == ['"TargetFilename" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 field="value"']