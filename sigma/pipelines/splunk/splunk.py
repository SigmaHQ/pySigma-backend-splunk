from sigma.pipelines.common import logsource_windows
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

windows_service_source_mapping = {      # mapping between Sigma Windows log source services and Splunk source identifiers
    "security": "WinEventLog:Security",
    "application": "WinEventLog:Application",
    "system": "WinEventLog:System",
    "sysmon": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
    "powershell": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
    "powershell-classic": "WinEventLog:Windows PowerShell",
    "taskscheduler": "WinEventLog:Microsoft-Windows-TaskScheduler/Operational",
    "wmi": "WinEventLog:Microsoft-Windows-WMI-Activity/Operational",
    "dns-server": "WinEventLog:DNS Server",
    "dns-server-audit": "WinEventLog:Microsoft-Windows-DNS-Server/Audit",
    "driver-framework": "WinEventLog:Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "ntlm": "WinEventLog:Microsoft-Windows-NTLM/Operational",
    "dhcp": "WinEventLog:Microsoft-Windows-DHCP-Server/Operational",
    "applocker": "WinEventLog:MSExchange Management",
    "printservice-admin": "WinEventLog:Microsoft-Windows-PrintService/Admin",
    "printservice-operational": "WinEventLog:Microsoft-Windows-PrintService/Operational",
    "codeintegrity-operational": "WinEventLog:Microsoft-Windows-CodeIntegrity/Operational",
    "smbclient-security": "WinEventLog:Microsoft-Windows-SmbClient/Security",
    "firewall-as": "WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "bits-client": "WinEventLog:Microsoft-Windows-Bits-Client/Operational",
}

windows_sysmon_acceleration_keywords = {    # Map Sysmon event sources and keywords that are added to search for Sysmon optimization pipeline
   "process_creation": "ParentProcessGuid",
   "file_event": "TargetFilename",
}

def splunk_windows_pipeline():
    return ProcessingPipeline(
        name="Splunk Windows log source conditions",
        priority=20,
        items=[
            ProcessingItem(         # log sources mapped from windows_service_source_mapping
                identifier=f"splunk_windows_{service}",
                transformation=AddConditionTransformation({ "source": source}),
                rule_conditions=[logsource_windows(service)],
            )
            for service, source in windows_service_source_mapping.items()
        ] + [
            ProcessingItem(     # Field mappings
                identifier="splunk_windows_field_mapping",
                transformation=FieldMappingTransformation({
                    "EventID": "EventCode",
                })
            )
        ],
    )

def splunk_windows_sysmon_acceleration_keywords():
    return ProcessingPipeline(
        name="Splunk Windows Sysmon search acceleration keywords",
        priority=25,
        items=[
            ProcessingItem(     # Some optimizations searching for characteristic keyword for specific log sources
                identifier="splunk_windows_sysmon_process_creation",
                transformation=AddConditionTransformation({
                    None: keyword,
                }),
                rule_conditions=[
                    LogsourceCondition(
                        category=sysmon_category,
                        product="windows",
                        service="sysmon",
                    )
                ]
            )
            for sysmon_category, keyword in windows_sysmon_acceleration_keywords.items()
        ]
    )