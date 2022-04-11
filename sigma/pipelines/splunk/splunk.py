from sigma.pipelines.common import logsource_windows
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition
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

splunk_windows_process_creation_dm_mapping = {
    "CommandLine": "Processes.process",
    "Computer": "Processes.dest",
    "CurrentDirectory": "Processes.process_current_directory",
    "Image": "Processes.process_path",
    "IntegrityLevel": "Processes.process_integrity_level",
    "ParentCommandLine": "Processes.parent_process",
    "ParentImage": "Processes.parent_process_path",
    "ParentProcessGuid": "Processes.parent_process_guid",
    "ParentProcessId": "Processes.parent_process_id",
    "ProcessGuid": "Processes.process_guid",
    "ProcessId": "Processes.process_id",
    "User": "Processes.user",
}

splunk_windows_registry_dm_mapping = {
    "Computer": "Registry.dest",
    "Details": "Registry.registry_value_data",
    "EventType": "Registry.action", # EventType: DeleteKey is parsed to action: deleted
    "Image": "Registry.process_path",
    "ProcessGuid": "Registry.process_guid",
    "ProcessId": "Registry.process_id",
    "TargetObject": "Registry.registry_key_name",
}

splunk_windows_file_event_dm_mapping = {
    "Computer": "Filesystem.dest",
    "CreationUtcTime": "Filesystem.file_create_time",
    "Image": "Filesystem.process_path",
    "ProcessGuid": "Filesystem.process_guid",
    "ProcessId": "Filesystem.process_id",
    "TargetFilename": "Filesystem.file_path",
}

# registry rewrite EventType value

# file_delete

# dns

# wmi

def logsource_windows_process_creation():
    return LogsourceCondition(
        category="process_creation",
        product="windows",
    )

def logsource_windows_registry_add():
    return LogsourceCondition(
        category="registry_add",
        product="windows",
    )

def logsource_windows_registry_delete():
    return LogsourceCondition(
        category="registry_delete",
        product="windows",
    )

def logsource_windows_registry_event():
    return LogsourceCondition(
        category="registry_event",
        product="windows",
    )

def logsource_windows_registry_set():
    return LogsourceCondition(
        category="registry_set",
        product="windows",
    )

def logsource_windows_file_event():
    return LogsourceCondition(
        category="file_event",
        product="windows",
    )

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

def splunk_data_model():
    return ProcessingPipeline(
        name="Splunk Data Model Mapping for Sysmon Process Creation",
        priority=20,
        items=[
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_process_creation",
                transformation=FieldMappingTransformation(splunk_windows_process_creation_dm_mapping),
                rule_conditions=[
                    logsource_windows_process_creation()
                ]
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_process_creation_unsupported_fields",
                transformation=DetectionItemFailureTransformation("The Splunk Data Model backend does only support field which can mapped to Splunk Common Information Model."),
                rule_conditions=[
                    logsource_windows_process_creation()
                ],
                detection_item_conditions=[
                    IncludeFieldCondition(
                        fields = [splunk_windows_process_creation_dm_mapping.values()]
                    )
                ],
                detection_item_condition_linking=any,
                detection_item_condition_negation=True,
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_registry",
                transformation=FieldMappingTransformation(splunk_windows_registry_dm_mapping),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_registry_unsupported_fields",
                transformation=DetectionItemFailureTransformation("The Splunk Data Model backend does only support field which can mapped to Splunk Common Information Model."),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
                detection_item_conditions=[
                    IncludeFieldCondition(
                        fields = [
                            "NewName",
                        ]
                    )
                ]
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_file_event",
                transformation=FieldMappingTransformation(splunk_windows_file_event_dm_mapping),
                rule_conditions=[
                    logsource_windows_file_event(),
                ]
            ),
        ]
    )

