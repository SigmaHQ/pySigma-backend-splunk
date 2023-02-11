from .splunk import splunk_windows_pipeline, splunk_windows_sysmon_acceleration_keywords, splunk_cim_data_model

pipelines = {
    "splunk_windows": splunk_windows_pipeline,
    "splunk_sysmon_acceleration": splunk_windows_sysmon_acceleration_keywords,
    "splunk_cim": splunk_cim_data_model,
}