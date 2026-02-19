from .splunk import SplunkBackend
from .spl2 import SplunkSPL2Backend

backends = {
    "splunk": SplunkBackend,
    "splunk_spl2": SplunkSPL2Backend,
}
