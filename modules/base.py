"""Base Auditor and Data Loader for Zscaler Security Scanner."""
import csv, json, datetime
from pathlib import Path
from typing import Dict, List, Any

class BaseAuditor:
    SEVERITY_CRITICAL="CRITICAL"; SEVERITY_HIGH="HIGH"; SEVERITY_MEDIUM="MEDIUM"; SEVERITY_LOW="LOW"
    def __init__(self, data, baseline=None):
        self.data=data; self.baseline=baseline or {}; self.findings=[]
    def finding(self, check_id, title, severity, category, description,
                affected_items=None, remediation="", references=None, details=None):
        f={"check_id":check_id,"title":title,"severity":severity,"category":category,
           "description":description,"affected_items":affected_items or [],
           "affected_count":len(affected_items) if affected_items else 0,
           "remediation":remediation,"references":references or [],"details":details or {},
           "timestamp":datetime.datetime.now().isoformat()}
        self.findings.append(f); return f
    def run_all_checks(self)->List[Dict]: raise NotImplementedError
    def gb(self,key,default): return self.baseline.get(key,default)

FILE_MAP={
    # ZIA configs
    "url_filtering":["url_filtering_rules.json","url_filtering.json"],
    "ssl_inspection":["ssl_inspection_policy.json","ssl_inspection.json"],
    "firewall_rules":["firewall_rules.json","cloud_firewall.json"],
    "dlp_policy":["dlp_policy.json","dlp_rules.json"],
    "dlp_dictionaries":["dlp_dictionaries.json"],
    "sandbox_policy":["sandbox_policy.json","cloud_sandbox.json"],
    "malware_policy":["malware_policy.json","advanced_threat.json"],
    "cloud_app_control":["cloud_app_control.json","app_control.json"],
    "bandwidth_control":["bandwidth_control.json"],
    "browser_control":["browser_control.json"],
    # ZPA configs
    "zpa_access_policy":["zpa_access_policy.json","access_policy.json"],
    "zpa_app_segments":["zpa_app_segments.json","application_segments.json"],
    "zpa_app_connectors":["zpa_app_connectors.json","app_connectors.json"],
    "zpa_server_groups":["zpa_server_groups.json","server_groups.json"],
    "zpa_segment_groups":["zpa_segment_groups.json","segment_groups.json"],
    "zpa_posture_profiles":["zpa_posture_profiles.json","device_posture.json"],
    "zpa_service_edges":["zpa_service_edges.json"],
    # Shared configs
    "admin_users":["admin_users.json","administrators.json"],
    "admin_roles":["admin_roles.json"],
    "auth_config":["auth_config.json","authentication.json"],
    "idp_config":["idp_config.json","saml_config.json"],
    "locations":["locations.json","zia_locations.json"],
    "forwarding_policy":["forwarding_policy.json"],
    "audit_config":["audit_config.json","audit_log.json"],
    "notification_config":["notification_config.json"],
    "advanced_settings":["advanced_settings.json"],
    # DSPM
    "dspm_config":["dspm_config.json","data_security.json"],
    "dspm_classification":["dspm_classification.json","data_classification.json"],
    "dspm_policies":["dspm_policies.json","data_policies.json"],
}

class DataLoader:
    def __init__(self, data_dir):
        self.data_dir=Path(data_dir); self._data={}
    def load_all(self):
        for key,fnames in FILE_MAP.items():
            for fn in fnames:
                fp=self.data_dir/fn
                if fp.exists():
                    print(f"    Loading {fn}...")
                    try:
                        with open(fp,"r",encoding="utf-8-sig") as f:
                            self._data[key]=json.load(f)
                    except Exception as e:
                        print(f"    [WARN] {e}"); self._data[key]=None
                    break
            else: self._data[key]=None
        loaded=[k for k,v in self._data.items() if v is not None]
        print(f"    Loaded: {len(loaded)} configs ({', '.join(loaded[:10])}{'...' if len(loaded)>10 else ''})")
        return self._data
