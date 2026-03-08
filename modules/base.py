"""Base Auditor and CrowdStrike Falcon Configuration Data Loader."""
import json, datetime
from pathlib import Path
from typing import Dict, List, Any

class BaseAuditor:
    SEVERITY_CRITICAL="CRITICAL"; SEVERITY_HIGH="HIGH"; SEVERITY_MEDIUM="MEDIUM"; SEVERITY_LOW="LOW"
    def __init__(self, data, baseline=None):
        self.data=data; self.baseline=baseline or {}; self.findings=[]
    def finding(self, cid, title, sev, cat, desc, items=None, remed="", refs=None,
                details=None, remediation=None, references=None):
        f={"check_id":cid,"title":title,"severity":sev,"category":cat,"description":desc,
           "affected_items":items or [],"affected_count":len(items) if items else 0,
           "remediation":remediation or remed,"references":references or refs or [],
           "details":details or {},"timestamp":datetime.datetime.now().isoformat()}
        self.findings.append(f); return f
    def run_all_checks(self)->List[Dict]: raise NotImplementedError

FILE_MAP={
    "prevention_policies":["prevention_policies.json","prevent_policies.json"],
    "sensor_update_policies":["sensor_update_policies.json","update_policies.json"],
    "response_policies":["response_policies.json","rtr_policies.json"],
    "device_control_policies":["device_control_policies.json","usb_policies.json"],
    "firewall_policies":["firewall_policies.json","fw_policies.json"],
    "ml_exclusions":["ml_exclusions.json","machine_learning_exclusions.json"],
    "ioa_exclusions":["ioa_exclusions.json"],
    "sv_exclusions":["sv_exclusions.json","sensor_visibility_exclusions.json"],
    "host_groups":["host_groups.json","groups.json"],
    "hosts":["hosts.json","devices.json","sensors.json"],
    "custom_ioas":["custom_ioas.json","custom_ioa_rules.json"],
    "admin_users":["admin_users.json","falcon_users.json"],
    "admin_roles":["admin_roles.json","falcon_roles.json"],
    "api_clients":["api_clients.json","oauth_clients.json"],
    "audit_log":["audit_log.json","audit_events.json"],
    "identity_policies":["identity_policies.json","idp_policies.json"],
    "notification_policies":["notification_policies.json","notifications.json"],
    "spotlight_vulns":["spotlight_vulns.json","vulnerabilities.json"],
    "discover_assets":["discover_assets.json","unmanaged_assets.json"],
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
                        with open(fp,"r",encoding="utf-8-sig") as f: self._data[key]=json.load(f)
                    except Exception as e: print(f"    [WARN] {e}"); self._data[key]=None
                    break
            else: self._data[key]=None
        loaded=sum(1 for v in self._data.values() if v is not None)
        print(f"    Loaded: {loaded}/{len(FILE_MAP)} config files")
        return self._data
