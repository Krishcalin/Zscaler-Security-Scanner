#!/usr/bin/env python3
"""
CrowdStrike Falcon Deployment Validation Scanner
====================================================
Validates CrowdStrike Falcon configuration for policy gaps,
dangerous exclusions, sensor health, and MITRE ATT&CK coverage.

Usage:
    python cs_scanner.py --data-dir ./sample_data --output report.html
    python cs_scanner.py --data-dir ./exports --modules prevention exclusions sensors
"""
import argparse,json,sys,datetime
from pathlib import Path
from modules.base import DataLoader
from modules.policy_validation import (PreventionPolicyAuditor,SensorUpdateAuditor,
    ResponsePolicyAuditor,DeviceControlAuditor)
from modules.advanced_validation import (ExclusionAuditor,SensorHealthAuditor,
    AdminSecurityAuditor,CustomIoaAuditor,FirewallPolicyAuditor,MitreCoverageAuditor)

try: from modules.report_generator import ReportGenerator
except ImportError: ReportGenerator=None

def banner():
    print(r"""
  ╔═══════════════════════════════════════════════════════════════════╗
  ║   CrowdStrike Falcon Deployment Validation Scanner v1.0          ║
  ║                                                                  ║
  ║   Prevention · Exclusions · Sensors · Admin · MITRE ATT&CK      ║
  ║   Policy Gaps · Dangerous Paths · Coverage · Compliance          ║
  ╚═══════════════════════════════════════════════════════════════════╝
    """)

MODULE_MAP={
    "prevention":("Prevention Policy Validation",PreventionPolicyAuditor),
    "updates":   ("Sensor Update Policy",SensorUpdateAuditor),
    "response":  ("Response Policy",ResponsePolicyAuditor),
    "device":    ("Device Control",DeviceControlAuditor),
    "exclusions":("Exclusion Audit",ExclusionAuditor),
    "sensors":   ("Sensor Health & Coverage",SensorHealthAuditor),
    "admin":     ("Admin & API Security",AdminSecurityAuditor),
    "ioas":      ("Custom IOA Rules",CustomIoaAuditor),
    "firewall":  ("Firewall Policy",FirewallPolicyAuditor),
    "mitre":     ("MITRE ATT&CK Coverage",MitreCoverageAuditor),
}

def main():
    banner()
    parser=argparse.ArgumentParser(description="CrowdStrike Falcon Deployment Validation Scanner")
    parser.add_argument("--data-dir",required=True)
    parser.add_argument("--output",default="cs_validation_report.html")
    parser.add_argument("--severity",choices=["CRITICAL","HIGH","MEDIUM","LOW","ALL"],default="ALL")
    parser.add_argument("--modules",nargs="+",choices=list(MODULE_MAP.keys())+["all"],default=["all"])
    args=parser.parse_args()
    data_dir=Path(args.data_dir)
    if not data_dir.exists(): print(f"[ERROR] Not found: {data_dir}"); sys.exit(1)
    print("[*] Loading CrowdStrike Falcon configuration data...")
    data=DataLoader(data_dir).load_all()
    run=list(MODULE_MAP.keys()) if "all" in args.modules else args.modules
    all_findings=[]
    for mod in run:
        if mod not in MODULE_MAP: continue
        label,cls=MODULE_MAP[mod]
        print(f"[*] Running {label}...")
        findings=cls(data).run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")
    sev={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    if args.severity!="ALL":
        t=sev.get(args.severity,3)
        all_findings=[f for f in all_findings if sev.get(f["severity"],3)<=t]
    meta={"scan_time":datetime.datetime.now().isoformat(),"data_directory":str(data_dir),
          "modules_run":run,"severity_filter":args.severity,"platform":"CrowdStrike Falcon"}
    print(f"\n[*] Generating report: {args.output}")
    if ReportGenerator: ReportGenerator(all_findings,meta).generate(args.output)
    else:
        with open(args.output.replace(".html",".json"),"w") as f:
            json.dump({"findings":all_findings,"meta":meta},f,indent=2)
    c=sum(1 for f in all_findings if f["severity"]=="CRITICAL")
    h=sum(1 for f in all_findings if f["severity"]=="HIGH")
    m=sum(1 for f in all_findings if f["severity"]=="MEDIUM")
    l=sum(1 for f in all_findings if f["severity"]=="LOW")
    print(f"\n{'='*67}")
    print(f"  SCAN COMPLETE — {len(all_findings)} finding(s)")
    print(f"  CRITICAL: {c}  |  HIGH: {h}  |  MEDIUM: {m}  |  LOW: {l}")
    print(f"  Report: {args.output}")
    print(f"{'='*67}\n")

if __name__=="__main__": main()
