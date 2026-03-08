#!/usr/bin/env python3
"""
Zscaler SASE & DSPM Security Scanner
========================================
Security posture scanner for Zscaler Internet Access (ZIA),
Zscaler Private Access (ZPA), and Data Security Posture Management (DSPM).

Usage:
    python zscaler_scanner.py --data-dir ./sample_data --output report.html
    python zscaler_scanner.py --data-dir ./exports --modules zia-url zia-ssl zpa-policy dspm
"""
import argparse,json,sys,datetime
from pathlib import Path
from modules.base import DataLoader
from modules.zia_security import (UrlFilteringAuditor,SslInspectionAuditor,
    CloudFirewallAuditor,ThreatPreventionAuditor)
from modules.zia_zpa_modules import (DlpDataProtectionAuditor,CloudAppControlAuditor,
    ZpaAccessPolicyAuditor,ZpaAppSecurityAuditor)
from modules.platform_dspm import (AdminSecurityAuditor,AuthIdpAuditor,
    DspmAuditor,AuditComplianceAuditor)

try: from modules.report_generator import ReportGenerator
except ImportError: ReportGenerator=None

def banner():
    print(r"""
  ╔═══════════════════════════════════════════════════════════════════╗
  ║   Zscaler SASE & DSPM Security Scanner v1.0                     ║
  ║   ZIA · ZPA · DSPM · Zero Trust Exchange                        ║
  ║   URL Filtering · SSL · DLP · Firewall · Access Policy · DSPM   ║
  ╚═══════════════════════════════════════════════════════════════════╝
    """)

MODULE_MAP={
    "zia-url":    ("ZIA URL Filtering Policy",UrlFilteringAuditor),
    "zia-ssl":    ("ZIA SSL/TLS Inspection",SslInspectionAuditor),
    "zia-fw":     ("ZIA Cloud Firewall",CloudFirewallAuditor),
    "zia-threat": ("ZIA Threat Prevention",ThreatPreventionAuditor),
    "zia-dlp":    ("ZIA DLP & Data Protection",DlpDataProtectionAuditor),
    "zia-app":    ("ZIA Cloud App Control",CloudAppControlAuditor),
    "zpa-policy": ("ZPA Access Policy",ZpaAccessPolicyAuditor),
    "zpa-app":    ("ZPA Application Security",ZpaAppSecurityAuditor),
    "admin":      ("Admin & Platform Security",AdminSecurityAuditor),
    "auth":       ("Authentication & IdP",AuthIdpAuditor),
    "dspm":       ("DSPM Controls",DspmAuditor),
    "audit":      ("Audit, Logging & Compliance",AuditComplianceAuditor),
}

def main():
    banner()
    parser=argparse.ArgumentParser(description="Zscaler SASE & DSPM Security Scanner")
    parser.add_argument("--data-dir",required=True)
    parser.add_argument("--output",default="zscaler_security_report.html")
    parser.add_argument("--severity",choices=["CRITICAL","HIGH","MEDIUM","LOW","ALL"],default="ALL")
    parser.add_argument("--modules",nargs="+",choices=list(MODULE_MAP.keys())+["all"],default=["all"])
    parser.add_argument("--config",default=None)
    args=parser.parse_args()
    data_dir=Path(args.data_dir)
    if not data_dir.exists(): print(f"[ERROR] Not found: {data_dir}"); sys.exit(1)
    print("[*] Loading Zscaler configuration data...")
    data=DataLoader(data_dir).load_all()
    baseline={}
    if args.config:
        with open(args.config) as f: baseline=json.load(f)
    run=list(MODULE_MAP.keys()) if "all" in args.modules else args.modules
    all_findings=[]
    for mod in run:
        if mod not in MODULE_MAP: continue
        label,cls=MODULE_MAP[mod]
        print(f"[*] Running {label}...")
        findings=cls(data,baseline).run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")
    sev={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    if args.severity!="ALL":
        t=sev.get(args.severity,3)
        all_findings=[f for f in all_findings if sev.get(f["severity"],3)<=t]
    meta={"scan_time":datetime.datetime.now().isoformat(),"data_directory":str(data_dir),
          "modules_run":run,"severity_filter":args.severity}
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
