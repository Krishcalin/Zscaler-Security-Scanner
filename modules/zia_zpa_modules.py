"""
Modules 5-8: DLP, Cloud App Control, ZPA Access Policy, ZPA App Security
"""
from collections import defaultdict
from typing import List, Dict, Any
from modules.base import BaseAuditor

# ═══ Module 5: DLP & Data Protection ═══
class DlpDataProtectionAuditor(BaseAuditor):
    STANDARD_DICTIONARIES=["SSN","Credit Card","PII","HIPAA","PCI","GDPR","Financial","Source Code"]
    def run_all_checks(self)->List[Dict]:
        self.check_dlp_policy(); self.check_dlp_dictionaries()
        self.check_dlp_engines(); self.check_dlp_actions()
        self.check_icap_integration()
        return self.findings
    def check_dlp_policy(self):
        dlp=self.data.get("dlp_policy")
        if not dlp:
            self.finding("ZIA-DLP-001","No DLP policy configured",self.SEVERITY_HIGH,
                "DLP & Data Protection","Data Loss Prevention is not configured.",
                remediation="Configure DLP rules for sensitive data (SSN, CC, PII, source code).",
                references=["Zscaler DLP Best Practices"])
            return
        rules=dlp if isinstance(dlp,list) else dlp.get("rules",dlp.get("dlpRules",[]))
        if not rules:
            self.finding("ZIA-DLP-001","DLP policy has no rules",self.SEVERITY_HIGH,
                "DLP & Data Protection","DLP config exists but has no rules.",
                remediation="Create DLP rules.",references=["Zscaler DLP Best Practices"])
    def check_dlp_dictionaries(self):
        dicts=self.data.get("dlp_dictionaries")
        if not dicts: return
        dl=dicts if isinstance(dicts,list) else dicts.get("dictionaries",[])
        names=[d.get("name","") for d in dl if isinstance(d,dict)]
        missing=[s for s in self.STANDARD_DICTIONARIES if not any(s.upper() in n.upper() for n in names)]
        if missing:
            self.finding("ZIA-DLP-002",f"Standard DLP dictionaries missing ({len(missing)})",
                self.SEVERITY_MEDIUM,"DLP & Data Protection",
                f"{len(missing)} standard dictionaries not configured.",
                [f"Missing: {m}" for m in missing],
                "Add DLP dictionaries for SSN, Credit Card, PII, HIPAA, PCI, GDPR.",
                ["Zscaler — DLP Dictionary Best Practices"])
    def check_dlp_engines(self):
        dlp=self.data.get("dlp_policy") or {}
        if isinstance(dlp,dict) and not dlp.get("exactDataMatch",{}).get("enabled",False):
            self.finding("ZIA-DLP-003","Exact Data Match (EDM) not enabled",self.SEVERITY_MEDIUM,
                "DLP & Data Protection","EDM provides highest-accuracy DLP detection.",
                remediation="Enable EDM with indexed datasets for key data types.",
                references=["Zscaler — EDM Configuration"])
    def check_dlp_actions(self):
        dlp=self.data.get("dlp_policy")
        if not dlp: return
        rules=dlp if isinstance(dlp,list) else dlp.get("rules",[])
        allow_only=[r.get("name","") for r in rules if isinstance(r,dict)
                   and r.get("action","").upper() in ("ALLOW","AUDIT_ONLY","MONITOR")]
        if allow_only and len(allow_only)==len(rules):
            self.finding("ZIA-DLP-004","All DLP rules in monitor-only mode",self.SEVERITY_HIGH,
                "DLP & Data Protection","No DLP rules actively blocking data exfiltration.",
                allow_only[:10],"Set critical DLP rules to BLOCK action.",
                references=["Zscaler DLP — Enforcement Mode"])
    def check_icap_integration(self):
        dlp=self.data.get("dlp_policy") or {}
        if isinstance(dlp,dict) and not dlp.get("icapEnabled",False):
            pass  # ICAP is optional, not a finding

# ═══ Module 6: Cloud App Control ═══
class CloudAppControlAuditor(BaseAuditor):
    RISKY_APPS=["BitTorrent","Tor","Ultrasurf","Psiphon","Hola VPN","TeamViewer","AnyDesk",
        "LogMeIn","Mega","MediaFire","Anonymous Proxy","VPN Services"]
    def run_all_checks(self)->List[Dict]:
        self.check_app_control_policy(); self.check_risky_apps()
        self.check_shadow_it(); self.check_tenant_restrictions()
        return self.findings
    def check_app_control_policy(self):
        ac=self.data.get("cloud_app_control")
        if not ac:
            self.finding("ZIA-APP-001","No Cloud App Control policy configured",self.SEVERITY_HIGH,
                "Cloud App Control","Cloud applications are not being controlled.",
                remediation="Configure Cloud App Control for SaaS visibility and control.",
                references=["Zscaler — Cloud App Control"])
    def check_risky_apps(self):
        ac=self.data.get("cloud_app_control")
        if not ac: return
        rules=ac if isinstance(ac,list) else ac.get("rules",[])
        allowed=[]
        for r in rules:
            if r.get("action","").upper() in ("ALLOW",""):
                apps=r.get("applications",r.get("cloudApps",[]))
                for a in apps:
                    name=a if isinstance(a,str) else a.get("name","")
                    if any(ra.upper() in name.upper() for ra in self.RISKY_APPS):
                        allowed.append(f"Rule '{r.get('name','')}': allows {name}")
        if allowed:
            self.finding("ZIA-APP-002",f"Risky applications allowed ({len(allowed)})",self.SEVERITY_HIGH,
                "Cloud App Control","High-risk apps (torrents, VPN bypass, remote access) allowed.",
                allowed[:15],"Block BitTorrent, Tor, anonymous proxies, unauthorized remote access.",
                ["Zscaler Baseline — Risk Index Apps"])
    def check_shadow_it(self):
        ac=self.data.get("cloud_app_control") or {}
        if isinstance(ac,dict) and not ac.get("shadowItDiscovery",ac.get("saasDiscovery",True)):
            self.finding("ZIA-APP-003","Shadow IT/SaaS discovery not enabled",self.SEVERITY_MEDIUM,
                "Cloud App Control","Unsanctioned SaaS usage is not being detected.",
                remediation="Enable SaaS security and shadow IT discovery.",
                references=["Zscaler — SaaS Security"])
    def check_tenant_restrictions(self):
        ac=self.data.get("cloud_app_control") or {}
        if isinstance(ac,dict) and not ac.get("tenantRestrictions",{}).get("enabled",False):
            self.finding("ZIA-APP-004","Tenant restrictions not configured",self.SEVERITY_MEDIUM,
                "Cloud App Control","Users can access personal M365/Google tenants.",
                remediation="Configure tenant restrictions for M365 and Google Workspace.",
                references=["Zscaler — Tenant Restrictions"])

# ═══ Module 7: ZPA Access Policy ═══
class ZpaAccessPolicyAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_access_policy_exists(); self.check_overly_permissive()
        self.check_posture_enforcement(); self.check_risk_score()
        self.check_default_deny(); self.check_timeout_policy()
        return self.findings
    def _rules(self):
        d=self.data.get("zpa_access_policy")
        if not d: return []
        return d if isinstance(d,list) else d.get("rules",d.get("accessPolicyRules",[]))
    def check_access_policy_exists(self):
        if not self._rules():
            self.finding("ZPA-POL-001","No ZPA access policy rules configured",self.SEVERITY_CRITICAL,
                "ZPA Access Policy","ZPA has no access policy — all access is uncontrolled.",
                remediation="Configure granular access policies per application segment.",
                references=["Zscaler ZPA — Access Policy Best Practices"])
    def check_overly_permissive(self):
        rules=self._rules(); broad=[]
        for r in rules:
            action=r.get("action","").upper()
            if action != "ALLOW": continue
            apps=r.get("appSegmentGroups",r.get("applicationSegments",[]))
            users=r.get("conditions",r.get("criteria",[]))
            if not apps or str(apps).lower() in ("any","all","*","[]"):
                broad.append(f"Rule '{r.get('name','')}': allows access to ALL app segments")
            elif not users or str(users).lower() in ("any","all","*","[]"):
                broad.append(f"Rule '{r.get('name','')}': allows ALL users")
        if broad:
            self.finding("ZPA-POL-002",f"Overly permissive ZPA access rules ({len(broad)})",
                self.SEVERITY_HIGH,"ZPA Access Policy",
                "Access rules grant broad access — violates least privilege.",broad[:15],
                "Restrict access rules to specific SCIM groups and app segments.",
                ["Zscaler ZPA — Least Privilege","Zero Trust Segmentation"])
    def check_posture_enforcement(self):
        rules=self._rules(); no_posture=[]
        for r in rules:
            if r.get("action","").upper()!="ALLOW": continue
            posture=r.get("postureProfile",r.get("devicePosture",r.get("deviceTrustLevel","")))
            if not posture:
                no_posture.append(r.get("name","unknown"))
        if no_posture:
            self.finding("ZPA-POL-003",f"Access rules without device posture check ({len(no_posture)})",
                self.SEVERITY_HIGH,"ZPA Access Policy",
                "Access rules don't verify device compliance (OS patches, AV, disk encryption).",
                no_posture[:15],
                "Add device posture profiles to all critical access rules.",
                ["Zscaler ZPA — Adaptive Access Policy","Device Posture Best Practices"])
    def check_risk_score(self):
        rules=self._rules(); no_risk=[]
        for r in rules:
            if r.get("action","").upper()!="ALLOW": continue
            risk=r.get("userRiskScoreLevel",r.get("riskScore",""))
            if not risk: no_risk.append(r.get("name","unknown"))
        if no_risk and len(no_risk)==len([r for r in self._rules() if r.get("action","").upper()=="ALLOW"]):
            self.finding("ZPA-POL-004","No ZPA rules use user risk score",self.SEVERITY_MEDIUM,
                "ZPA Access Policy","User risk scoring not used in any access decision.",
                remediation="Enable adaptive access with user risk score levels.",
                references=["Zscaler — User Risk Scoring","ZPA Adaptive Access"])
    def check_default_deny(self):
        rules=self._rules()
        if rules:
            last=rules[-1]
            if last.get("action","").upper()!="DENY":
                self.finding("ZPA-POL-005","ZPA default access rule is not deny",self.SEVERITY_HIGH,
                    "ZPA Access Policy",f"Default rule: {last.get('action','')} (should be DENY).",
                    remediation="Ensure default ZPA rule is DENY (zero trust).",
                    references=["Zero Trust — Default Deny"])
    def check_timeout_policy(self):
        d=self.data.get("zpa_access_policy") or {}
        if isinstance(d,dict):
            timeout=d.get("reauthTimeout",d.get("session_timeout",0))
            if timeout:
                try:
                    if int(str(timeout))>43200:
                        self.finding("ZPA-POL-006",f"ZPA re-auth timeout too long ({timeout}s)",
                            self.SEVERITY_MEDIUM,"ZPA Access Policy",
                            "Long re-auth windows reduce session security.",
                            remediation="Set re-auth timeout ≤12 hours.",
                            references=["Zscaler — Session Security"])
                except ValueError: pass

# ═══ Module 8: ZPA Application Security ═══
class ZpaAppSecurityAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_wildcard_segments(); self.check_connector_health()
        self.check_segment_isolation(); self.check_bypass_settings()
        self.check_server_group_mapping()
        return self.findings
    def check_wildcard_segments(self):
        segs=self.data.get("zpa_app_segments")
        if not segs: return
        sl=segs if isinstance(segs,list) else segs.get("segments",segs.get("applicationSegments",[]))
        wildcards=[]
        for s in sl:
            if not isinstance(s,dict): continue
            domains=s.get("domainNames",s.get("domains",[]))
            for d in domains:
                if "*" in str(d) or str(d).startswith("*."):
                    wildcards.append(f"Segment '{s.get('name','')}': {d}")
        if wildcards:
            self.finding("ZPA-APP-001",f"Wildcard application segments ({len(wildcards)})",self.SEVERITY_HIGH,
                "ZPA Application Security","Wildcard segments expose more than intended.",wildcards[:15],
                "Replace wildcards with explicit FQDNs. Use app discovery to identify actual apps.",
                ["Zscaler ZPA — Application Segmentation Best Practices"])
    def check_connector_health(self):
        conn=self.data.get("zpa_app_connectors")
        if not conn: return
        cl=conn if isinstance(conn,list) else conn.get("connectors",[])
        unhealthy=[f"{c.get('name','')}: {c.get('status','')}" for c in cl
                  if isinstance(c,dict) and c.get("status","").upper() not in ("HEALTHY","UP","CONNECTED","ACTIVE")]
        if unhealthy:
            self.finding("ZPA-APP-002",f"Unhealthy App Connectors ({len(unhealthy)})",self.SEVERITY_HIGH,
                "ZPA Application Security","App Connectors not in healthy state.",unhealthy,
                "Investigate and restore unhealthy connectors.",
                references=["Zscaler ZPA — App Connector Troubleshooting"])
    def check_segment_isolation(self):
        segs=self.data.get("zpa_app_segments")
        if not segs: return
        sl=segs if isinstance(segs,list) else segs.get("segments",[])
        broad=[s.get("name","") for s in sl if isinstance(s,dict)
              and len(s.get("domainNames",s.get("domains",[])))>20]
        if broad:
            self.finding("ZPA-APP-003",f"Application segments with many domains ({len(broad)})",
                self.SEVERITY_MEDIUM,"ZPA Application Security",
                "Large segments reduce micro-segmentation granularity.",broad,
                "Break large segments into smaller, function-specific segments.",
                references=["Zscaler — Zero Trust Micro-Segmentation"])
    def check_bypass_settings(self):
        segs=self.data.get("zpa_app_segments")
        if not segs: return
        sl=segs if isinstance(segs,list) else segs.get("segments",[])
        bypassed=[s.get("name","") for s in sl if isinstance(s,dict)
                 and s.get("bypassType","").upper() in ("ALWAYS","ON_NET")]
        if bypassed:
            self.finding("ZPA-APP-004",f"Segments with bypass enabled ({len(bypassed)})",self.SEVERITY_MEDIUM,
                "ZPA Application Security","Bypass mode skips ZPA security controls.",bypassed,
                "Remove bypass where possible. Use Client Forwarding Policy instead.",
                references=["Zscaler ZPA — Bypass Settings"])
    def check_server_group_mapping(self):
        segs=self.data.get("zpa_app_segments")
        sg=self.data.get("zpa_server_groups")
        if not segs or not sg: return
        sl=segs if isinstance(segs,list) else segs.get("segments",[])
        orphaned=[s.get("name","") for s in sl if isinstance(s,dict)
                 and not s.get("serverGroups",s.get("server_groups",[]))]
        if orphaned:
            self.finding("ZPA-APP-005",f"App segments without server groups ({len(orphaned)})",
                self.SEVERITY_MEDIUM,"ZPA Application Security",
                "Segments without server group mappings may be unreachable.",orphaned,
                "Map all segments to appropriate server groups.",
                references=["Zscaler ZPA — Server Groups"])
