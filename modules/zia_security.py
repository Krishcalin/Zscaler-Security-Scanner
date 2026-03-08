"""
ZIA Security Modules (1-4)
============================
URL Filtering, SSL Inspection, Cloud Firewall, Threat Prevention
Based on Zscaler Recommended Baseline Policies and Leading Practices
"""
from collections import defaultdict
from typing import List, Dict, Any
from modules.base import BaseAuditor

# ═══ Module 1: URL Filtering Policy ═══
class UrlFilteringAuditor(BaseAuditor):
    HIGH_RISK_CATEGORIES=["Malware","Phishing","Cryptomining","Adware/Spyware","Botnet",
        "Command & Control","Cross-site Scripting","Unauthorized Communication","Peer-to-Peer",
        "Newly Registered Domains","DNS Tunneling","Web Spam"]
    def run_all_checks(self)->List[Dict]:
        self.check_url_policy_exists(); self.check_high_risk_categories()
        self.check_uncategorized_urls(); self.check_caution_pages()
        self.check_safe_search(); self.check_default_action()
        return self.findings
    def _rules(self):
        d=self.data.get("url_filtering")
        if not d: return []
        return d if isinstance(d,list) else d.get("rules",d.get("urlFilteringRules",[]))
    def check_url_policy_exists(self):
        if not self._rules():
            self.finding("ZIA-URL-001","No URL filtering rules configured",self.SEVERITY_HIGH,
                "ZIA URL Filtering","URL filtering policy is empty.",
                remediation="Configure URL filtering per Zscaler Recommended Baseline.",
                references=["Zscaler Recommended Baseline — URL Filtering"])
    def check_high_risk_categories(self):
        rules=self._rules(); allowed=[]
        for r in rules:
            action=r.get("action","").upper(); cats=r.get("urlCategories",r.get("url_categories",[]))
            if action in ("ALLOW","") and isinstance(cats,list):
                for c in cats:
                    cn=c if isinstance(c,str) else c.get("name","")
                    if any(hr.upper() in cn.upper() for hr in self.HIGH_RISK_CATEGORIES):
                        allowed.append(f"Rule '{r.get('name','')}': allows {cn}")
        if allowed:
            self.finding("ZIA-URL-002",f"High-risk URL categories not blocked ({len(allowed)})",
                self.SEVERITY_CRITICAL,"ZIA URL Filtering",
                "High-risk categories are allowed instead of blocked.",allowed[:20],
                "Block all high-risk URL categories: Malware, Phishing, C2, Cryptomining, Botnet.",
                ["Zscaler Recommended Baseline — URL Categories"])
    def check_uncategorized_urls(self):
        rules=self._rules()
        for r in rules:
            cats=r.get("urlCategories",r.get("url_categories",[]))
            action=r.get("action","").upper()
            for c in cats:
                cn=c if isinstance(c,str) else c.get("name","")
                if "uncategorized" in cn.lower() and action in ("ALLOW",""):
                    self.finding("ZIA-URL-003","Uncategorized URLs allowed",self.SEVERITY_HIGH,
                        "ZIA URL Filtering","Uncategorized URLs should be cautioned, not allowed.",
                        remediation="Set Uncategorized URLs to CAUTION action.",
                        references=["Zscaler Baseline — Caution Uncategorized"]); return
    def check_caution_pages(self):
        d=self.data.get("url_filtering")
        if isinstance(d,dict):
            if not d.get("cautionEnabled",d.get("caution_enabled",True)):
                self.finding("ZIA-URL-004","Caution/warning pages disabled",self.SEVERITY_MEDIUM,
                    "ZIA URL Filtering","User caution interstitials are disabled.",
                    remediation="Enable caution pages for risky categories.",
                    references=["Zscaler — Caution Page Best Practices"])
    def check_safe_search(self):
        d=self.data.get("advanced_settings") or {}
        if not d.get("safeSearchEnabled",d.get("enforced_safe_search",False)):
            self.finding("ZIA-URL-005","Safe search enforcement not enabled",self.SEVERITY_MEDIUM,
                "ZIA URL Filtering","Google/Bing safe search not enforced.",
                remediation="Enable safe search: Administration > Advanced Settings.",
                references=["Zscaler Baseline — Safe Search"])
    def check_default_action(self):
        rules=self._rules()
        if rules:
            last=rules[-1] if rules else {}
            if last.get("action","").upper()=="ALLOW" and "any" in str(last.get("urlCategories","")).lower():
                self.finding("ZIA-URL-006","Default URL rule allows all categories",self.SEVERITY_HIGH,
                    "ZIA URL Filtering","The default/last URL rule allows all categories.",
                    remediation="Set default rule to CAUTION or BLOCK.",
                    references=["Zscaler Baseline — Default Deny"])

# ═══ Module 2: SSL/TLS Inspection Policy ═══
class SslInspectionAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_ssl_inspection_enabled(); self.check_ssl_bypass_rules()
        self.check_ssl_cert_pinning(); self.check_tls_minimum()
        self.check_ssl_for_cc()
        return self.findings
    def _rules(self):
        d=self.data.get("ssl_inspection")
        if not d: return []
        return d if isinstance(d,list) else d.get("rules",d.get("sslRules",[]))
    def check_ssl_inspection_enabled(self):
        if not self._rules():
            self.finding("ZIA-SSL-001","No SSL inspection rules configured",self.SEVERITY_CRITICAL,
                "ZIA SSL Inspection","SSL inspection is not configured. Encrypted threats pass uninspected.",
                remediation="Configure SSL Forward Proxy inspection per Zscaler baseline.",
                references=["Zscaler SSL Inspection Leading Practices"])
    def check_ssl_bypass_rules(self):
        rules=self._rules(); bypasses=[]
        for r in rules:
            action=r.get("action","").upper()
            if action in ("BYPASS","DO_NOT_INSPECT","EXEMPT"):
                name=r.get("name",""); cats=r.get("urlCategories",[])
                bypasses.append(f"Rule '{name}': bypasses SSL for {cats or 'unspecified categories'}")
        if bypasses:
            sev=self.SEVERITY_HIGH if len(bypasses)>5 else self.SEVERITY_MEDIUM
            self.finding("ZIA-SSL-002",f"SSL inspection bypass rules ({len(bypasses)})",sev,
                "ZIA SSL Inspection","SSL bypass rules allow encrypted traffic uninspected.",
                bypasses[:20],
                "Minimize SSL bypass rules. Only exempt certificate-pinned apps.",
                ["Zscaler SSL Leading Practices — Minimize Bypasses"])
    def check_ssl_cert_pinning(self):
        d=self.data.get("ssl_inspection")
        if isinstance(d,dict) and not d.get("certPinningDetection",True):
            self.finding("ZIA-SSL-003","Certificate pinning detection disabled",self.SEVERITY_MEDIUM,
                "ZIA SSL Inspection","Certificate pinning detection is off.",
                remediation="Enable cert pinning detection to auto-bypass pinned apps.",
                references=["Zscaler — Certificate Pinning"])
    def check_tls_minimum(self):
        d=self.data.get("ssl_inspection") or {}
        if isinstance(d,dict):
            min_tls=d.get("minTlsVersion",d.get("minimumTls",""))
            if min_tls and min_tls.lower() in ("tls1.0","tls1.1","tlsv1","tlsv1.1"):
                self.finding("ZIA-SSL-004",f"Minimum TLS version too low ({min_tls})",self.SEVERITY_HIGH,
                    "ZIA SSL Inspection",f"Min TLS: {min_tls}. TLS 1.0/1.1 have vulnerabilities.",
                    remediation="Set minimum TLS 1.2.",references=["NIST SP 800-52 Rev 2"])
    def check_ssl_for_cc(self):
        d=self.data.get("ssl_inspection") or {}
        if isinstance(d,dict):
            cc_ssl=d.get("clientConnectorSslEnabled",d.get("zcc_ssl_inspection",None))
            if cc_ssl is not None and not cc_ssl:
                self.finding("ZIA-SSL-005","SSL inspection disabled for Client Connector",self.SEVERITY_HIGH,
                    "ZIA SSL Inspection","SSL not inspected for Zscaler Client Connector traffic.",
                    remediation="Enable SSL inspection for Client Connector sessions.",
                    references=["Zscaler SSL Inspection — Client Connector"])

# ═══ Module 3: Cloud Firewall ═══
class CloudFirewallAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_firewall_rules(); self.check_default_deny()
        self.check_dns_rules(); self.check_rule_logging()
        self.check_rule_hygiene()
        return self.findings
    def _rules(self):
        d=self.data.get("firewall_rules")
        if not d: return []
        return d if isinstance(d,list) else d.get("rules",d.get("firewallRules",[]))
    def check_firewall_rules(self):
        if not self._rules():
            self.finding("ZIA-FW-001","No cloud firewall rules configured",self.SEVERITY_HIGH,
                "ZIA Cloud Firewall","Firewall policy is empty — all non-web traffic uncontrolled.",
                remediation="Configure firewall rules per Zscaler Recommended Baseline.",
                references=["Zscaler Recommended Firewall Control Policy"])
    def check_default_deny(self):
        rules=self._rules()
        if rules:
            last=rules[-1]
            if last.get("action","").upper() not in ("BLOCK","DROP","DENY","BLOCK_RESET"):
                self.finding("ZIA-FW-002","Firewall default rule is not deny/block",self.SEVERITY_HIGH,
                    "ZIA Cloud Firewall",f"Default rule action: {last.get('action','')}, expected: Block.",
                    remediation="Set default firewall rule to Block (deny all).",
                    references=["Zscaler Baseline — Default Deny"])
    def check_dns_rules(self):
        rules=self._rules()
        dns_rules=[r for r in rules if "DNS" in str(r.get("networkServices","")).upper()
                  or "53" in str(r.get("destPorts",""))]
        if not dns_rules:
            self.finding("ZIA-FW-003","No explicit DNS firewall rules",self.SEVERITY_MEDIUM,
                "ZIA Cloud Firewall","DNS traffic not explicitly controlled in firewall.",
                remediation="Add DNS-specific firewall rules. Block DNS over non-standard ports.",
                references=["Zscaler Baseline — DNS Control"])
    def check_rule_logging(self):
        rules=self._rules(); no_log=[]
        for r in rules:
            if r.get("state","").upper()!="ENABLED": continue
            if not r.get("enableLogging",r.get("log_enabled",True)):
                no_log.append(r.get("name","unknown"))
        if no_log:
            self.finding("ZIA-FW-004",f"Firewall rules without logging ({len(no_log)})",self.SEVERITY_MEDIUM,
                "ZIA Cloud Firewall","Rules without logging miss visibility.",no_log[:15],
                "Enable logging on all firewall rules.",references=["Zscaler — Firewall Logging"])
    def check_rule_hygiene(self):
        rules=self._rules()
        disabled=[r.get("name","") for r in rules if r.get("state","").upper() in ("DISABLED","INACTIVE")]
        if disabled and len(disabled)>5:
            self.finding("ZIA-FW-005",f"Many disabled firewall rules ({len(disabled)})",self.SEVERITY_LOW,
                "ZIA Cloud Firewall","Disabled rules clutter the policy.",disabled[:10],
                "Review and remove unnecessary disabled rules.",references=["Zscaler — Rule Hygiene"])

# ═══ Module 4: Threat Prevention ═══
class ThreatPreventionAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_sandbox_policy(); self.check_malware_protection()
        self.check_browser_control(); self.check_file_type_control()
        return self.findings
    def check_sandbox_policy(self):
        sb=self.data.get("sandbox_policy")
        if not sb:
            self.finding("ZIA-THREAT-001","Cloud Sandbox not configured",self.SEVERITY_HIGH,
                "ZIA Threat Prevention","Cloud Sandbox is not configured for zero-day analysis.",
                remediation="Configure Cloud Sandbox policy for unknown file analysis.",
                references=["Zscaler — Cloud Sandbox Best Practices"])
            return
        cfg=sb if isinstance(sb,dict) else {}
        if not cfg.get("enabled",True):
            self.finding("ZIA-THREAT-002","Cloud Sandbox disabled",self.SEVERITY_HIGH,
                "ZIA Threat Prevention","Sandbox analysis is disabled.",
                remediation="Enable Cloud Sandbox.",references=["Zscaler — Sandbox Policy"])
    def check_malware_protection(self):
        mp=self.data.get("malware_policy")
        if not mp:
            self.finding("ZIA-THREAT-003","No advanced threat protection policy",self.SEVERITY_HIGH,
                "ZIA Threat Prevention","ATP/IPS policy not configured.",
                remediation="Configure Advanced Threat Protection.",
                references=["Zscaler — ATP Best Practices"])
            return
        cfg=mp if isinstance(mp,dict) else {}
        if not cfg.get("blockMaliciousUrls",True):
            self.finding("ZIA-THREAT-004","Malicious URL blocking disabled",self.SEVERITY_CRITICAL,
                "ZIA Threat Prevention","Known malicious URLs are not being blocked.",
                remediation="Enable malicious URL blocking.",references=["Zscaler ATP"])
    def check_browser_control(self):
        bc=self.data.get("browser_control")
        if not bc or not isinstance(bc,dict): return
        if not bc.get("blockVulnerableBrowsers",False):
            self.finding("ZIA-THREAT-005","Vulnerable browser blocking not enabled",self.SEVERITY_MEDIUM,
                "ZIA Threat Prevention","Users can browse with outdated/vulnerable browsers.",
                remediation="Enable browser vulnerability control.",
                references=["Zscaler Baseline — Browser Control"])
    def check_file_type_control(self):
        d=self.data.get("url_filtering") or {}
        if isinstance(d,dict) and not d.get("fileTypeControlEnabled",True):
            self.finding("ZIA-THREAT-006","File type control not enabled",self.SEVERITY_MEDIUM,
                "ZIA Threat Prevention","Executable downloads not controlled by file type.",
                remediation="Block executable downloads from uncategorized sites.",
                references=["Zscaler Baseline — File Type Control"])
