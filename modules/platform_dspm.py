"""
Modules 9-12: Admin, Auth/IdP, DSPM, Audit/Compliance
"""
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any
from modules.base import BaseAuditor

# ═══ Module 9: Admin & Platform Security ═══
class AdminSecurityAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_admin_accounts(); self.check_admin_roles()
        self.check_admin_mfa(); self.check_admin_ip_restriction()
        self.check_api_keys()
        return self.findings
    def check_admin_accounts(self):
        admins=self.data.get("admin_users")
        if not admins: return
        al=admins if isinstance(admins,list) else admins.get("admins",admins.get("administrators",[]))
        inactive=[]
        for a in al:
            if not isinstance(a,dict): continue
            last=a.get("lastLogin",a.get("last_login",""))
            if last:
                for fmt in ("%Y-%m-%d","%Y-%m-%dT%H:%M:%S"):
                    try:
                        d=datetime.strptime(last[:19],fmt)
                        if (datetime.now()-d).days>90:
                            inactive.append(f"{a.get('userName',a.get('name',''))}: last login {last}")
                        break
                    except ValueError: continue
        if inactive:
            self.finding("ADM-001",f"Dormant admin accounts ({len(inactive)})",self.SEVERITY_HIGH,
                "Admin & Platform Security","Admin accounts inactive >90 days.",inactive[:15],
                "Deactivate dormant admin accounts. Review admin access quarterly.",
                references=["Zscaler — Admin Account Best Practices"])
    def check_admin_roles(self):
        admins=self.data.get("admin_users")
        if not admins: return
        al=admins if isinstance(admins,list) else admins.get("admins",[])
        super_admins=[a.get("userName",a.get("name","")) for a in al
                     if isinstance(a,dict) and a.get("role","").upper() in ("SUPER_ADMIN","SUPER ADMIN","FULL_ADMIN")]
        if len(super_admins)>3:
            self.finding("ADM-002",f"Excessive super admin accounts ({len(super_admins)})",self.SEVERITY_HIGH,
                "Admin & Platform Security",f"{len(super_admins)} super admin accounts.",super_admins,
                "Limit super admins. Use role-based admin profiles.",
                references=["Zscaler — Role-Based Administration"])
    def check_admin_mfa(self):
        auth=self.data.get("auth_config") or {}
        if isinstance(auth,dict) and not auth.get("adminMfa",auth.get("admin_mfa_required",False)):
            self.finding("ADM-003","Admin MFA not enforced",self.SEVERITY_CRITICAL,
                "Admin & Platform Security","Admin portal access without MFA.",
                remediation="Enforce MFA for all admin accounts via IDP.",
                references=["Zscaler — Admin Authentication Security"])
    def check_admin_ip_restriction(self):
        auth=self.data.get("auth_config") or {}
        if isinstance(auth,dict) and not auth.get("adminIpRestriction",auth.get("ip_whitelist",[])):
            self.finding("ADM-004","No IP restrictions for admin access",self.SEVERITY_MEDIUM,
                "Admin & Platform Security","Admin portal accessible from any IP.",
                remediation="Restrict admin access to corporate IP ranges.",
                references=["Zscaler — Admin IP Restrictions"])
    def check_api_keys(self):
        auth=self.data.get("auth_config") or {}
        if isinstance(auth,dict):
            keys=auth.get("apiKeys",auth.get("api_keys",[]))
            if isinstance(keys,list):
                old=[k.get("name","") for k in keys if isinstance(k,dict)
                    and k.get("age_days",0)>365]
                if old:
                    self.finding("ADM-005",f"API keys older than 1 year ({len(old)})",self.SEVERITY_MEDIUM,
                        "Admin & Platform Security","Old API keys should be rotated.",old,
                        "Rotate API keys annually.",references=["Zscaler API — Key Rotation"])

# ═══ Module 10: Authentication & IdP ═══
class AuthIdpAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_idp_config(); self.check_scim_provisioning()
        self.check_saml_settings(); self.check_surrogate_ip()
        return self.findings
    def check_idp_config(self):
        idp=self.data.get("idp_config")
        if not idp:
            self.finding("AUTH-001","No Identity Provider configured",self.SEVERITY_CRITICAL,
                "Authentication & IdP","No SAML/OIDC IdP integration found.",
                remediation="Configure SAML 2.0 IdP integration (Okta, Azure AD, Ping).",
                references=["Zscaler — User Provisioning & Authentication"])
            return
        cfg=idp if isinstance(idp,dict) else {}
        if not cfg.get("enabled",True):
            self.finding("AUTH-001","IdP integration disabled",self.SEVERITY_CRITICAL,
                "Authentication & IdP","IdP is configured but disabled.",
                remediation="Enable IdP integration.",references=["Zscaler — SAML Configuration"])
    def check_scim_provisioning(self):
        idp=self.data.get("idp_config") or {}
        if isinstance(idp,dict) and not idp.get("scimEnabled",idp.get("scim_provisioning",False)):
            self.finding("AUTH-002","SCIM provisioning not enabled",self.SEVERITY_HIGH,
                "Authentication & IdP","User/group attributes not synced in real-time via SCIM.",
                remediation="Enable SCIM for real-time user/group sync from IdP.",
                references=["Zscaler — SCIM Provisioning Best Practices"])
    def check_saml_settings(self):
        idp=self.data.get("idp_config") or {}
        if not isinstance(idp,dict): return
        issues=[]
        if not idp.get("signedSamlRequest",True): issues.append("SAML request signing: disabled")
        if not idp.get("encryptedSamlAssertion",False): issues.append("SAML assertion encryption: disabled")
        if idp.get("allowIdpInitiated",True): issues.append("IDP-initiated SSO: enabled (replay risk)")
        if issues:
            self.finding("AUTH-003","SAML configuration weaknesses",self.SEVERITY_HIGH,
                "Authentication & IdP",f"{len(issues)} SAML issue(s).",issues,
                "Sign SAML requests. Encrypt assertions. Disable IDP-initiated SSO.",
                references=["Zscaler — SAML Security Best Practices"])
    def check_surrogate_ip(self):
        adv=self.data.get("advanced_settings") or {}
        if isinstance(adv,dict) and adv.get("surrogateIp",{}).get("enabled",False):
            timeout=adv.get("surrogateIp",{}).get("idleTimeout",0)
            if timeout and int(str(timeout))>60:
                self.finding("AUTH-004",f"Surrogate IP idle timeout too long ({timeout} min)",
                    self.SEVERITY_MEDIUM,"Authentication & IdP",
                    "Long surrogate IP timeout allows impersonation risk.",
                    remediation="Set surrogate IP idle timeout ≤60 minutes.",
                    references=["Zscaler — Surrogate IP Settings"])

# ═══ Module 11: DSPM (Data Security Posture Management) ═══
class DspmAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_dspm_enabled(); self.check_data_classification()
        self.check_data_exposure(); self.check_dspm_policies()
        self.check_data_at_rest()
        return self.findings
    def check_dspm_enabled(self):
        dspm=self.data.get("dspm_config")
        if not dspm:
            self.finding("DSPM-001","DSPM not configured",self.SEVERITY_HIGH,
                "DSPM","Data Security Posture Management is not configured.",
                remediation="Enable DSPM for data discovery and classification.",
                references=["Zscaler DSPM Overview"])
            return
        cfg=dspm if isinstance(dspm,dict) else {}
        if not cfg.get("enabled",True):
            self.finding("DSPM-001","DSPM disabled",self.SEVERITY_HIGH,
                "DSPM","DSPM service is disabled.",
                remediation="Enable DSPM.",references=["Zscaler DSPM"])
    def check_data_classification(self):
        cls_cfg=self.data.get("dspm_classification")
        if not cls_cfg:
            self.finding("DSPM-002","No data classification policies",self.SEVERITY_HIGH,
                "DSPM","Data is not being classified — cannot identify sensitive data.",
                remediation="Configure data classification with standard patterns.",
                references=["Zscaler DSPM — Data Classification"])
            return
        cfg=cls_cfg if isinstance(cls_cfg,dict) else {}
        cats=cfg.get("categories",cfg.get("classificationTypes",[]))
        if len(cats)<3:
            self.finding("DSPM-003","Insufficient data classification categories",self.SEVERITY_MEDIUM,
                "DSPM",f"Only {len(cats)} classification categories defined.",
                remediation="Add categories: PII, Financial, Healthcare, IP, Credentials.",
                references=["Zscaler DSPM — Classification Best Practices"])
    def check_data_exposure(self):
        dspm=self.data.get("dspm_config") or {}
        if isinstance(dspm,dict):
            exposure=dspm.get("exposureMonitoring",{})
            if not exposure.get("enabled",False):
                self.finding("DSPM-004","Data exposure monitoring not enabled",self.SEVERITY_HIGH,
                    "DSPM","Public/external data exposure not being monitored.",
                    remediation="Enable data exposure monitoring for SaaS and cloud.",
                    references=["Zscaler DSPM — Exposure Detection"])
    def check_dspm_policies(self):
        policies=self.data.get("dspm_policies")
        if not policies: return
        pl=policies if isinstance(policies,list) else policies.get("policies",[])
        if not pl:
            self.finding("DSPM-005","No DSPM enforcement policies",self.SEVERITY_MEDIUM,
                "DSPM","DSPM has no enforcement policies — findings are informational only.",
                remediation="Create DSPM policies to enforce data handling rules.",
                references=["Zscaler DSPM — Policy Enforcement"])
    def check_data_at_rest(self):
        dspm=self.data.get("dspm_config") or {}
        if isinstance(dspm,dict) and not dspm.get("scanDataAtRest",False):
            self.finding("DSPM-006","Data-at-rest scanning not enabled",self.SEVERITY_MEDIUM,
                "DSPM","Sensitive data in SaaS/cloud storage not being scanned.",
                remediation="Enable data-at-rest scanning for SaaS (M365, GWS, Box, etc.).",
                references=["Zscaler DSPM — Data at Rest"])

# ═══ Module 12: Audit, Logging & Compliance ═══
class AuditComplianceAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_audit_logging(); self.check_nss_integration()
        self.check_log_retention(); self.check_location_config()
        self.check_forwarding_policy()
        return self.findings
    def check_audit_logging(self):
        ac=self.data.get("audit_config")
        if not ac:
            self.finding("AUDIT-001","No audit log configuration found",self.SEVERITY_HIGH,
                "Audit & Compliance","Cannot verify audit logging setup.",
                remediation="Enable audit logging for admin portal changes.",
                references=["Zscaler — Audit Logging"])
            return
        cfg=ac if isinstance(ac,dict) else {}
        if not cfg.get("enabled",True):
            self.finding("AUDIT-002","Audit logging disabled",self.SEVERITY_CRITICAL,
                "Audit & Compliance","Admin changes are not being logged.",
                remediation="Enable audit logging.",references=["Zscaler — Audit Trail"])
    def check_nss_integration(self):
        ac=self.data.get("audit_config") or {}
        if isinstance(ac,dict) and not ac.get("nssEnabled",ac.get("nanologStreaming",False)):
            self.finding("AUDIT-003","Nanolog Streaming Service (NSS) not configured",self.SEVERITY_HIGH,
                "Audit & Compliance","Logs not streamed to external SIEM.",
                remediation="Configure NSS to stream logs to Splunk/Sentinel/QRadar.",
                references=["Zscaler — NSS Integration","Security Analytics Best Practices"])
    def check_log_retention(self):
        ac=self.data.get("audit_config") or {}
        if isinstance(ac,dict):
            days=ac.get("retentionDays",180)
            if days<365:
                self.finding("AUDIT-004",f"Log retention below 365 days ({days}d)",self.SEVERITY_MEDIUM,
                    "Audit & Compliance",f"Retention: {days} days. Many frameworks require 1+ year.",
                    remediation="Increase retention or export to long-term SIEM storage.",
                    references=["Zscaler — Nanolog Retention"])
    def check_location_config(self):
        locs=self.data.get("locations")
        if not locs: return
        ll=locs if isinstance(locs,list) else locs.get("locations",[])
        no_auth=[l.get("name","") for l in ll if isinstance(l,dict)
                and not l.get("authRequired",l.get("authentication",True))]
        if no_auth:
            self.finding("AUDIT-005",f"Locations without authentication ({len(no_auth)})",self.SEVERITY_HIGH,
                "Audit & Compliance","Locations allowing unauthenticated traffic bypass user policies.",
                no_auth[:10],"Enable authentication on all locations.",
                references=["Zscaler — Location Authentication"])
    def check_forwarding_policy(self):
        fp=self.data.get("forwarding_policy")
        if not fp: return
        rules=fp if isinstance(fp,list) else fp.get("rules",[])
        direct=[r.get("name","") for r in rules if isinstance(r,dict)
               and r.get("action","").upper() in ("DIRECT","BYPASS")]
        if direct:
            self.finding("AUDIT-006",f"Forwarding rules bypassing Zscaler ({len(direct)})",self.SEVERITY_HIGH,
                "Audit & Compliance","Forwarding rules send traffic directly, bypassing ZIA inspection.",
                direct[:10],"Minimize bypass/direct rules. Forward all traffic through ZIA.",
                references=["Zscaler — Forwarding Policy Best Practices"])
