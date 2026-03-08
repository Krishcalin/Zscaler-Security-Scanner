"""
Modules 5-10: Exclusions, Sensor Health, Admin, IOAs, Firewall, MITRE
"""
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any
from modules.base import BaseAuditor

# ═══ Module 5: Exclusion Audit (Critical!) ═══
class ExclusionAuditor(BaseAuditor):
    DANGEROUS_PATHS=["C:\\Windows\\Temp","C:\\Temp","C:\\Users\\Public","C:\\ProgramData",
        "C:\\Windows\\System32","C:\\Windows\\SysWOW64","\\AppData\\Local\\Temp",
        "\\AppData\\Roaming","C:\\","D:\\","*\\Downloads","*\\Desktop",
        "/tmp","/var/tmp","/dev/shm","/home","/opt"]
    DANGEROUS_EXTENSIONS=["*.exe","*.dll","*.ps1","*.bat","*.cmd","*.vbs","*.js",
        "*.hta","*.scr","*.msi","*.wsf","*.py","*.sh","*.elf"]
    DANGEROUS_PROCESSES=["powershell.exe","cmd.exe","wscript.exe","cscript.exe",
        "mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe","bitsadmin.exe",
        "bash","python","perl","ruby","sh"]

    def run_all_checks(self)->List[Dict]:
        self.check_ml_exclusions(); self.check_ioa_exclusions()
        self.check_sv_exclusions(); self.check_exclusion_scope()
        self.check_exclusion_count(); self.check_dangerous_process_exclusions()
        return self.findings

    def _check_dangerous_paths(self, exclusions, exc_type):
        dangerous=[]
        for e in exclusions:
            if not isinstance(e,dict): continue
            path=e.get("value",e.get("pattern",e.get("path","")))
            groups=e.get("groups",e.get("host_groups",[]))
            all_hosts=not groups or str(groups).lower() in ("all","*","[]")
            for dp in self.DANGEROUS_PATHS:
                if dp.lower() in str(path).lower():
                    scope="ALL hosts" if all_hosts else f"{len(groups)} group(s)"
                    dangerous.append(f"{path} — scope: {scope}")
            for de in self.DANGEROUS_EXTENSIONS:
                if de.lower() in str(path).lower():
                    dangerous.append(f"{path} (executable extension exclusion)")
        return dangerous

    def check_ml_exclusions(self):
        ml=self.data.get("ml_exclusions")
        if not ml: return
        el=ml if isinstance(ml,list) else ml.get("resources",ml.get("exclusions",[]))
        dangerous=self._check_dangerous_paths(el,"ML")
        if dangerous:
            self.finding("EXC-001",f"Dangerous ML exclusion paths ({len(dangerous)})",self.SEVERITY_CRITICAL,
                "Exclusion Audit","ML exclusions on attacker-abused paths — malware won't be detected.",
                dangerous[:20],
                "Remove broad path exclusions. Use process+path combination instead. "
                "Never exclude temp folders, user profiles, or entire drives.",
                ["CrowdStrike — Exclusion Best Practices"])
        if el:
            broad=[e.get("value","") for e in el if isinstance(e,dict)
                  and not e.get("groups") and str(e.get("applied_globally",True)).lower()=="true"]
            if broad:
                self.finding("EXC-002",f"ML exclusions applied to ALL hosts ({len(broad)})",self.SEVERITY_HIGH,
                    "Exclusion Audit","Global exclusions affect every endpoint.",
                    broad[:15],"Scope exclusions to specific host groups, not global.",
                    ["CrowdStrike — Scoped Exclusions"])

    def check_ioa_exclusions(self):
        ioa=self.data.get("ioa_exclusions")
        if not ioa: return
        el=ioa if isinstance(ioa,list) else ioa.get("resources",[])
        if len(el)>20:
            self.finding("EXC-003",f"Excessive IOA exclusions ({len(el)})",self.SEVERITY_HIGH,
                "Exclusion Audit","Many IOA exclusions reduce behavioral detection coverage.",
                [f"Total IOA exclusions: {len(el)}"],
                "Review and remove unnecessary IOA exclusions. Each one is a detection blind spot.",
                ["CrowdStrike — IOA Exclusion Management"])

    def check_sv_exclusions(self):
        sv=self.data.get("sv_exclusions")
        if not sv: return
        el=sv if isinstance(sv,list) else sv.get("resources",[])
        dangerous=self._check_dangerous_paths(el,"SV")
        if dangerous:
            self.finding("EXC-004",f"Sensor Visibility exclusions on dangerous paths ({len(dangerous)})",
                self.SEVERITY_CRITICAL,"Exclusion Audit",
                "SV exclusions stop the sensor from collecting ANY telemetry — complete blind spot.",
                dangerous[:15],
                "SV exclusions should be extremely rare. Remove unless causing proven performance issues.",
                ["CrowdStrike — Sensor Visibility vs ML Exclusions"])

    def check_exclusion_scope(self):
        all_exc=[]
        for key in ("ml_exclusions","ioa_exclusions","sv_exclusions"):
            d=self.data.get(key)
            if d:
                el=d if isinstance(d,list) else d.get("resources",[])
                all_exc.extend(el)
        wildcard=[e.get("value",e.get("pattern","")) for e in all_exc
                 if isinstance(e,dict) and ("**" in str(e.get("value","")) or
                 str(e.get("value","")).endswith("\\*") or str(e.get("value","")).endswith("/*"))]
        if wildcard:
            self.finding("EXC-005",f"Wildcard exclusions detected ({len(wildcard)})",self.SEVERITY_HIGH,
                "Exclusion Audit","Wildcard exclusions (\\*, /**) are overly broad.",wildcard[:15],
                "Replace wildcards with specific file/process exclusions.",
                ["CrowdStrike — Exclusion Best Practices"])

    def check_exclusion_count(self):
        total=0
        for key in ("ml_exclusions","ioa_exclusions","sv_exclusions"):
            d=self.data.get(key)
            if d:
                el=d if isinstance(d,list) else d.get("resources",[])
                total+=len(el)
        if total>50:
            self.finding("EXC-006",f"High total exclusion count ({total})",self.SEVERITY_MEDIUM,
                "Exclusion Audit",f"{total} total exclusions across ML/IOA/SV — indicates over-exclusion.",
                [f"ML: {len(self.data.get('ml_exclusions',[]))} exclusions" if self.data.get('ml_exclusions') else "ML: 0",
                 f"IOA: {len(self.data.get('ioa_exclusions',[]))} exclusions" if self.data.get('ioa_exclusions') else "IOA: 0",
                 f"SV: {len(self.data.get('sv_exclusions',[]))} exclusions" if self.data.get('sv_exclusions') else "SV: 0"],
                "Audit all exclusions quarterly. Remove stale/unnecessary entries.",
                ["CrowdStrike — Exclusion Hygiene"])

    def check_dangerous_process_exclusions(self):
        all_exc=[]
        for key in ("ml_exclusions","ioa_exclusions"):
            d=self.data.get(key)
            if d:
                el=d if isinstance(d,list) else d.get("resources",[])
                all_exc.extend(el)
        proc_exc=[]
        for e in all_exc:
            if not isinstance(e,dict): continue
            val=str(e.get("value",e.get("pattern",""))).lower()
            for dp in self.DANGEROUS_PROCESSES:
                if dp.lower() in val:
                    proc_exc.append(f"{e.get('value','')}: excludes {dp}")
        if proc_exc:
            self.finding("EXC-007",f"Exclusions for commonly abused processes ({len(proc_exc)})",
                self.SEVERITY_CRITICAL,"Exclusion Audit",
                "Processes excluded that attackers routinely abuse (LOLBins).",proc_exc[:15],
                "NEVER exclude PowerShell, cmd, wscript, mshta, certutil, etc.",
                ["MITRE ATT&CK — LOLBins","CrowdStrike — Dangerous Exclusions"])

# ═══ Module 6: Sensor Health & Coverage ═══
class SensorHealthAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_sensor_status(); self.check_rfm_hosts()
        self.check_stale_sensors(); self.check_os_coverage()
        return self.findings
    def _hosts(self):
        d=self.data.get("hosts")
        if not d: return []
        return d if isinstance(d,list) else d.get("resources",d.get("devices",[]))
    def check_sensor_status(self):
        inactive=[h.get("hostname","") for h in self._hosts()
                 if isinstance(h,dict) and h.get("status","").lower()!="normal"
                 and h.get("status","").lower() not in ("","online")]
        if inactive:
            self.finding("SENSOR-001",f"Sensors not in normal status ({len(inactive)})",self.SEVERITY_HIGH,
                "Sensor Health","Sensors offline/degraded = no protection.",inactive[:20],
                "Investigate offline sensors. Reinstall if necessary.",
                ["CrowdStrike — Sensor Troubleshooting"])
    def check_rfm_hosts(self):
        rfm=[h.get("hostname","") for h in self._hosts()
            if isinstance(h,dict) and h.get("reduced_functionality_mode",h.get("rfm","")).lower()=="true"]
        if rfm:
            self.finding("SENSOR-002",f"Hosts in Reduced Functionality Mode ({len(rfm)})",self.SEVERITY_CRITICAL,
                "Sensor Health","RFM sensors have severely limited detection — nearly unprotected.",rfm[:15],
                "RFM usually indicates kernel incompatibility. Update sensor or OS kernel.",
                ["CrowdStrike — RFM Troubleshooting"])
    def check_stale_sensors(self):
        stale=[]; now=datetime.now()
        for h in self._hosts():
            if not isinstance(h,dict): continue
            last=h.get("last_seen",h.get("lastSeen",""))
            if last:
                for fmt in ("%Y-%m-%dT%H:%M:%SZ","%Y-%m-%d"):
                    try:
                        d=datetime.strptime(last[:19],fmt.replace("Z",""))
                        if (now-d).days>30: stale.append(f"{h.get('hostname','')}: last seen {last[:10]}")
                        break
                    except ValueError: continue
        if stale:
            self.finding("SENSOR-003",f"Stale sensors (>30 days offline) ({len(stale)})",self.SEVERITY_MEDIUM,
                "Sensor Health","Hosts haven't checked in for 30+ days.",stale[:15],
                "Remove decommissioned hosts. Investigate unreachable sensors.",
                ["CrowdStrike — Host Management"])
    def check_os_coverage(self):
        os_dist=defaultdict(int)
        for h in self._hosts():
            if isinstance(h,dict):
                os_dist[h.get("platform_name",h.get("os","unknown"))]+=1
        if os_dist:
            items=[f"{os}: {c} hosts" for os,c in sorted(os_dist.items(),key=lambda x:-x[1])]
            self.finding("SENSOR-004","Sensor OS distribution (informational)",self.SEVERITY_LOW,
                "Sensor Health","Sensor fleet composition for coverage analysis.",items,
                "Ensure all OS types have appropriate prevention policies.",
                ["CrowdStrike — Platform Coverage"])

# ═══ Module 7: Admin & API Security ═══
class AdminSecurityAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_admin_count(); self.check_admin_mfa()
        self.check_api_clients(); self.check_admin_roles()
        return self.findings
    def check_admin_count(self):
        admins=self.data.get("admin_users")
        if not admins: return
        al=admins if isinstance(admins,list) else admins.get("resources",[])
        falcon_admins=[a.get("uid",a.get("email","")) for a in al
                      if isinstance(a,dict) and "admin" in str(a.get("roles",a.get("role",""))).lower()]
        if len(falcon_admins)>5:
            self.finding("ADMIN-001",f"Excessive Falcon admin accounts ({len(falcon_admins)})",self.SEVERITY_MEDIUM,
                "Admin Security","Too many users with Falcon Admin role.",falcon_admins[:10],
                "Limit Falcon Admins. Use Endpoint Manager role for policy management.",
                ["CrowdStrike — RBAC Best Practices"])
    def check_admin_mfa(self):
        admins=self.data.get("admin_users")
        if not admins: return
        al=admins if isinstance(admins,list) else admins.get("resources",[])
        no_mfa=[a.get("uid","") for a in al
               if isinstance(a,dict) and not a.get("mfa_enabled",a.get("twoFactor",True))]
        if no_mfa:
            self.finding("ADMIN-002",f"Falcon console users without MFA ({len(no_mfa)})",self.SEVERITY_HIGH,
                "Admin Security","Console access without MFA = account takeover risk.",no_mfa[:10],
                "Enforce MFA for all Falcon console users.",
                ["CrowdStrike — MFA Configuration"])
    def check_api_clients(self):
        clients=self.data.get("api_clients")
        if not clients: return
        cl=clients if isinstance(clients,list) else clients.get("resources",[])
        broad=[c.get("name",c.get("clientId","")) for c in cl
              if isinstance(c,dict) and any(s in str(c.get("scopes",c.get("scope",[])))
              for s in ["*","admin","write"])]
        if broad:
            self.finding("ADMIN-003",f"API clients with broad scopes ({len(broad)})",self.SEVERITY_HIGH,
                "Admin Security","API clients with write/admin access.",broad[:10],
                "Restrict API scopes to minimum required. Use read-only where possible.",
                ["CrowdStrike — OAuth2 API Scopes"])
    def check_admin_roles(self):
        roles=self.data.get("admin_roles")
        if not roles: return
        rl=roles if isinstance(roles,list) else roles.get("resources",[])
        custom=[r.get("name","") for r in rl if isinstance(r,dict) and not r.get("is_default",True)]
        if not custom:
            self.finding("ADMIN-004","No custom admin roles defined",self.SEVERITY_LOW,
                "Admin Security","Using only default roles — may not follow least privilege.",
                remediation="Create custom roles for SOC analysts, policy managers, read-only.",
                references=["CrowdStrike — Custom RBAC Roles"])

# ═══ Module 8: Custom IOA Rules ═══
class CustomIoaAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_custom_ioas_exist(); self.check_ioa_coverage()
        return self.findings
    def check_custom_ioas_exist(self):
        ioas=self.data.get("custom_ioas")
        if not ioas:
            self.finding("IOA-001","No custom IOA rules configured",self.SEVERITY_MEDIUM,
                "Custom IOAs","No environment-specific behavioral detection rules.",
                remediation="Create custom IOA rules for your environment-specific threats.",
                references=["CrowdStrike — Custom IOA Rule Groups"])
    def check_ioa_coverage(self):
        ioas=self.data.get("custom_ioas")
        if not ioas: return
        il=ioas if isinstance(ioas,list) else ioas.get("resources",[])
        disabled=[r.get("name","") for r in il if isinstance(r,dict) and not r.get("enabled",True)]
        if disabled:
            self.finding("IOA-002",f"Disabled custom IOA rules ({len(disabled)})",self.SEVERITY_LOW,
                "Custom IOAs","Custom rules created but not active.",disabled[:10],
                "Review and enable relevant custom IOA rules.",
                ["CrowdStrike — IOA Rule Management"])

# ═══ Module 9: Firewall Policy ═══
class FirewallPolicyAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_firewall_enabled()
        return self.findings
    def check_firewall_enabled(self):
        fw=self.data.get("firewall_policies")
        if not fw:
            self.finding("FW-001","No Falcon Firewall policies configured",self.SEVERITY_MEDIUM,
                "Firewall Policy","Host-based firewall not managed by CrowdStrike.",
                remediation="Configure Falcon Firewall Management policies if licensed.",
                references=["CrowdStrike — Falcon Firewall Management"])

# ═══ Module 10: MITRE ATT&CK Coverage Assessment ═══
class MitreCoverageAuditor(BaseAuditor):
    CRITICAL_TECHNIQUES={"T1059":"Command and Scripting Interpreter","T1053":"Scheduled Task/Job",
        "T1003":"OS Credential Dumping","T1021":"Remote Services","T1055":"Process Injection",
        "T1078":"Valid Accounts","T1486":"Data Encrypted for Impact (Ransomware)",
        "T1082":"System Information Discovery","T1047":"Windows Management Instrumentation",
        "T1218":"System Binary Proxy Execution (LOLBins)"}
    def run_all_checks(self)->List[Dict]:
        self.check_technique_coverage()
        return self.findings
    def check_technique_coverage(self):
        policies=self.data.get("prevention_policies") or []
        pl=policies if isinstance(policies,list) else policies.get("resources",[])
        if not pl: return
        coverage_gaps=[]
        for p in pl:
            if not isinstance(p,dict): continue
            settings=p.get("prevention_settings",p.get("settings",{}))
            if isinstance(settings,list):
                settings={s.get("id",""):s.get("value","") for s in settings}
            if not settings.get("suspiciousScriptsAndCommands"):
                coverage_gaps.append("T1059 — Command/Script Interpreter: script monitoring disabled")
            if not settings.get("suspiciousProcesses"):
                coverage_gaps.append("T1055 — Process Injection: suspicious process detection off")
            break  # Check first policy as sample
        self.finding("MITRE-001","MITRE ATT&CK technique coverage assessment",self.SEVERITY_LOW,
            "MITRE Coverage","Top 10 MITRE ATT&CK techniques and prevention posture.",
            [f"{tid} — {name}" for tid,name in self.CRITICAL_TECHNIQUES.items()] + (coverage_gaps or ["No gaps detected"]),
            "Map prevention settings to MITRE ATT&CK matrix. Close detection gaps.",
            ["MITRE ATT&CK — Enterprise","CrowdStrike — ATT&CK Coverage"])
