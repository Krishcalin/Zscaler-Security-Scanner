"""
Modules 1-4: Prevention Policy, Sensor Updates, Response, Device Control
CrowdStrike Falcon Deployment Validation
"""
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any
from modules.base import BaseAuditor

# ═══ Module 1: Prevention Policy Validation ═══
class PreventionPolicyAuditor(BaseAuditor):
    # Settings that should be enabled for maximum protection
    CRITICAL_SETTINGS={
        "cloudAntiMalware":("Cloud Anti-Malware","NGAV cloud ML detection"),
        "sensorAntiMalware":("Sensor Anti-Malware","Offline ML protection"),
        "adwarePUP":("Adware & PUP","Potentially unwanted programs"),
        "onSensorMLSlider":("On-Sensor ML Level","Sensor-based ML aggressiveness"),
        "cloudMLSlider":("Cloud ML Level","Cloud-based ML aggressiveness"),
    }
    BEHAVIORAL_SETTINGS={
        "suspiciousProcesses":("Suspicious Processes","Block suspicious process behavior"),
        "suspiciousRegistryOperations":("Suspicious Registry Ops","Block ASEP/registry abuse"),
        "suspiciousScriptsAndCommands":("Suspicious Scripts","Block malicious PowerShell/scripts"),
        "intelligenceSourcedThreats":("Intelligence-Sourced Threats","Block known malware hashes"),
        "suspiciousKernelDrivers":("Suspicious Kernel Drivers","Block suspicious drivers"),
        "interpreterProtection":("Interpreter Protection","Monitor script interpreters"),
    }
    EXPLOIT_SETTINGS={
        "forceASLR":("Force ASLR","Address Space Layout Randomization"),
        "forceDEP":("Force DEP","Data Execution Prevention"),
        "heapSprayPreallocation":("Heap Spray Protection","Heap spray preallocation"),
        "nullPageAllocation":("Null Page Allocation","Null page protection"),
        "SEHOverwriteProtection":("SEH Overwrite","Structured Exception Handler protection"),
    }

    def run_all_checks(self)->List[Dict]:
        self.check_policies_exist(); self.check_ngav_settings()
        self.check_behavioral_prevention(); self.check_exploit_mitigation()
        self.check_ml_levels(); self.check_detect_vs_prevent()
        self.check_unassigned_policies(); self.check_policy_coverage()
        self.check_ransomware_protection(); self.check_script_monitoring()
        return self.findings

    def _policies(self):
        d=self.data.get("prevention_policies")
        if not d: return []
        return d if isinstance(d,list) else d.get("resources",d.get("policies",[]))

    def check_policies_exist(self):
        if not self._policies():
            self.finding("PREV-001","No prevention policies found",self.SEVERITY_CRITICAL,
                "Prevention Policy","Cannot validate prevention — no policy data exported.",
                remediation="Export prevention policies via Falcon API or console.",
                references=["CrowdStrike — Prevention Policy Management"])

    def check_ngav_settings(self):
        for p in self._policies():
            if not isinstance(p,dict): continue
            name=p.get("name",p.get("policy_name","unknown"))
            settings=p.get("prevention_settings",p.get("settings",{}))
            if isinstance(settings,list):
                settings={s.get("id",s.get("name","")):s.get("value","") for s in settings}
            disabled=[]
            for key,(label,desc) in self.CRITICAL_SETTINGS.items():
                val=settings.get(key,"")
                if isinstance(val,dict): val=val.get("prevention","")
                if str(val).lower() in ("disabled","false","off","0","detect",""):
                    disabled.append(f"{label}: {val or 'not set'} — {desc}")
            if disabled:
                self.finding("PREV-002",f"NGAV settings disabled in '{name}' ({len(disabled)})",
                    self.SEVERITY_HIGH,"Prevention Policy",
                    f"Policy '{name}' has critical NGAV settings disabled.",disabled,
                    "Enable Cloud Anti-Malware, Sensor Anti-Malware, and Adware/PUP detection.",
                    ["CrowdStrike — Recommended Prevention Settings"])

    def check_behavioral_prevention(self):
        for p in self._policies():
            if not isinstance(p,dict): continue
            name=p.get("name","unknown")
            settings=p.get("prevention_settings",p.get("settings",{}))
            if isinstance(settings,list):
                settings={s.get("id",""):s.get("value","") for s in settings}
            disabled=[]
            for key,(label,desc) in self.BEHAVIORAL_SETTINGS.items():
                val=settings.get(key,"")
                if isinstance(val,dict): val=val.get("prevention","")
                if str(val).lower() in ("disabled","false","off","0",""):
                    disabled.append(f"{label}: {val or 'not set'}")
            if disabled:
                self.finding("PREV-003",f"Behavioral prevention gaps in '{name}' ({len(disabled)})",
                    self.SEVERITY_HIGH,"Prevention Policy",
                    f"Behavioral IOA settings disabled — exploits and scripts may not be blocked.",disabled,
                    "Enable: Suspicious Processes, Registry Ops, Scripts, Intel Threats, Kernel Drivers.",
                    ["CrowdStrike — Behavior-Based Prevention"])

    def check_exploit_mitigation(self):
        for p in self._policies():
            if not isinstance(p,dict): continue
            name=p.get("name","unknown")
            settings=p.get("prevention_settings",p.get("settings",{}))
            if isinstance(settings,list):
                settings={s.get("id",""):s.get("value","") for s in settings}
            disabled=[]
            for key,(label,desc) in self.EXPLOIT_SETTINGS.items():
                val=settings.get(key,"")
                if str(val).lower() in ("disabled","false","off","0",""):
                    disabled.append(f"{label}: not enabled — {desc}")
            if disabled:
                self.finding("PREV-004",f"Exploit mitigations disabled in '{name}' ({len(disabled)})",
                    self.SEVERITY_MEDIUM,"Prevention Policy",
                    "Memory exploit protections not fully enabled.",disabled,
                    "Enable ASLR, DEP, Heap Spray, Null Page, and SEH protections.",
                    ["CrowdStrike — Exploit Mitigation Settings"])

    def check_ml_levels(self):
        for p in self._policies():
            if not isinstance(p,dict): continue
            name=p.get("name","unknown")
            settings=p.get("prevention_settings",p.get("settings",{}))
            if isinstance(settings,list):
                settings={s.get("id",""):s.get("value","") for s in settings}
            cloud_ml=str(settings.get("cloudMLSlider",settings.get("cloud_ml_level",""))).upper()
            sensor_ml=str(settings.get("onSensorMLSlider",settings.get("sensor_ml_level",""))).upper()
            issues=[]
            if cloud_ml in ("DISABLED","OFF","","CAUTIOUS"):
                issues.append(f"Cloud ML: {cloud_ml or 'not set'} (recommend: MODERATE or AGGRESSIVE)")
            if sensor_ml in ("DISABLED","OFF","","CAUTIOUS"):
                issues.append(f"Sensor ML: {sensor_ml or 'not set'} (recommend: MODERATE or AGGRESSIVE)")
            if issues:
                self.finding("PREV-005",f"ML detection levels low in '{name}'",self.SEVERITY_HIGH,
                    "Prevention Policy","Low ML sensitivity reduces zero-day detection.",issues,
                    "Set ML levels to MODERATE minimum, AGGRESSIVE for high-security hosts.",
                    ["CrowdStrike — ML Detection Levels"])

    def check_detect_vs_prevent(self):
        detect_only=[]
        for p in self._policies():
            if not isinstance(p,dict): continue
            name=p.get("name","unknown")
            settings=p.get("prevention_settings",p.get("settings",{}))
            if isinstance(settings,list):
                settings={s.get("id",""):s.get("value","") for s in settings}
            detect_count=sum(1 for v in settings.values()
                           if isinstance(v,dict) and str(v.get("prevention","")).lower()=="disabled"
                           and str(v.get("detection","")).lower()!="disabled")
            if detect_count>3:
                detect_only.append(f"'{name}': {detect_count} settings in detect-only mode")
        if detect_only:
            self.finding("PREV-006",f"Policies in detect-only mode ({len(detect_only)})",self.SEVERITY_HIGH,
                "Prevention Policy","Settings detect threats but do NOT block them.",detect_only,
                "After tuning baseline, switch from detect-only to prevent mode.",
                ["CrowdStrike — Deployment: Detect → Prevent"])

    def check_unassigned_policies(self):
        unassigned=[p.get("name","") for p in self._policies()
                   if isinstance(p,dict) and not p.get("groups",p.get("host_groups",[]))]
        if unassigned:
            self.finding("PREV-007",f"Prevention policies not assigned to any host group ({len(unassigned)})",
                self.SEVERITY_MEDIUM,"Prevention Policy",
                "Unassigned policies have no effect on any hosts.",unassigned,
                "Assign policies to appropriate host groups.",
                ["CrowdStrike — Policy Assignment"])

    def check_policy_coverage(self):
        hosts=self.data.get("hosts")
        if not hosts: return
        hl=hosts if isinstance(hosts,list) else hosts.get("resources",hosts.get("devices",[]))
        no_policy=[h.get("hostname",h.get("device_id","")) for h in hl
                  if isinstance(h,dict) and not h.get("prevention_policy",h.get("policies",{}).get("prevention",""))]
        if no_policy:
            self.finding("PREV-008",f"Hosts without prevention policy ({len(no_policy)})",self.SEVERITY_CRITICAL,
                "Prevention Policy","Hosts with sensor but NO prevention policy = unprotected.",
                no_policy[:20],
                "Assign prevention policy to all host groups.",
                ["CrowdStrike — Policy Coverage"])

    def check_ransomware_protection(self):
        for p in self._policies():
            if not isinstance(p,dict): continue
            name=p.get("name","unknown")
            settings=p.get("prevention_settings",p.get("settings",{}))
            if isinstance(settings,list):
                settings={s.get("id",""):s.get("value","") for s in settings}
            ransom=settings.get("ransomware",settings.get("cryptowall",""))
            if isinstance(ransom,dict): ransom=ransom.get("prevention","")
            if str(ransom).lower() in ("disabled","false","off","detect",""):
                self.finding("PREV-009",f"Ransomware prevention not enabled in '{name}'",self.SEVERITY_CRITICAL,
                    "Prevention Policy","Ransomware protection is disabled or detect-only.",
                    [f"Policy: {name}, ransomware: {ransom or 'not set'}"],
                    "Enable ransomware prevention in BLOCK mode.",
                    ["CrowdStrike — Ransomware Protection"]); break

    def check_script_monitoring(self):
        for p in self._policies():
            if not isinstance(p,dict): continue
            name=p.get("name","unknown")
            settings=p.get("prevention_settings",p.get("settings",{}))
            if isinstance(settings,list):
                settings={s.get("id",""):s.get("value","") for s in settings}
            sbm=settings.get("scriptBasedExecutionMonitoring",settings.get("script_monitoring",""))
            if str(sbm).lower() in ("disabled","false","off","0",""):
                self.finding("PREV-010",f"Script-Based Execution Monitoring disabled in '{name}'",
                    self.SEVERITY_HIGH,"Prevention Policy",
                    "PowerShell, VBScript, JScript, and macro monitoring is off.",
                    remediation="Enable Script-Based Execution Monitoring.",
                    references=["CrowdStrike — Script Monitoring"]); break

# ═══ Module 2: Sensor Update Policy ═══
class SensorUpdateAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_update_policies(); self.check_auto_update()
        self.check_sensor_versions(); self.check_uninstall_protection()
        return self.findings
    def _policies(self):
        d=self.data.get("sensor_update_policies")
        if not d: return []
        return d if isinstance(d,list) else d.get("resources",d.get("policies",[]))
    def check_update_policies(self):
        if not self._policies():
            self.finding("UPD-001","No sensor update policies found",self.SEVERITY_MEDIUM,
                "Sensor Updates","Cannot validate sensor update configuration.",
                remediation="Export sensor update policies.",
                references=["CrowdStrike — Sensor Update Policies"])
    def check_auto_update(self):
        no_auto=[p.get("name","") for p in self._policies()
                if isinstance(p,dict) and not p.get("settings",{}).get("build","")
                and p.get("settings",{}).get("uninstall_protection","")!="ENABLED"]
        # Check for pinned/manual update policies
        pinned=[p.get("name","") for p in self._policies()
               if isinstance(p,dict) and p.get("settings",{}).get("sensor_version","")]
        if pinned:
            self.finding("UPD-002",f"Sensor update policies with pinned versions ({len(pinned)})",
                self.SEVERITY_MEDIUM,"Sensor Updates",
                "Pinned sensor versions miss new detection capabilities.",pinned,
                "Use N-1 or N-2 auto-update. Avoid pinning to specific versions.",
                ["CrowdStrike — Sensor Update Rings"])
    def check_sensor_versions(self):
        hosts=self.data.get("hosts")
        if not hosts: return
        hl=hosts if isinstance(hosts,list) else hosts.get("resources",[])
        versions=defaultdict(int)
        for h in hl:
            if isinstance(h,dict):
                v=h.get("agent_version",h.get("sensor_version","unknown"))
                versions[v]+=1
        if len(versions)>3:
            items=[f"Version {v}: {c} hosts" for v,c in sorted(versions.items(),key=lambda x:-x[1])]
            self.finding("UPD-003",f"Multiple sensor versions deployed ({len(versions)} versions)",
                self.SEVERITY_MEDIUM,"Sensor Updates",
                "Too many sensor versions indicates inconsistent update policies.",items[:10],
                "Standardize on N-1 version. Use update rings.",
                ["CrowdStrike — Sensor Version Management"])
    def check_uninstall_protection(self):
        no_protect=[p.get("name","") for p in self._policies()
                   if isinstance(p,dict) and
                   str(p.get("settings",{}).get("uninstall_protection","")).upper()!="ENABLED"]
        if no_protect:
            self.finding("UPD-004",f"Sensor uninstall protection disabled ({len(no_protect)})",
                self.SEVERITY_HIGH,"Sensor Updates",
                "Sensors can be removed by local admins without a maintenance token.",no_protect,
                "Enable Uninstall and Maintenance Protection on all policies.",
                ["CrowdStrike — Uninstall Protection"])

# ═══ Module 3: Response Policy ═══
class ResponsePolicyAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_rtr_enabled(); self.check_rtr_scripts()
        return self.findings
    def check_rtr_enabled(self):
        rp=self.data.get("response_policies")
        if not rp: return
        pl=rp if isinstance(rp,list) else rp.get("resources",[])
        no_rtr=[p.get("name","") for p in pl
               if isinstance(p,dict) and not p.get("settings",{}).get("real_time_response",True)]
        if no_rtr:
            self.finding("RSP-001",f"Real-Time Response disabled ({len(no_rtr)} policies)",self.SEVERITY_MEDIUM,
                "Response Policy","RTR allows remote investigation and remediation.",no_rtr,
                "Enable RTR for incident response capability.",
                ["CrowdStrike — Real-Time Response"])
    def check_rtr_scripts(self):
        rp=self.data.get("response_policies")
        if not rp: return
        pl=rp if isinstance(rp,list) else rp.get("resources",[])
        unrestricted=[p.get("name","") for p in pl
                     if isinstance(p,dict) and p.get("settings",{}).get("custom_scripts",False)
                     and p.get("settings",{}).get("run_scripts_unrestricted",False)]
        if unrestricted:
            self.finding("RSP-002","Unrestricted custom RTR scripts enabled",self.SEVERITY_MEDIUM,
                "Response Policy","Any admin can run custom scripts on endpoints.",unrestricted,
                "Restrict RTR to predefined commands. Require approval for custom scripts.",
                ["CrowdStrike — RTR Security"])

# ═══ Module 4: Device Control ═══
class DeviceControlAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_usb_policy(); self.check_usb_enforcement()
        return self.findings
    def check_usb_policy(self):
        dc=self.data.get("device_control_policies")
        if not dc:
            self.finding("DEV-001","No device control (USB) policies configured",self.SEVERITY_MEDIUM,
                "Device Control","USB devices not controlled — data exfiltration risk.",
                remediation="Configure device control policies to block unauthorized USB.",
                references=["CrowdStrike — Device Control"])
            return
    def check_usb_enforcement(self):
        dc=self.data.get("device_control_policies")
        if not dc: return
        pl=dc if isinstance(dc,list) else dc.get("resources",[])
        allow_all=[p.get("name","") for p in pl
                  if isinstance(p,dict) and p.get("settings",{}).get("default_action","").upper()=="ALLOW"]
        if allow_all:
            self.finding("DEV-002",f"USB policies with default ALLOW ({len(allow_all)})",self.SEVERITY_MEDIUM,
                "Device Control","All USB devices allowed by default.",allow_all,
                "Set default action to BLOCK. Allowlist specific approved devices.",
                ["CrowdStrike — USB Device Management"])
