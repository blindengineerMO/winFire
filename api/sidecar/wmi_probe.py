"""DCOM/WMI host check and optional WinRM bootstrap. JSON in and out."""

import base64
import io
import json
import re
import socket
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import SMBConnection


def credentials(value):
    if "\\" in value:
        domain, username = value.split("\\", 1)
        return domain, username
    return "", value


def firewall_script(mode, version, args, marker):
    if mode in ("audit_policy", "audit_policy_enable"):
        if not str(version).startswith(("6.", "10.")):
            raise RuntimeError("WMI audit-policy management requires Windows Vista or newer")
        source = (Path(__file__).resolve().parent / "wmi_audit.ps1").read_text()
        return ("try {\n$mode='" + mode + "'\n" + source + "\nWrite-Output 'DONE|" + marker + "'\n} catch {\n"
                "Write-Output ('ERROR|'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.Exception.Message)))\n"
                "Write-Output 'DONE|" + marker + "'\n}\n")
    if mode == "facts":
        source = (Path(__file__).resolve().parent / "wmi_facts.ps1").read_text()
        return ("try {\n" + source + "\nWrite-Output 'DONE|" + marker + "'\n} catch {\n"
                "Write-Output ('ERROR|'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.Exception.Message)))\n"
                "Write-Output 'DONE|" + marker + "'\n}\n")
    if mode in ("events", "events_recent", "events_probe", "event_cursor"):
        if not str(version).startswith(("6.", "10.")):
            raise RuntimeError("WMI Security event collection requires Windows Vista or newer")
        after = int(args.get("after") or 0)
        if after < 0 or after > 9223372036854775807:
            raise ValueError("Invalid event cursor")
        source = (Path(__file__).resolve().parent / "wmi_events.ps1").read_text()
        script = f"$mode='{mode}';$after=[long]{after}\n{source}"
        return ("try {\n" + script + "\nWrite-Output 'DONE|" + marker + "'\n} catch {\n"
                "Write-Output ('ERROR|'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.Exception.Message)))\n"
                "Write-Output 'DONE|" + marker + "'\n}\n")
    if mode not in ("all_rules", "rules", "apply"):
        raise ValueError("Unsupported WMI firewall operation")
    if str(version).startswith(("5.1.", "5.2.")):
        if mode != "all_rules":
            raise RuntimeError("Windows XP firewall policy changes and managed readback are unavailable")
        source = (Path(__file__).resolve().parent / "xp_firewall.ps1").read_text()
        call = "Get-WinFireXpRules"
    elif str(version).startswith(("6.", "10.")):
        source = (Path(__file__).resolve().parent / "legacy_firewall.ps1").read_text()
        call = "Get-WinFireLegacyRules"
    else:
        raise RuntimeError("Unsupported Windows version for WMI firewall inventory")
    offset = min(1000000, max(0, int(args.get("offset") or 0))) if mode == "all_rules" else 0
    limit = min(200, max(1, int(args.get("limit") or 100))) if mode == "all_rules" else 10000
    group = str(args.get("group") or "")
    if mode in ("rules", "apply") and not re.fullmatch(r"WinFireSecure:[A-Za-z0-9_.:-]{1,160}", group):
        raise ValueError("Managed firewall group is required")
    encoded_group = base64.b64encode(group.encode("utf-8")).decode("ascii")
    if mode == "apply":
        from wsman_client import legacy_apply_script
        source = legacy_apply_script(args, group)
        invocation = ""
    elif call == "Get-WinFireXpRules":
        invocation = f"{call} {offset} {limit}"
    else:
        invocation = f"$group=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_group}'));{call} '{mode}' $group {offset} {limit}"
    return ("try {\n" + source + "\n" + invocation + "\nWrite-Output 'DONE|" + marker + "'\n} catch {\n"
            "Write-Output ('ERROR|'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.Exception.Message)))\n"
            "Write-Output 'DONE|" + marker + "'\n}\n")


def decode_remote_output(raw):
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8", errors="replace").replace("\x00", "")


def parse_event_output(lines, mode):
    if mode == "event_cursor":
        if len(lines) != 1 or not re.fullmatch(r"CURSOR\|\d+", lines[0]):
            raise RuntimeError("WMI event cursor returned an invalid response")
        return int(lines[0].split("|", 1)[1])
    events = []
    for line in lines:
        if not line.startswith("EVENT|"):
            raise RuntimeError("WMI Security event query returned an invalid frame")
        xml = base64.b64decode(line.split("|", 1)[1], validate=True)
        root = ET.fromstring(xml)
        namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        system = root.find("e:System", namespace)
        if system is None:
            raise RuntimeError("WMI Security event has no System data")
        def value(name):
            item = system.find("e:" + name, namespace)
            return item.text if item is not None else None
        fields = {}
        for item in root.findall("e:EventData/e:Data", namespace):
            if item.get("Name"):
                fields[item.get("Name")] = item.text or ""
        time_item = system.find("e:TimeCreated", namespace)
        record_id = int(value("EventRecordID"))
        event_id = int(value("EventID"))
        if record_id < 0 or event_id not in {5156, 5157, 5150, 5151, 4624, 4625, 4634, 4647, 5712}:
            raise RuntimeError("WMI Security event returned an unexpected ID")
        events.append({"RecordId": record_id, "Id": event_id,
                       "TimeCreated": time_item.get("SystemTime") if time_item is not None else None,
                       "Fields": fields})
    return events


def run_staged_operation(services, host, account, password, domain, mode, version, args):
    from wsman_client import parse_legacy_facts, parse_legacy_firewall

    marker = uuid.uuid4().hex
    script = firewall_script(mode, version, args, marker)
    script_name = f"WinFire-{marker}.ps1"
    output_name = f"WinFire-{marker}.txt"
    script_share = f"Temp\\{script_name}"
    output_share = f"Temp\\{output_name}"
    script_path = f"C:\\Windows\\Temp\\{script_name}"
    output_path = f"C:\\Windows\\Temp\\{output_name}"
    smb = SMBConnection(host, host, timeout=5)
    process_class = None
    process_result = None
    try:
        smb.login(account, password, domain)
        content = io.BytesIO(b"\xef\xbb\xbf" + script.encode("utf-8"))
        smb.putFile("ADMIN$", script_share, content.read)
        process_class, _ = services.GetObject("Win32_Process")
        command = (f'cmd.exe /c powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass '
                   f'-File "{script_path}" > "{output_path}" 2>&1')
        process_result = process_class.Create(command, "C:\\", None)
        values = process_result.getProperties()
        raw_return = values.get("ReturnValue", {}).get("value")
        if raw_return is None or int(raw_return) != 0:
            raise RuntimeError(f"Win32_Process.Create returned {raw_return}")
        last_output = ""
        for _ in range(30):
            output = io.BytesIO()
            try:
                smb.getFile("ADMIN$", output_share, output.write)
                last_output = decode_remote_output(output.getvalue())
                if f"DONE|{marker}" in last_output:
                    lines = [line.strip() for line in last_output.splitlines() if line.strip()]
                    if not lines or lines[-1] != f"DONE|{marker}":
                        raise RuntimeError("WMI command output ended unexpectedly")
                    for line in lines:
                        if line.startswith("ERROR|"):
                            detail = base64.b64decode(line.split("|", 1)[1]).decode("utf-8", "replace")
                            raise RuntimeError(f"Remote WMI command failed: {detail}")
                    if mode == "apply":
                        if lines[:-1] != ["APPLIED|true"]:
                            raise RuntimeError("WMI firewall apply returned no success confirmation")
                        return {"applied": True}
                    if mode in ("events", "events_recent", "events_probe", "event_cursor"):
                        return parse_event_output(lines[:-1], mode)
                    if mode == "facts":
                        facts = parse_legacy_facts("\n".join(lines[:-1]))
                        if not facts["computer"]["Name"] or not facts["os"]["Version"]:
                            raise RuntimeError("WMI facts returned no computer name or OS version")
                        return facts
                    if mode in ("audit_policy", "audit_policy_enable"):
                        if len(lines[:-1]) != 1 or not re.fullmatch(r"AUDIT\|[0-3]", lines[0]):
                            raise RuntimeError("WMI audit policy returned an invalid readback")
                        setting = int(lines[0].split("|", 1)[1])
                        if mode == "audit_policy_enable" and setting != 3:
                            raise RuntimeError("WMI audit policy update was not confirmed")
                        return {"subcategoryGuid": "0CCE9226-69AE-11D9-BED3-505054503030",
                                "settingValue": setting, "successEnabled": bool(setting & 1),
                                "failureEnabled": bool(setting & 2)}
                    return parse_legacy_firewall("\n".join(lines[:-1]), mode)
            except RuntimeError:
                raise
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError(f"WMI command did not finish: {last_output[:200]}")
    finally:
        for name in (script_share, output_share):
            try:
                smb.deleteFile("ADMIN$", name)
            except Exception:
                pass
        try:
            smb.logoff()
        except Exception:
            pass
        for item in (process_result, process_class):
            if item is not None:
                try:
                    item.RemRelease()
                except Exception:
                    pass


def main():
    request = json.load(sys.stdin)
    host = request["host"]
    username = request["username"]
    password = request["password"]
    mode = request.get("mode", "probe")
    domain, account = credentials(username)
    socket.setdefaulttimeout(8)
    connection = None
    login = None
    services = None
    enumeration = None
    process_class = None
    process_result = None
    try:
        connection = DCOMConnection(host, account, password, domain, oxidResolver=False)
        interface = connection.CoCreateInstanceEx(
            wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
        )
        login = wmi.IWbemLevel1Login(interface)
        services = login.NTLMLogin("//./root/cimv2", NULL, NULL)
        enumeration = services.ExecQuery("SELECT Name FROM Win32_ComputerSystem")
        result = enumeration.Next(0xFFFFFFFF, 1)[0].getProperties()
        name = str(result.get("Name", {}).get("value") or "")
        if not name:
            raise RuntimeError("WMI did not return a computer name")
        expected = str(request.get("expectedName") or "").split(".", 1)[0]
        if expected and name.casefold() != expected.casefold():
            raise RuntimeError("WMI computer name does not match the directory inventory record")
        response = {"success": True, "transport": "wmi", "computerName": name}
        if mode == "diagnose_winrm":
            service_enum = services.ExecQuery("SELECT Name,State,StartMode,ProcessId FROM Win32_Service WHERE Name='WinRM'")
            try:
                service = service_enum.Next(0xFFFFFFFF, 1)[0].getProperties()
                response["winrmService"] = {
                    key: service.get(key, {}).get("value")
                    for key in ("Name", "State", "StartMode", "ProcessId")
                }
            finally:
                service_enum.RemRelease()
        if mode in ("facts", "audit_policy", "audit_policy_enable", "all_rules", "rules", "apply", "events", "events_recent", "events_probe", "event_cursor"):
            os_enum = services.ExecQuery("SELECT Version FROM Win32_OperatingSystem")
            try:
                os_row = os_enum.Next(0xFFFFFFFF, 1)[0].getProperties()
                os_version = str(os_row.get("Version", {}).get("value") or "")
            finally:
                os_enum.RemRelease()
            response["osVersion"] = os_version
            operation_result = run_staged_operation(
                services, host, account, password, domain, mode, os_version, request.get("args") or {}
            )
            response["applyResult" if mode == "apply" else "eventResult" if mode.startswith("event") else "factsResult" if mode == "facts" else "auditResult" if mode.startswith("audit_policy") else "ruleResult"] = operation_result
        elif mode in ("enable_winrm", "diagnose_winrm"):
            process_class, _ = services.GetObject("Win32_Process")
            output_name = f"WinFire-{uuid.uuid4().hex}.txt"
            output_path = f"C:\\Windows\\Temp\\{output_name}"
            script = ("$ErrorActionPreference='Stop'; Enable-PSRemoting -Force; 'WINFIRE_READY'"
                      if mode == "enable_winrm" else
                      "$ErrorActionPreference='Stop'; "
                      "Get-NetFirewallRule -Name 'WINRM*' -ErrorAction SilentlyContinue | "
                      "Select-Object Name,Enabled,Profile,Direction,Action | ConvertTo-Json -Compress; "
                      "Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue | "
                      "ForEach-Object { $f=$_ | Get-NetFirewallAddressFilter; "
                      "[pscustomobject]@{Name=$_.Name;RemoteAddress=$f.RemoteAddress} } | ConvertTo-Json -Compress; "
                      "Get-NetConnectionProfile | Select-Object Name,NetworkCategory | ConvertTo-Json -Compress; "
                      "winrm enumerate winrm/config/listener")
            encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
            command = (
                f'cmd.exe /c powershell.exe -NoProfile -NonInteractive '
                f'-EncodedCommand {encoded} > "{output_path}" 2>&1'
            )
            process_result = process_class.Create(command, "C:\\", None)
            values = process_result.getProperties()
            raw_return = values.get("ReturnValue", {}).get("value")
            if raw_return is None:
                raise RuntimeError("Win32_Process.Create did not return a status")
            return_value = int(raw_return)
            if return_value != 0:
                raise RuntimeError(f"Win32_Process.Create returned {return_value}")
            response["processId"] = values.get("ProcessId", {}).get("value")
            if mode == "enable_winrm":
                response["activationStarted"] = True
            # Win32_Process.Create only confirms launch. Read the exit output
            # through the administrative share before claiming success.
            smb = None
            try:
                smb = SMBConnection(host, host, timeout=4)
                smb.login(account, password, domain)
                for _ in range(8):
                    output = io.BytesIO()
                    try:
                        smb.getFile("ADMIN$", f"Temp\\{output_name}", output.write)
                        raw = output.getvalue()
                        content = (raw.decode("utf-16", errors="replace") if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else raw.decode("utf-8", errors="replace").replace("\x00", ""))
                        if content:
                            response["commandOutput"] = content[:5000]
                            if mode == "enable_winrm":
                                response["activationSucceeded"] = "WINFIRE_READY" in content
                            break
                    except Exception:
                        pass
                    time.sleep(1)
                if "commandOutput" in response:
                    smb.deleteFile("ADMIN$", f"Temp\\{output_name}")
            except Exception as error:
                response["activationReadbackError"] = str(error).replace(password, "[redacted]")[:200]
            finally:
                if smb is not None:
                    try:
                        smb.logoff()
                    except Exception:
                        pass
        elif mode != "probe":
            raise RuntimeError("Unsupported WMI operation")
        print(json.dumps(response))
    except Exception as error:
        raise RuntimeError(str(error).replace(password, "[redacted]")) from None
    finally:
        for item in (process_result, process_class, enumeration, services, login):
            if item is not None:
                try:
                    item.RemRelease()
                except Exception:
                    pass
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
