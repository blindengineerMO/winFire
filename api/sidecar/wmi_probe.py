"""DCOM/WMI host check and optional WinRM bootstrap. JSON in and out."""

import base64
import io
import json
import socket
import sys
import time
import uuid

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import SMBConnection


def credentials(value):
    if "\\" in value:
        domain, username = value.split("\\", 1)
        return domain, username
    return "", value


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
        if mode in ("enable_winrm", "diagnose_winrm"):
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
        elif mode not in ("probe", "diagnose_winrm"):
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
