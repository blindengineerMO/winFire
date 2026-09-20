"""Read-only DCOM/WMI credential check. One JSON request on stdin, one result on stdout."""

import json
import socket
import sys

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL


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
    domain, account = credentials(username)
    socket.setdefaulttimeout(8)
    connection = None
    login = None
    services = None
    enumeration = None
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
        print(json.dumps({"success": True, "transport": "wmi", "computerName": name}))
    except Exception as error:
        raise RuntimeError(str(error).replace(password, "[redacted]")) from None
    finally:
        for item in (enumeration, services, login):
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
