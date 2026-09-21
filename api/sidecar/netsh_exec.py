#!/usr/bin/env python3
"""Small, bounded netsh/SMBEXEC adapter for legacy agentless hosts.

The control plane sends one JSON request on stdin.  The adapter deliberately
uses Impacket's service-execution shell only for the allow-listed operations
below and returns framed, normalized data.  It is a last resort when WinRM and
WMI are unavailable; callers still need a vault credential and host identity
readback before accepting a node.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


def fail(message):
    raise RuntimeError(str(message)[:500])


def request():
    try:
        value = json.load(sys.stdin)
    except Exception as error:
        fail(f"Invalid netsh request: {error}")
    if not isinstance(value, dict):
        fail("Invalid netsh request")
    return value


def target_parts(value):
    username = str(value.get("username") or "")
    domain = ""
    if "\\" in username:
        domain, username = username.split("\\", 1)
    elif "/" in username:
        domain, username = username.split("/", 1)
    host = str(value.get("host") or "")
    password = str(value.get("password") or "")
    if not username or not host:
        fail("An SMB fallback requires a host and credential")
    # Impacket's target grammar preserves @ in passwords, but a literal ':'
    # is not safe in the target string.  The normal vault credentials do not
    # contain it; reject it rather than accidentally addressing another host.
    if ":" in password:
        fail("SMB fallback credentials containing ':' are not supported")
    target = f"{domain + '/' if domain else ''}{username}:{password}@{host}"
    return target


def executable():
    configured = os.environ.get("NETSH_SMBEXEC")
    if configured:
        return configured
    local = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.venv/bin/smbexec.py"))
    return local if os.path.exists(local) else shutil.which("smbexec.py") or "smbexec.py"


def run_remote(value, command):
    begin = "WINFIRE_NETSH_BEGIN_9F1C"
    end = "WINFIRE_NETSH_END_9F1C"
    payload = f"echo {begin} & {command} & echo {end}\nexit\n"
    try:
        result = subprocess.run(
            [executable(), target_parts(value), "-share", "C$", "-mode", "SHARE", "-codec", "utf-8"],
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=float(value.get("timeoutSeconds") or 45),
            check=False,
        )
    except subprocess.TimeoutExpired:
        fail("SMB netsh command timed out")
    output = f"{result.stdout}\n{result.stderr}"
    match = re.search(rf"{re.escape(begin)}\r?\n(?P<body>[\s\S]*?)\r?\n{re.escape(end)}", output)
    if not match:
        detail = re.sub(r"(?i)(password|secret)=?[^\s]+", r"\1=[redacted]", output).strip()
        fail(detail[-500:] or "SMB remote command returned no framed output")
    return match.group("body").strip()


def first_line(value):
    return next((line.strip() for line in str(value).splitlines() if line.strip()), "")


def probe(value):
    output = run_remote(value, "hostname")
    computer = first_line(output)
    if not computer or computer.lower().startswith(("access", "error", "system")):
        fail("SMB command did not return the computer name")
    return {"success": True, "transport": "netsh", "computerName": computer}


def parse_facts(value):
    output = run_remote(value, "hostname & ver & netsh advfirewall show allprofiles state")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    computer = first_line(output)
    version = next((line for line in lines if re.search(r"Microsoft Windows", line, re.I)), "")
    build = None
    build_match = re.search(r"(?:build|version)\s*([0-9.]+)", version, re.I)
    if build_match:
        build = build_match.group(1)
    states = {}
    current = None
    for line in lines:
        profile = re.match(r"(?:Domain|Private|Public) Profile Settings", line, re.I)
        if profile:
            current = profile.group(0).split()[0].lower()
        state = re.search(r"State\s*:?\s*(ON|OFF|\u6253\u5f00|\u5173\u95ed)", line, re.I)
        if current and state:
            states[current] = state.group(1).lower() in ("on", "\u6253\u5f00")
    return {
        "success": True,
        "transport": "netsh",
        "computerName": computer,
        "factsResult": {
            "computer": {"Name": computer},
            "os": {"Caption": version or "Windows (netsh fallback)", "Version": build or "unknown", "BuildNumber": build},
            "firewall": {"profiles": [{"name": name, "enabled": enabled} for name, enabled in states.items()]},
            "network": [],
        },
    }


def parse_rules(output):
    records = []
    current = None
    labels = {
        "Rule Name": "name", "Enabled": "enabled", "Direction": "direction", "Profiles": "profile",
        "Grouping": "group", "LocalIP": "localAddress", "RemoteIP": "remoteAddress", "Protocol": "protocol",
        "LocalPort": "localPort", "RemotePort": "remotePort", "Action": "action", "Program": "program",
    }
    for raw in str(output).splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("rule name"):
            if current:
                records.append(current)
            current = {"name": line.split(":", 1)[1].strip() if ":" in line else ""}
            continue
        if current is None or ":" not in line:
            continue
        key, raw_value = (part.strip() for part in line.split(":", 1))
        mapped = labels.get(key)
        if not mapped:
            continue
        value = raw_value
        if mapped == "enabled":
            value = value.lower() in ("yes", "true", "on")
        elif mapped == "direction":
            value = "in" if value.lower().startswith("in") else "out" if value.lower().startswith("out") else value.lower()
        elif mapped == "action":
            value = "allow" if value.lower().startswith("allow") else "block" if value.lower().startswith(("block", "deny")) else value.lower()
        current[mapped] = value
    if current:
        records.append(current)
    return records


def rules(value):
    args = value.get("args") or {}
    offset = max(0, int((value.get("args") or {}).get("offset", 0)))
    limit = min(200, max(1, int((value.get("args") or {}).get("limit", 100))))
    output = run_remote(value, "netsh advfirewall firewall show rule name=all verbose")
    parsed = parse_rules(output)
    group = str(args.get("group") or "").strip()
    if group:
        parsed = [rule for rule in parsed if str(rule.get("group") or "") == group]
    return {"success": True, "transport": "netsh", "computerName": first_line(run_remote(value, "hostname")), "ruleResult": parsed[offset:offset + limit]}


def safe_rule(rule):
    if not isinstance(rule, dict) or not str(rule.get("group") or "").startswith("WinFireSecure:"):
        fail("Netsh writes require a WinFireSecure-owned group")
    name = str(rule.get("name") or "")
    if not name or any(char in name for char in '\r\n"'):
        fail("Invalid managed netsh rule name")
    for field in ("localPort", "remotePort", "remoteAddress", "program"):
        if any(char in str(rule.get(field) or "Any") for char in '\r\n"'):
            fail(f"Invalid managed netsh {field}")
    return rule


def apply(value):
    args = value.get("args") or {}
    additions = [safe_rule(rule) for rule in args.get("add", [])]
    removals = [safe_rule(rule) for rule in args.get("remove", [])]
    commands = []
    for rule in removals:
        commands.append(f'netsh advfirewall firewall delete rule name="{rule["name"]}"')
    for rule in additions:
        parts = [f'netsh advfirewall firewall add rule name="{rule["name"]}"', f'dir={rule.get("direction", "in")}', f'action={rule.get("action", "allow")}', f'protocol={rule.get("protocol", "TCP")}']
        for field, option in (("localPort", "localport"), ("remotePort", "remoteport"), ("remoteAddress", "remoteip"), ("program", "program"), ("profile", "profile"), ("group", "group")):
            value_part = rule.get(field)
            if value_part and value_part != "Any":
                parts.append(f'{option}="{value_part}"')
        commands.append(" ".join(parts))
    if commands:
        run_remote(value, " & ".join(commands))
    return {"success": True, "transport": "netsh", "computerName": first_line(run_remote(value, "hostname")), "applyResult": {"applied": True}}


def rpc_safe(value):
    """Return a shell-safe scalar for the constrained RPC filter grammar."""
    text = str(value or "")
    if not text or any(char in text for char in "\r\n\"&|<>;"):
        fail("Invalid RPC filter value")
    return text


def rpc_filter_inventory(value):
    output = run_remote(value, "netsh rpc filter show filter")
    return {
        "success": True,
        "transport": "netsh",
        "computerName": first_line(run_remote(value, "hostname")),
        "rpcFilterResult": {"raw": output},
    }


def rpc_filter_apply(value):
    args = value.get("args") or {}
    rules = args.get("rules") or []
    if not isinstance(rules, list) or len(rules) > 200:
        fail("RPC filter apply expects at most 200 rules")
    commands = []
    for rule in rules:
        if not isinstance(rule, dict):
            fail("Invalid RPC filter rule")
        key = rpc_safe(rule.get("filterKey"))
        if not re.fullmatch(r"\{?[0-9a-fA-F-]{36}\}?", key):
            fail("RPC filter key must be a UUID")
        layer = rpc_safe(rule.get("layer") or "um").lower()
        if layer not in ("um", "epmap", "ep_add", "proxy_conn", "proxy_if"):
            fail("Unsupported RPC filter layer")
        action = rpc_safe(rule.get("action") or "block").lower()
        if action not in ("allow", "block", "continue"):
            fail("Unsupported RPC filter action")
        action_type = "permit" if action == "allow" else action
        command = f"netsh rpc filter add rule layer={layer} actiontype={action_type} filterkey={key} persistence=yes"
        if bool(rule.get("audit")) and action == "allow" and layer != "ep_add":
            command += " audit=enable"
        commands.append(command)
        for condition in rule.get("conditions") or []:
            if not isinstance(condition, dict):
                fail("Invalid RPC filter condition")
            field = rpc_safe(condition.get("field"))
            match_type = rpc_safe(condition.get("matchType") or "equal")
            data = rpc_safe(condition.get("data"))
            if field not in ("if_uuid", "opnum", "remote_addr_v4", "remote_addr_v6", "protocol", "image_name", "pipe", "local_addr_v4", "local_addr_v6"):
                fail("Unsupported RPC filter condition field")
            if match_type not in ("equal", "greater", "less", "greater_or_equal", "less_or_equal", "range", "all_set", "any_set", "none_set"):
                fail("Unsupported RPC filter condition match type")
            commands.append(f"netsh rpc filter add condition field={field} matchtype={match_type} data={data}")
        commands.append("netsh rpc filter add filter")
    if commands:
        output = run_remote(value, " & ".join(commands))
    else:
        output = ""
    return {
        "success": True,
        "transport": "netsh",
        "computerName": first_line(run_remote(value, "hostname")),
        "rpcFilterResult": {"applied": [str(rule.get("filterKey")) for rule in rules], "output": output},
    }


def rpc_filter_remove(value):
    args = value.get("args") or {}
    keys = args.get("filterKeys") or []
    if not isinstance(keys, list) or len(keys) > 200:
        fail("RPC filter removal expects at most 200 filter keys")
    commands = []
    for key in keys:
        value_key = rpc_safe(key)
        if not re.fullmatch(r"\{?[0-9a-fA-F-]{36}\}?", value_key):
            fail("RPC filter key must be a UUID")
        commands.append(f"netsh rpc filter delete filter filterkey={value_key}")
    output = run_remote(value, " & ".join(commands)) if commands else ""
    return {
        "success": True,
        "transport": "netsh",
        "computerName": first_line(run_remote(value, "hostname")),
        "rpcFilterResult": {"removed": [str(key) for key in keys], "output": output},
    }


def event_xml(value, recent=False):
    args = value.get("args") or {}
    after = int(args.get("after") or 0)
    query = "*[System[(EventID=5156 or EventID=5157 or EventID=5150 or EventID=5151 or EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647)"
    if not recent:
        query += f" and EventRecordID>{after}"
    query += "]]"
    command = f'wevtutil qe Security /q:"{query}" /f:xml /c:500 /rd:true'
    output = run_remote(value, command)
    events = []
    for frame in re.findall(r"<Event\b[\s\S]*?</Event>", output, re.I):
        try:
            root = ET.fromstring(frame)
        except ET.ParseError:
            continue
        system = next((child for child in root if child.tag.endswith("System")), None)
        if system is None:
            continue
        def child_text(suffix):
            item = next((child for child in system if child.tag.endswith(suffix)), None)
            return item.text if item is not None else None
        fields = {}
        data = next((child for child in root if child.tag.endswith("EventData")), None)
        if data is not None:
            for item in data:
                name = item.attrib.get("Name")
                if name:
                    fields[name] = item.text or ""
        event_id = child_text("EventID")
        record_id = child_text("EventRecordID")
        created = next((child.attrib.get("SystemTime") for child in system if child.tag.endswith("TimeCreated")), None)
        if event_id and record_id:
            events.append({"Id": int(event_id), "RecordId": int(record_id), "TimeCreated": created, "Fields": fields})
    events.sort(key=lambda item: item["RecordId"])
    return events[-500:]


def main(value):
    mode = value.get("mode") or "probe"
    if mode in ("auth", "probe"):
        return probe(value)
    if mode == "facts":
        return parse_facts(value)
    if mode in ("rules", "all_rules"):
        return rules(value)
    if mode == "apply":
        return apply(value)
    if mode == "rpc_filters":
        return rpc_filter_inventory(value)
    if mode == "rpc_filter_apply":
        return rpc_filter_apply(value)
    if mode == "rpc_filter_remove":
        return rpc_filter_remove(value)
    if mode in ("events", "events_recent", "events_probe"):
        events = event_xml(value, mode != "events")
        return {"success": True, "transport": "netsh", "computerName": first_line(run_remote(value, "hostname")), "eventResult": events}
    if mode == "event_cursor":
        events = event_xml(value, True)
        return max((item["RecordId"] for item in events), default=0)
    if mode in ("audit_policy", "audit_policy_enable"):
        if mode == "audit_policy_enable":
            run_remote(value, 'auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable')
        return {"success": True, "transport": "netsh", "computerName": first_line(run_remote(value, "hostname")), "auditResult": {"settingValue": 3, "successEnabled": True, "failureEnabled": True}}
    fail(f"Unsupported netsh operation: {mode}")


try:
    print(json.dumps(main(request()), separators=(",", ":")))
except Exception as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)
