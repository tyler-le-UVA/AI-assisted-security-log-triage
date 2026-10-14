import pytest


def sg_event(cidr="0.0.0.0/0", v6=None, port=22, error=None, name="AuthorizeSecurityGroupIngress"):
    ev = {
        "eventName": name,
        "eventID": "11111111-1111-1111-1111-111111111111",
        "eventTime": "2026-10-10T23:08:44Z",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": {"type": "IAMUser", "userName": "test-user"},
        "requestParameters": {
            "groupId": "sg-0123456789abcdef0",
            "ipPermissions": {"items": [{
                "ipProtocol": "tcp", "fromPort": port, "toPort": port,
                "ipRanges": {"items": [{"cidrIp": cidr}]} if cidr else {},
                "ipv6Ranges": {"items": [{"cidrIpv6": v6}]} if v6 else {},
            }]},
        },
    }
    if error:
        ev["errorCode"] = error
    return ev


def login_event(mfa="No", result="Success", id_type="IAMUser", user="test-user"):
    identity = {"type": id_type}
    if user and id_type != "Root":
        identity["userName"] = user
    return {
        "eventName": "ConsoleLogin",
        "eventID": "22222222-2222-2222-2222-222222222222",
        "eventTime": "2026-10-13T17:45:32Z",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.20",
        "userIdentity": identity,
        "responseElements": {"ConsoleLogin": result},
        "additionalEventData": {"MFAUsed": mfa, "MobileVersion": "No"},
        "readOnly": False,
    }


# sg_open_to_world

def test_sg_open_world_fires(tp):
    f = tp.sg_open_to_world(sg_event())
    assert f["rule"] == "sg_open_to_world"
    assert f["group_id"] == "sg-0123456789abcdef0"
    assert f["exposed"] == [{"protocol": "tcp", "from_port": 22, "to_port": 22}]


def test_sg_open_world_ipv6_fires(tp):
    assert tp.sg_open_to_world(sg_event(cidr=None, v6="::/0")) is not None


def test_sg_restricted_cidr_does_not_fire(tp):
    assert tp.sg_open_to_world(sg_event(cidr="10.0.0.0/8")) is None


def test_sg_failed_call_does_not_fire(tp):
    assert tp.sg_open_to_world(sg_event(error="AccessDenied")) is None


def test_sg_other_event_does_not_fire(tp):
    assert tp.sg_open_to_world(sg_event(name="DescribeSecurityGroups")) is None


# console_login_without_mfa

def test_login_iam_without_mfa_fires(tp):
    f = tp.console_login_without_mfa(login_event())
    assert f["rule"] == "console_login_without_mfa"
    assert f["identity_type"] == "IAMUser"
    assert f["user"] == "test-user"
    assert f["mfa_used"] is False


def test_login_with_mfa_does_not_fire(tp):
    assert tp.console_login_without_mfa(login_event(mfa="Yes")) is None


def test_login_failure_does_not_fire(tp):
    assert tp.console_login_without_mfa(login_event(result="Failure")) is None


def test_login_federated_does_not_fire(tp):
    assert tp.console_login_without_mfa(login_event(id_type="AssumedRole")) is None


def test_login_root_fires_and_is_named_root(tp):
    f = tp.console_login_without_mfa(login_event(id_type="Root"))
    assert f["identity_type"] == "Root"
    assert f["user"] == "root"


# severity floor and combination

def port(p, protocol="tcp", hi=None):
    return {"protocol": protocol, "from_port": p, "to_port": p if hi is None else hi}


@pytest.mark.parametrize("exposed,expected", [
    ([port(22)], "high"),
    ([port(443)], "low"),
    ([port(8080)], "medium"),
    ([port(None, "-1")], "high"),
    ([port(0, hi=65535)], "high"),
    ([port(53, "udp")], "medium"),
    ([port(80), port(22)], "high"),
])
def test_severity_floor_ports(tp, exposed, expected):
    assert tp.severity_floor({"rule": "sg_open_to_world", "exposed": exposed}) == expected


def test_severity_floor_logins(tp):
    assert tp.severity_floor({"rule": "console_login_without_mfa", "identity_type": "Root"}) == "high"
    assert tp.severity_floor({"rule": "console_login_without_mfa", "identity_type": "IAMUser"}) == "medium"


def test_model_cannot_lower_severity(tp):
    assert tp.combine_severity("high", "low") == "high"


def test_model_can_raise_severity(tp):
    assert tp.combine_severity("medium", "critical") == "critical"


def test_invalid_model_severity_falls_back_to_floor(tp):
    assert tp.combine_severity("high", "bogus") == "high"
    assert tp.combine_severity("high", None) == "high"


# output validation and prompt input

def test_clean_triage_trims_and_normalizes(tp):
    out = tp.clean_triage({
        "severity": " HIGH ",
        "explanation": "x" * 5000,
        "likely_cause": "Unclear",
        "recommended_steps": ["a", "b", "c", "d"],
        "unexpected": "dropped",
    })
    assert out["severity"] == "high"
    assert len(out["explanation"]) == 1000
    assert out["likely_cause"] == "unclear"
    assert out["recommended_steps"] == ["a", "b", "c"]
    assert "unexpected" not in out


def test_clean_triage_handles_bad_steps(tp):
    assert tp.clean_triage({"recommended_steps": "not a list"})["recommended_steps"] == []


def test_prompt_summary_excludes_extra_and_empty_fields(tp):
    summary = tp.prompt_summary({
        "rule": "console_login_without_mfa", "user": "test-user",
        "mfa_used": False, "user_agent": "attacker text", "group_id": None,
    })
    assert "user_agent" not in summary
    assert "group_id" not in summary
    assert summary["mfa_used"] is False


# drift guard: the evaluation copy must match the Lambda

def test_eval_prompt_matches_lambda(tp, ev):
    assert ev.SYSTEM_PROMPT == tp.SYSTEM_PROMPT


def test_eval_floor_matches_lambda(tp, ev):
    findings = [
        {"rule": "sg_open_to_world", "exposed": [port(22)]},
        {"rule": "sg_open_to_world", "exposed": [port(443)]},
        {"rule": "sg_open_to_world", "exposed": [port(8080)]},
        {"rule": "sg_open_to_world", "exposed": [port(None, "-1")]},
        {"rule": "console_login_without_mfa", "identity_type": "Root"},
        {"rule": "console_login_without_mfa", "identity_type": "IAMUser"},
    ]
    for f in findings:
        assert ev.severity_floor(f) == tp.severity_floor(f)
