import gzip
import json
import os
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])


def sg_open_to_world(e):
    if e.get("eventName") != "AuthorizeSecurityGroupIngress" or e.get("errorCode"):
        return None
    params = e.get("requestParameters") or {}
    perms = (params.get("ipPermissions") or {}).get("items", [])
    hits = []
    for p in perms:
        v4 = [r.get("cidrIp") for r in (p.get("ipRanges") or {}).get("items", [])]
        v6 = [r.get("cidrIpv6") for r in (p.get("ipv6Ranges") or {}).get("items", [])]
        if "0.0.0.0/0" in v4 or "::/0" in v6:
            hits.append({
                "protocol": p.get("ipProtocol"),
                "from_port": p.get("fromPort"),
                "to_port": p.get("toPort"),
            })
    if not hits:
        return None
    return {
        "rule": "sg_open_to_world",
        "event_time": e.get("eventTime"),
        "user": (e.get("userIdentity") or {}).get("userName"),
        "source_ip": e.get("sourceIPAddress"),
        "region": e.get("awsRegion"),
        "group_id": params.get("groupId"),
        "exposed": hits,
    }


RULES = [sg_open_to_world]


def save_finding(event_id, finding):
    item = {"event_id": event_id, **finding}
    try:
        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(event_id)",
        )
        print("FINDING saved:", finding["rule"], event_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ConditionalCheckFailedException":
            print("Duplicate finding skipped:", event_id)
        else:
            raise


def lambda_handler(event, context):
    for rec in event["Records"]:
        bucket = rec["s3"]["bucket"]["name"]
        key = rec["s3"]["object"]["key"]
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        data = json.loads(gzip.decompress(body))
        for e in data.get("Records", []):
            if e.get("readOnly"):
                continue
            for rule in RULES:
                finding = rule(e)
                if finding:
                    save_finding(e["eventID"], finding)
