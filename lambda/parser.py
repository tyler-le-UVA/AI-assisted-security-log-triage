import gzip
import json
import boto3

s3 = boto3.client("s3")

def lambda_handler(event, context):
    for rec in event["Records"]:
        bucket = rec["s3"]["bucket"]["name"]
        key = rec["s3"]["object"]["key"]
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        data = json.loads(gzip.decompress(body))
        for e in data.get("Records", []):
            if e.get("readOnly"):
                continue
            print(e["eventTime"], e["eventName"], e.get("sourceIPAddress"), e.get("errorCode", "-"))
