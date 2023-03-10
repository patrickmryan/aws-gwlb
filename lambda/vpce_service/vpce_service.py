import sys
import json
import logging
import time
import boto3
from botocore.exceptions import ClientError
import cfnresponse


def lambda_handler(event, context):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.info("Received event: {}".format(json.dumps(event)))

    try:
        ec2 = boto3.client("ec2")
    except ClientError as e:
        logger.error(f"ERROR: failed to connect to EC2 client: {e}")
        sys.exit(1)

    response_data = {}
    response_status = cfnresponse.FAILED

    try:
        serviceid = event["ResourceProperties"]["VpceServiceId"]
    except Exception as e:
        logger.info("Attribute retrival failure: {}".format(e))

    try:
        if event["RequestType"] == "Delete":
            response_status = cfnresponse.SUCCESS
            cfnresponse.send(event, context, response_status, response_data)
    except Exception:
        logger.exception("Signaling failure to CloudFormation.")
        cfnresponse.send(event, context, cfnresponse.FAILED, {})

    if event["RequestType"] == "Create":
        logger.info("Retrieving VPC Endpoint Service Name:")
        try:
            response = ec2.describe_vpc_endpoint_service_configurations(
                Filters=[{"Name": "service-id", "Values": [serviceid]}]
            )
            logger.info(json.dumps(response))
        except Exception as e:
            logger.info(
                "ec2.describe_vpc_endpoint_service_configurations failure: {}".format(e)
            )

        service_name = response["ServiceConfigurations"][0]["ServiceName"]

        time.sleep(120)

        response_data["ServiceName"] = service_name
        response_status = cfnresponse.SUCCESS
        cfnresponse.send(event, context, response_status, response_data)
