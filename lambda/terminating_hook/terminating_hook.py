import json
import logging
import os
from datetime import datetime
import boto3
from botocore.exceptions import ClientError


def stringify(o):
    # hack around the fact that datetime does not have a JSON converter
    return o.__str__() if isinstance(o, datetime) else o


def lambda_handler(event, context):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    logger.info(json.dumps(event))
    event_detail = event["detail"]

    # need to introspect some info about the instance
    result = None
    ec2_client = boto3.client("ec2")
    instance_id = event_detail["EC2InstanceId"]
    try:
        result = ec2_client.describe_instances(InstanceIds=[instance_id])
        # there can only be one
        inst_details = result["Reservations"][0]["Instances"][0]
        logger.info(json.dumps(inst_details, default=stringify))

    except ClientError as exc:
        message = f"could not describe instance {instance_id}: {exc}"
        logger.error(message)
        raise exc

    elb_client = boto3.client("elbv2")

    geneve_port = 6081
    tg_arn = os.environ["TARGET_GROUP_ARN"]
    tags = {tag["Key"]: tag["Value"] for tag in inst_details["Tags"]}
    private_ip = tags["TARGET_IP"]

    try:
        logger.info(f"deregistering {private_ip} from {tg_arn}")
        response = elb_client.deregister_targets(
            TargetGroupArn=tg_arn, Targets=[{"Id": private_ip, "Port": geneve_port}]
        )
        logger.info("success")
    except ClientError as e:
        logger.error(e)
        logger.error(f"Error deregistering IP : {private_ip} to {tg_arn}")

        # allow the terminating event to complete

    autoscaling = boto3.client("autoscaling")

    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/autoscaling.html#AutoScaling.Client.complete_lifecycle_action
    response = None
    try:
        params = {
            "LifecycleActionResult": "CONTINUE",
            "LifecycleHookName": event_detail["LifecycleHookName"],
            "AutoScalingGroupName": event_detail["AutoScalingGroupName"],
            "LifecycleActionToken": event_detail["LifecycleActionToken"],
            # super weird that this name is inconsistent
            "InstanceId": event_detail["EC2InstanceId"],
        }

        logger.info("calling autoscaling.complete_lifecycle_action")
        logger.info(json.dumps(params))
        response = autoscaling.complete_lifecycle_action(**params)
        logger.info(json.dumps(response))

    except ClientError as e:
        message = "Error completing lifecycle action: {}".format(e)
        logger.error(message)

    return response
