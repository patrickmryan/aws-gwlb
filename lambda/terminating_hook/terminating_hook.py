import json
import logging
import os
import boto3
import botocore
from botocore.exceptions import ClientError

# need design patterny approach to handling each type of lifecycle action


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

    except ClientError as exc:
        message = f"could not describe instance {instance_id}: {exc}"
        print(message)
        raise exc

    elb_client = boto3.client("elbv2")

    geneve_port = 6081
    device_index = 0
    tg_arn = os.environ["TARGET_GROUP_ARN"]
    eni = [
        intf
        for intf in inst_details["NetworkInterfaces"]
        if intf["Attachment"]["DeviceIndex"] == device_index
    ]
    private_ip = eni["PrivateIpAddress"]

    try:
        response = elb_client.deregister_targets(
            TargetGroupArn=tg_arn, Targets=[{"Id": private_ip, "Port": geneve_port}]
        )
    except ClientError as e:
        print(e)
        print(f"Error deregistering IP : {private_ip} to {tg_arn}")

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
