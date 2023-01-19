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
