import os
import json
import boto3
import random
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    print(json.dumps(event))

    # {
    #     "version": "0",
    #     "id": "be263847-9cfa-4b44-7aee-83fb33413352",
    #     "detail-type": "EC2 Instance-launch Lifecycle Action",
    #     "source": "aws.autoscaling",
    #     "account": "286367598331",
    #     "time": "2023-07-09T20:26:16Z",
    #     "region": "us-east-1",
    #     "resources": [
    #         "arn:aws:autoscaling:us-east-1:286367598331:autoScalingGroup:0f879b1b-2af6-4b23-98cb-84a7a6330787:autoScalingGroupName/NSB-gwlb-asg-AwsGwlbStack"
    #     ],
    #     "detail": {
    #         "LifecycleActionToken": "d4f4a29d-36fa-4d10-ab1a-cda7d35c72d5",
    #         "AutoScalingGroupName": "NSB-gwlb-asg-AwsGwlbStack",
    #         "LifecycleHookName": "LaunchingHook",
    #         "EC2InstanceId": "i-0e2132792885032a7",
    #         "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
    #         "NotificationMetadata": {
    #             "message": "here is some cool metadata"
    #         },
    #         "Origin": "EC2",
    #         "Destination": "AutoScalingGroup"
    #     }
    # }
