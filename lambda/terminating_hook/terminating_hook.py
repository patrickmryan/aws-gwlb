import json
import logging
import os
import boto3
import botocore
from botocore.exceptions import ClientError

# need design patterny approach to handling each type of lifecycle action

# event =
#
# {
#   "version": "0",
#   "id": "f5dee75f-1a60-e71c-6551-be73abf6f29e",
#   "detail-type": "EC2 Instance-terminate Lifecycle Action",
#   "source": "aws.autoscaling",
#   "account": "772387910155",
#   "time": "2021-05-25T20:11:52Z",
#   "region": "us-west-1",
#   "resources": [
#     "arn:aws:autoscaling:us-west-1:772387910155:autoScalingGroup:a6f34dd4-8215-4206-a026-9d0db7afe09e:autoScalingGroupName/FTDv-ASG-us-west-1-asg34"
#   ],
#   "detail": {
#     "LifecycleActionToken": "7d2ae3d9-e8c9-40f7-8159-fdd27053e9c7",
#     "AutoScalingGroupName": "FTDv-ASG-us-west-1-asg34",
#     "LifecycleHookName": "ftdv-terminating-hook-asg34",
#     "EC2InstanceId": "i-0dd562a061fb40626",
#     "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING",
#     "NotificationMetadata": "cinder-configuration-asg34",
#     "Origin": "AutoScalingGroup",
#     "Destination": "EC2"
#   }
# }


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):

    logger.info(json.dumps(event))

    required_params = ["detail"]
    # generate a list of the missing parameters.
    missing = set(required_params).difference(event.keys())
    if missing:
        raise Exception("missing parameters: " + (",".join(missing)))

    event_detail = event["detail"]
    # instance_id = event_detail["EC2InstanceId"]
    # asg_name = event_detail["AutoScalingGroupName"]

    # # NotificationMetedata stores the name of the SSM param that contains the CI metadata
    # # ci_configuration_param = event_detail["NotificationMetadata"]
    # # if not ci_configuration_param:
    # #     raise Exception("missing required parameter configuration_ssm_parameter")

    # result = None
    # ec2_client = boto3.client("ec2")
    # try:
    #     result = ec2_client.describe_instances(InstanceIds=[instance_id])
    # except botocore.exceptions.ClientError as e:
    #     print(
    #         "Error describing the instance {}: {}".format(
    #             instance_id, e.response["Error"]
    #         )
    #     )
    #     # pass

    # # should be exactly one result
    # instance = result["Reservations"][0]["Instances"][0]
    # # get the value of containerUUID from the tag on the instance
    # containerUUID = None
    # device_id_tag = next(
    #     (tag for tag in instance["Tags"] if tag["Key"] == "containerUUID"), None
    # )
    # if device_id_tag:
    #     containerUUID = device_id_tag["Value"]
    # else:
    #     # this is bad
    #     pass

    # # go get the configuration info from the SSM parameter
    # ssm_client = boto3.client("ssm")
    # resp = ssm_client.get_parameter(Name=ci_configuration_param, WithDecryption=True)
    # ci_param = json.loads(resp["Parameter"]["Value"])

    # # extract the values from the SSM parameter
    # # configuration = param_value['configuration']
    # # fmc_ip = configuration['fmc_ip']
    # fmc_ip  = ci_param["fmc_ip"]
    # vpc_id  = ci_param["vpc_id"]

    # # call the lambda that handles instance termination and failover
    # # should move this into SNS or similar

    # env = "UPDATE_ROUTING_LAMBDA"
    # routing_function = os.environ.get(env)
    # if not routing_function:
    #     raise Exception("missing required ENV variable {env}")

    # payload = {
    #     "action": "terminated",
    #     "instance_id": instance_id,
    #     "asg_name": asg_name,
    #     "vpc_id"  : vpc_id,
    #     "ci_configuration" : ci_param,
    #     # eventually get the CIDRs as parameters
    #     "destination_cidr": "0.0.0.0/0",
    #     "mission_cidr": "10.0.0.0/8",
    # }

    # lambda_client = boto3.client("lambda")
    # response = lambda_client.invoke(
    #     FunctionName=routing_function, Payload=(json.dumps(payload)).encode()
    # )

    # if (
    #     containerUUID
    # ):  # just skip the deregistration if there's no value for containerUUID.

    #     # get credentials for FMC
    #     token_function = os.environ.get(
    #         "GET_TOKEN_LAMBDA", None
    #     )  # exception if missing
    #     # lambda_client = boto3.client('lambda')
    #     response = lambda_client.invoke(
    #         FunctionName=token_function,
    #         Payload=(json.dumps({"fmc_ip": fmc_ip})).encode(),
    #     )
    #     # create the FMC API
    #     creds = json.loads((response["Payload"]).read())
    #     fmc_api = fmcapi.FmcApi(fmc_ip=fmc_ip)
    #     fmc_api.set_token(creds)

    #     try:
    #         # tell FMC to deregister this device
    #         fmc_api.deregister_ftd(containerUUID)
    #     except Exception as exc:
    #         print(
    #             f"deregister_ftd failed for instance {instance_id}, device {containerUUID}: {exc}"
    #         )
    #         # if the deregistration fails for any reason, just keep going
    #         # pass

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
        logger.info(response)
    except ClientError as e:
        message = "Error completing lifecycle action: {}".format(e)
        logger.error(message)
        # raise Exception(message)

    return response
