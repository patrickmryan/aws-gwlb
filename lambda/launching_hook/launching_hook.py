import os
import json
import boto3
import random
from botocore.exceptions import ClientError


def generate_random_key():
    # generate string of 4 random digits
    number = random.randint(0, 9999)
    return f"{number:04}"


def lambda_handler(event, context):

    print(json.dumps(event))
    event_detail = event["detail"]

    state_machine_arn = os.environ.get("STATE_MACHINE_ARN")

    sfn_client = boto3.client("stepfunctions")

    # Need a provide a one-time key to the new FTDv. It will be used when
    # the FTDv is registered to FMC.
    registration_key = "ftdv" + generate_random_key()

    # payload to kick off step function

    sfn_input = {
        "lifecycle_hook_details": event_detail,
        "registration_key": registration_key
        #     "configuration_ssm_parameter" : ci_configuration,
        #     "ci_configuration": ci_configuration,
        #     "instance_id": instance_id,
        #     "availability_zone": az,
        #     "ftd_ip": ftd_ip,
        #     "registration_key": registration_key,
        #     "fmc_ip": ci_configuration["fmc_ip"],
        #     "vpc_id": ci_configuration["vpc_id"],
        #     "access_policy": ci_configuration["access_policy"],
        #     "fmc_device_group": ci_configuration.get("fmc_device_group", ""),
        #     "nat_policy": ci_configuration.get("nat_policy", ""),
        #     "fmc_via_nat": False,  # "false"
    }

    task_name = "configuring-" + event_detail["EC2InstanceId"]

    # kick off the step function to create a new FTD
    response = sfn_client.start_execution(
        stateMachineArn=state_machine_arn, name=task_name, input=json.dumps(sfn_input)
    )
    print(response)
    return {"executionArn": response["executionArn"]}
