import json
import boto3
from botocore.exceptions import ClientError


def lambda_handler(event, context):

    print(json.dumps(event))

    ec2_client = boto3.client("ec2")
    autoscaling = boto3.client("autoscaling")
    event_detail = event["detail"]

    # need to introspect some info about the instance
    result = None
    ec2_client = boto3.client("ec2")
    instance_id = event_detail["EC2InstanceId"]
    try:
        result = ec2_client.describe_instances(InstanceIds=[instance_id])
        # there can only be one
        inst = result["Reservations"][0]["Instances"][0]
        vpc_id = inst["VpcId"]
        az = inst["Placement"]["AvailabilityZone"]
    except ClientError as exc:
        message = f"could not describe instance {instance_id}: {exc}"
        print(message)
        raise exc

    new_name = "firewall_" + (inst["PrivateIpAddress"]).replace(".", "_") + f"_{az}"

    response = ec2_client.create_tags(
        Resources=[instance_id], Tags=[{"Key": "Name", "Value": new_name}]
    )

    params = {
        "LifecycleHookName": event_detail["LifecycleHookName"],
        "AutoScalingGroupName": event_detail["AutoScalingGroupName"],
        "LifecycleActionToken": event_detail["LifecycleActionToken"],
        "LifecycleActionResult": "CONTINUE",
        "InstanceId": event_detail["EC2InstanceId"],
    }
    print(f"calling autoscaling.complete_lifecycle_action({params})")

    try:
        print(json.dumps(params))
        response = autoscaling.complete_lifecycle_action(**params)
    except ClientError as e:
        message = "Error completing lifecycle action: {}".format(e)
        print(message)

    print(response)
