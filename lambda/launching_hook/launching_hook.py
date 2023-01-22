import os
import json
import boto3
from datetime import datetime
from botocore.exceptions import ClientError

DEVICE_INDEX_MANAGEMENT = 0  # eth0
DEVICE_INDEX_DATA = 1  # eth1

# put these in SSM param
ROLE_KEY = "ROLE"


def stringify(o):
    # hack around the fact that datetime does not have a JSON converter
    return o.__str__() if isinstance(o, datetime) else o


def select_resources_with_tag(resources, tag_key, tag_value=""):
    """return a subset of resources that have a tag of the specified key and value"""

    selected = []
    for resource in resources:
        chosen = [
            tag
            for tag in resource["Tags"]
            if tag["Key"] == tag_key and tag["Value"] == tag_value
        ]
        if chosen:
            selected.append(resource)
    return selected


def create_attach_eni(
    ec2_client=None,
    instance_id=None,
    device_index=-1,
    subnet_id=None,
    security_groups=[],
    description="",
    source_dest_flag=True,
    tags={},
):
    """Create an ENI and attach it to the instance"""

    tag_param = {"ResourceType": "network-interface"}
    tag_param["Tags"] = [{"Key": key, "Value": value} for key, value in tags.items()]

    print(f"creating eth{device_index} for {instance_id} in {subnet_id}")

    new_interface = None
    try:
        response = ec2_client.create_network_interface(
            SubnetId=subnet_id,
            Groups=security_groups,
            Description=description,
            TagSpecifications=[tag_param],
        )
        new_interface = response["NetworkInterface"]

        eni_id = response["NetworkInterface"]["NetworkInterfaceId"]
        response = ec2_client.attach_network_interface(
            DeviceIndex=device_index, InstanceId=instance_id, NetworkInterfaceId=eni_id
        )

        # make sure the ENI gets deleted when the instance terminates.
        atch_id = response["AttachmentId"]
        response = ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            Attachment={"AttachmentId": atch_id, "DeleteOnTermination": True},
        )

        response = ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id, SourceDestCheck={"Value": source_dest_flag}
        )

    except ClientError as client_error:
        print(f"failed to create or attach ENI - {client_error}")
        print(
            f"instance {instance_id},  eth{device_index}, {subnet_id}, {security_groups}"
        )
        raise client_error

    return new_interface


def create_tags(ec2_client=None, resource_id="", tags={}):

    tag_list = [{"Key": key, "Value": value} for key, value in tags.items()]
    response = ec2_client.create_tags(Resources=[resource_id], Tags=tag_list)
    return response


def abandon_instance(event_detail={}, autoscaling=None):

    params = {
        "LifecycleHookName": event_detail["LifecycleHookName"],
        "AutoScalingGroupName": event_detail["AutoScalingGroupName"],
        "LifecycleActionToken": event_detail["LifecycleActionToken"],
        "LifecycleActionResult": "ABANDON",
        "InstanceId": event_detail["EC2InstanceId"],
    }
    print(f"calling autoscaling.complete_lifecycle_action({params})")

    try:
        print(json.dumps(params))
        response = autoscaling.complete_lifecycle_action(**params)
    except ClientError as e:
        message = "Error completing lifecycle action: {}".format(e)
        print(message)

    return response


def lambda_handler(event, context):

    print(json.dumps(event))
    event_detail = event["detail"]

    ec2_client = boto3.client("ec2")
    autoscaling = boto3.client("autoscaling")
    ssm_client = boto3.client("ssm")

    resp = ssm_client.get_parameter(
        Name=os.environ["NETWORK_CONFIGURATION_SSM_PARAM"], WithDecryption=True
    )
    network_configuration_param = json.loads(resp["Parameter"]["Value"])

    # convert the above into a list
    network_configs = [None] * len(network_configuration_param.keys())
    network_interfaces = [None] * len(network_configuration_param.keys())

    for index_string, config in network_configuration_param.items():
        device_index = int(index_string)
        network_configs[device_index] = config

    # need to introspect some info about the instance
    result = None
    ec2_client = boto3.client("ec2")
    instance_id = event_detail["EC2InstanceId"]
    try:
        result = ec2_client.describe_instances(InstanceIds=[instance_id])
        print(json.dumps(result, default=stringify))
        # there can only be one
        inst_details = result["Reservations"][0]["Instances"][0]
        vpc_id = inst_details["VpcId"]
        az = inst_details["Placement"]["AvailabilityZone"]

    except ClientError as exc:
        message = f"could not describe instance {instance_id}: {exc}"
        print(message)
        raise exc

    new_name = (
        "firewall_" + (inst_details["PrivateIpAddress"]).replace(".", "_") + f"_{az}"
    )

    create_tags(ec2_client=ec2_client, resource_id=instance_id, tags={"Name": new_name})

    primary_eni = next(
        (
            intf
            for intf in inst_details["NetworkInterfaces"]
            if intf["Attachment"]["DeviceIndex"] == 0
        ),
        None,
    )
    # tag the primary ENI
    role_value = network_configs[0][ROLE_KEY]
    create_tags(
        ec2_client=ec2_client,
        resource_id=primary_eni["NetworkInterfaceId"],
        tags={"Name": f"eth0 - {role_value} {az} {instance_id}", ROLE_KEY: role_value},
    )
    # at this point, there should still only be one interface, the primary one
    # that was created in the launch template
    network_interfaces[0] = primary_eni

    # grab all the subnets for this AZ
    response = ec2_client.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "availability-zone", "Values": [az]},
            {"Name": "tag-key", "Values": [ROLE_KEY]},
        ],
        DryRun=False,
    )
    vpc_subnets = response["Subnets"]

    # now add all the additional ENIs

    # iterate over the list of additional interface. skip the primary interface (index 0)
    for device_index in range(1, len(network_configs)):

        config = network_configs[device_index]
        role_value = config[ROLE_KEY]

        # extract the tagged subnet for this AZ
        subnets = select_resources_with_tag(
            vpc_subnets, tag_key=ROLE_KEY, tag_value=role_value
        )

        if len(subnets) != 1:
            message = (
                f"expected to find one subnet with tag {ROLE_KEY}={role_value} in VPC {vpc_id}, AZ {az}, found "
                + str(len(subnets))
                + " instead"
            )
            print(message)
            raise Exception(message)

        subnet_id = subnets[0]["SubnetId"]

        # extract the security groups for this AZ

        response = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "tag-key", "Values": [ROLE_KEY]},
            ],
            DryRun=False,
        )
        security_groups = response["SecurityGroups"]
        groups = select_resources_with_tag(
            security_groups, tag_key=ROLE_KEY, tag_value=role_value
        )
        if not groups:
            message = (
                f"could not find security groups with tag {role_value} in VPC {vpc_id}"
            )
            raise Exception(message)

        security_groups = [group["GroupId"] for group in groups]

        # create another ENI
        # attach the ENI
        # tag the ENI

        description = config[ROLE_KEY]
        eni = create_attach_eni(
            ec2_client=ec2_client,
            source_dest_flag=config["SourceDestCheck"],
            instance_id=instance_id,
            subnet_id=subnet_id,
            security_groups=security_groups,
            device_index=device_index,
            description=description,
            tags={
                "Name": f"eth{device_index} - {description} {az} {instance_id}",
                ROLE_KEY: role_value,
            },
        )
        network_interfaces[device_index] = eni

    # register the data interface with the GWLB
    elb_client = boto3.client("elbv2")
    geneve_port = 6081

    target_index = next(
        (index for index, config in enumerate(network_configs) if config["IsTarget"]),
        None,
    )

    tg_arn = os.environ["TARGET_GROUP_ARN"]
    private_ip = network_interfaces[target_index]["PrivateIpAddress"]

    try:
        response = elb_client.register_targets(
            TargetGroupArn=tg_arn, Targets=[{"Id": private_ip, "Port": geneve_port}]
        )
    except ClientError as e:
        print(e)
        print(f"Error registering IP : {private_ip} to {tg_arn}. abandoning instance.")

        response = abandon_instance(event_detail=event_detail, autoscaling=autoscaling)

        return response

    # record the target IP in a tag on the instance. we'll need the info
    # when the instance terminates.
    response = ec2_client.create_tags(
        Resources=[instance_id], Tags=[{"Key": "TARGET_IP", "Value": private_ip}]
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
