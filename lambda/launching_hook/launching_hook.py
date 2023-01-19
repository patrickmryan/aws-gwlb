import json
import boto3
from botocore.exceptions import ClientError

DEVICE_INDEX_MANAGEMENT = 0  # eth0
DEVICE_INDEX_DIAGNOSTIC = 1  # eth1
DEVICE_INDEX_EGRESS = 2  # eth2, GigEthernet0/0
DEVICE_INDEX_INGRESS = 3  # eth3, GigEthernet0/1

# put these in SSM param
ROLE_KEY = "ROLE"

MANAGEMENT_TAG = "MANAGEMENT"
DATA_TAG = "DATA"


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

    try:
        response = ec2_client.create_network_interface(
            SubnetId=subnet_id,
            Groups=security_groups,
            Description=description,
            TagSpecifications=[tag_param],
        )

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


def update_name_tag(ec2_client=None, instance_id="", name_tag=""):

    response = ec2_client.create_tags(
        Resources=[instance_id], Tags=[{"Key": "Name", "Value": name_tag}]
    )
    return response


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

    # response = ec2_client.create_tags(
    #     Resources=[instance_id], Tags=[{"Key": "Name", "Value": new_name}]
    # )
    response = update_name_tag(
        ec2_client=ec2_client, instance_id=instance_id, name_tag=new_name
    )

    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    inst_details = response["Reservations"][0]["Instances"][0]
    az = inst_details["Placement"]["AvailabilityZone"]

    # grab all the subnets for this AZ
    response = ec2_client.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "availability-zone", "Values": [az]},
            {"Name": "tag-key", "Values": [ROLE_KEY]},  # resource_tags
        ],
        DryRun=False,
    )
    vpc_subnets = response["Subnets"]
    # extract the mgmt subnet for this AZ
    mgmt_tag = MANAGEMENT_TAG
    subnets = select_resources_with_tag(
        vpc_subnets, tag_key=ROLE_KEY, tag_value=mgmt_tag
    )

    if len(subnets) != 1:
        message = (
            f"expected to find one subnet with tag {ROLE_KEY}={mgmt_tag} in VPC {vpc_id}, AZ {az}, found "
            + str(len(subnets))
            + " instead"
        )
        print(message)
        raise Exception(message)

    mgmt_subnet_id = subnets[0]["SubnetId"]

    # extract the security groups for this AZ

    response = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "tag-key", "Values": [ROLE_KEY]},  # resource_tags
        ],
        DryRun=False,
    )
    ftd_groups = response["SecurityGroups"]
    groups = select_resources_with_tag(ftd_groups, tag_key=ROLE_KEY, tag_value=mgmt_tag)
    if not groups:
        message = f"could not find security groups with tag {mgmt_tag} in VPC {vpc_id}"
        raise Exception(message)

    mgmt_security_groups = [group["GroupId"] for group in groups]

    # create another ENI
    # attach the ENI
    # tag the ENI

    index = 1
    description = "management"
    create_attach_eni(
        ec2_client=ec2_client,
        source_dest_flag=True,
        instance_id=instance_id,
        subnet_id=mgmt_subnet_id,
        security_groups=mgmt_security_groups,
        device_index=index,
        description=description,
        tags={
            "Name": f"eth{index} - {description} {az} {instance_id}",
            ROLE_KEY: "MANAGEMENT",
        },
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
