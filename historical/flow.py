import os
import boto3
import json
import pdb

if __name__ == "__main__":
    ec2_client = boto3.client("ec2")

    log_group_name = os.environ.get("LOG_GROUP_NAME")
    flow_log_arn = os.environ.get("FLOW_LOG_ARN")

    eni_id = "eni-0dcaf77c0a8604991"
    private_ip = "172.16.0.153"

    # if log_group_name and flow_log_arn:

    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.create_flow_logs
    response = ec2_client.create_flow_logs(
        DeliverLogsPermissionArn=flow_log_arn,
        LogGroupName=log_group_name,
        ResourceIds=[eni_id],
        ResourceType="NetworkInterface",
        TrafficType="ALL",
        LogDestinationType="cloud-watch-logs",
        MaxAggregationInterval=60,
        TagSpecifications=[
            {
                "ResourceType": "vpc-flow-log",
                "Tags": [{"Key": "Name", "Value": private_ip}],
            }
        ],
    )

    print(json.dumps(response, indent=2))
