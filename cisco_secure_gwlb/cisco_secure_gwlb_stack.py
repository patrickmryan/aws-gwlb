import sys
from aws_cdk import (
    Duration,
    Stack,
    Tags,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_elasticloadbalancingv2 as elbv2,
    aws_autoscaling as autoscaling,
)
from constructs import Construct


class CiscoSecureGwlbStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # cdk.json
        #  subnet names
        #  vpc-id
        #  AZs
        #  AMI = ami-020a3162e09801a69, AL2-GeneveProxy
        # permission boundary

        permissions_boundary_policy_arn = self.node.try_get_context(
            "PermissionsBoundaryPolicyArn"
        )

        if not permissions_boundary_policy_arn:
            permissions_boundary_policy_name = self.node.try_get_context(
                "PermissionsBoundaryPolicyName"
            )
            if permissions_boundary_policy_name:
                permissions_boundary_policy_arn = self.format_arn(
                    service="iam",
                    region="",
                    account=self.account,
                    resource="policy",
                    resource_name=permissions_boundary_policy_name,
                )
                print(permissions_boundary_policy_arn)

        if permissions_boundary_policy_arn:
            policy = iam.ManagedPolicy.from_managed_policy_arn(
                self, "PermissionsBoundary", permissions_boundary_policy_arn
            )
            iam.PermissionsBoundary.of(self).apply(policy)

        Tags.of(self).add("APPLIANCE", "TEST")

        vpc_name = self.node.try_get_context("VpcName")
        gwlb_subnet_name = "CHARLIE"
        asg_subnet = "DELTA"

        vpc_name = self.node.try_get_context("VpcName")
        vpc = ec2.Vpc.from_lookup(self, "Vpc", tags={"Name": vpc_name})

        if not vpc:
            print(f"could not find VPC named {vpc_name}")
            sys.exit(1)

        vpc_id = vpc.vpc_id
        # print(vpc_id)

        # IAM policies
        # security group(s)
        # launch template

        # INGRESS route to GWLBE
        # put GWLBEs in CHARLIE
        # put instances in DELTA
        # EGRESS default route to IGW, private CIDR route to GWLBE

        # extract the named subnets from the VPC

        # GWLB
        # GWLB endpoints
        # ASG
        # routing
