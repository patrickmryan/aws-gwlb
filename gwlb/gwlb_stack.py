import sys
from os.path import join

# from typing import Union, Sequence
import typing
from aws_cdk import (
    Duration,
    Stack,
    Tags,
    # ResolutionTypeHint,
    IResolvable,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_elasticloadbalancingv2 as elbv2,
    aws_autoscaling as autoscaling,
    aws_lambda as _lambda,
    aws_logs as logs,
)
from constructs import Construct
import boto3


class GwlbStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # cdk.json
        #  subnet names
        #  vpc-id
        #  AZs
        #  AMI = ami-020a3162e09801a69, AL2-GeneveProxy
        # permission boundary

        # to do
        #  create VPC
        #   subnets: egress (IGW), NAT, security, trusted
        #  add CW logs agent to template, add permission to role
        #  instance in trusted subnet, add SSM console access

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

        ec2_resource = boto3.resource("ec2")

        vpc_name = self.node.try_get_context("VpcName")
        gwlb_subnet_name = "CHARLIE"
        asg_subnet = "DELTA"

        vpc_name = self.node.try_get_context("VpcName")
        vpc = ec2.Vpc.from_lookup(self, "Vpc", tags={"Name": vpc_name})

        if not vpc:
            print(f"could not find VPC named {vpc_name}")
            sys.exit(1)

        vpc_id = vpc.vpc_id
        intra_vpc = ec2.Peer.ipv4(vpc.vpc_cidr_block)

        vpc_resource = ec2_resource.Vpc(vpc_id)

        subnets_dict = {}
        for subnet in vpc_resource.subnets.all():
            name_tag = next(
                (tag for tag in subnet.tags if tag["Key"] == "CWALL_ROLE"), None
            )
            subnet_name = name_tag["Value"]
            if subnet_name not in subnets_dict:
                subnets_dict[subnet_name] = []
            subnets_dict[subnet_name].append(subnet.id)

        gwlb_subnet_ids = subnets_dict[gwlb_subnet_name]

        template_sg = ec2.SecurityGroup(self, "GeneveProxySG", vpc=vpc)
        geneve_port = 6081
        template_sg.connections.allow_from(
            ec2.Peer.any_ipv4(), ec2.Port.tcp(geneve_port)
        )
        template_sg.connections.allow_from(intra_vpc, ec2.Port.tcp(22))

        # IAM policies
        # security group(s)
        # launch template

        ami = ec2.MachineImage.lookup(name="AL2-GeneveProxy")

        # role
        # enable CW logs access

        launch_template = ec2.LaunchTemplate(
            self,
            "GeneveProxyServer",
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL
            ),
            machine_image=ami,
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(40, delete_on_termination=True),
                )
            ],
            # role
            security_group=template_sg,
            # user_data=user_data,
        )

        # setting for all python Lambda functions
        runtime = _lambda.Runtime.PYTHON_3_9
        lambda_root = "lambda"
        log_retention = logs.RetentionDays.ONE_WEEK
        lambda_principal = iam.ServicePrincipal("lambda.amazonaws.com")

        basic_lambda_policy = iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AWSLambdaVPCAccessExecutionRole"
        )

        service_role = iam.Role(
            self,
            "VpceServiceLambdaExecutionRole",
            assumed_by=lambda_principal,
            managed_policies=[basic_lambda_policy],
            inline_policies={
                "ec2read": iam.PolicyDocument(
                    assign_sids=True,
                    statements=[
                        iam.PolicyStatement(
                            actions=["ec2:DescribeVpcEndpointServiceConfigurations"],
                            effect=iam.Effect.ALLOW,
                            resources=["*"],  # maybe narrower
                        ),
                    ],
                )
            },
        )

        vpce_service_lambda = _lambda.Function(
            self,
            "VpceServiceLambda",
            runtime=runtime,
            code=_lambda.Code.from_asset(join(lambda_root, "vpce_service")),
            handler="vpce_service.lambda_handler",
            # environment={**debug_env},
            timeout=Duration.seconds(150),
            role=service_role,
            log_retention=log_retention,
        )

        gwlb = elbv2.CfnLoadBalancer(
            self,
            "GatewayLoadBalancer",
            name=f"GWLB-{self.stack_name}",
            type="gateway",
            subnets=gwlb_subnet_ids,
            scheme="internal",
            load_balancer_attributes=[
                elbv2.CfnLoadBalancer.LoadBalancerAttributeProperty(
                    key="load_balancing.cross_zone.enabled", value="true"
                )
            ],
        )

        gw_endpoint_service = ec2.CfnVPCEndpointService(
            self,
            "VPCEndpointService",
            acceptance_required=False,
            gateway_load_balancer_arns=[gwlb.ref],  # <-- FIXED
        )

        # INGRESS route to GWLBE
        # put GWLBEs in CHARLIE
        # put instances in DELTA
        # EGRESS default route to IGW, private CIDR route to GWLBE (edge route table)

        # extract the named subnets from the VPC

        # GWLB
        # GWLB endpoints
        # ASG
        # routing
