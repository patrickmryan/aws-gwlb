import sys
from os.path import join

# from typing import Union, Sequence
import typing
from aws_cdk import (
    Duration,
    Stack,
    Tags,
    CustomResource,
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
        #  lifecycle hooks
        #     first just do init and terminate (not SFN)

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

        # Tags.of(self).add("APPLIANCE", "TEST")

        cidr_range = self.node.try_get_context("CidrRange")
        # availability_zones = self.node.try_get_context("AvailabilityZones")
        max_azs = self.node.try_get_context("MaxAZs")
        subnet_configs = []
        subnet_cidr_mask = 27

        subnet_configs.append(
            ec2.SubnetConfiguration(
                name="EGRESS",
                subnet_type=ec2.SubnetType.PUBLIC,
                cidr_mask=subnet_cidr_mask,
            )
        )
        subnet_configs.append(
            ec2.SubnetConfiguration(
                name="NAT",
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                cidr_mask=subnet_cidr_mask,
            )
        )
        subnet_configs.append(
            ec2.SubnetConfiguration(
                name="APPLIANCE",
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                cidr_mask=subnet_cidr_mask,
            )
        )
        subnet_configs.append(
            ec2.SubnetConfiguration(
                name="TRUSTED",
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                cidr_mask=subnet_cidr_mask,
            )
        )

        vpc = ec2.Vpc(
            self,
            "GwlbVpc",
            ip_addresses=ec2.IpAddresses.cidr(cidr_range),
            enable_dns_hostnames=True,
            enable_dns_support=True,
            # availability_zones=availability_zones,
            max_azs=max_azs,
            nat_gateway_provider=ec2.NatProvider.gateway(),
            subnet_configuration=subnet_configs,
        )

        # for az in availability_zones:
        #     appliance_subnets = vpc.select_subnets(subnet_group_name="APPLIANCE", availability_zones=[az])

        intra_vpc = ec2.Peer.ipv4(vpc.vpc_cidr_block)
        template_sg = ec2.SecurityGroup(self, "GeneveProxySG", vpc=vpc)
        geneve_port = 6081
        template_sg.connections.allow_from(
            ec2.Peer.any_ipv4(), ec2.Port.tcp(geneve_port)
        )
        template_sg.connections.allow_from(intra_vpc, ec2.Port.tcp(22))

        # IAM policies
        # security group(s)
        # launch template

        ami_name = self.node.try_get_context("AmiName")
        ami = ec2.MachineImage.lookup(name=ami_name)

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

        appliance_subnet_ids = (
            vpc.select_subnets(subnet_group_name="APPLIANCE")
        ).subnet_ids

        gwlb = elbv2.CfnLoadBalancer(
            self,
            "GatewayLoadBalancer",
            name=f"GWLB-{self.stack_name}",
            type="gateway",
            subnets=appliance_subnet_ids,
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
            gateway_load_balancer_arns=[gwlb.ref],
        )

        retrieve_vpce_service_name = CustomResource(
            self,
            "RetrieveVpceServiceName",
            resource_type="Custom::RetrieveAttributes",
            service_token=vpce_service_lambda.function_arn,
            properties={"VpceServiceId": gw_endpoint_service.ref},
        )

        # create the VPC endpoints
        for az in vpc.availability_zones:
            ec2.CfnVPCEndpoint(
                self,
                f"VPCE-{az}",
                vpc_id=vpc.vpc_id,
                subnet_ids=(
                    vpc.select_subnets(
                        subnet_group_name="APPLIANCE", availability_zones=[az]
                    )
                ).subnet_ids,
                vpc_endpoint_type="GatewayLoadBalancer",
                service_name=retrieve_vpce_service_name.get_att_string("ServiceName"),
            )


#   PAVMGatewayEndpoint1:
#     Type: AWS::EC2::VPCEndpoint
#     Properties:
#       VpcEndpointType: GatewayLoadBalancer
#       ServiceName: !GetAtt RetrieveVpceServiceName.ServiceName
#       SubnetIds:
#         - !Select [ 0, !Ref DataSubnets ]
#       VpcEndpointType: GatewayLoadBalancer
#       VpcId: !Ref InterfaceVpcId


# INGRESS route to GWLBE
# put GWLBEs in CHARLIE
# put instances in DELTA
# EGRESS default route to IGW, private CIDR route to GWLBE (edge route table)

# extract the named subnets from the VPC

# GWLB
# GWLB endpoints
# ASG
# routing
