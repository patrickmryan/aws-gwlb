import sys
from os.path import join
import json
from datetime import datetime, timezone

import typing
from aws_cdk import (
    Duration,
    Stack,
    Tags,
    CustomResource,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_elasticloadbalancingv2 as elbv2,
    aws_autoscaling as autoscaling,
    aws_lambda as _lambda,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_logs as logs,
    aws_sns as sns,
    custom_resources as cr,
)
from constructs import Construct


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
        key_name = self.node.try_get_context("KeyName")
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
            max_azs=max_azs,
            nat_gateway_provider=ec2.NatProvider.gateway(),
            subnet_configuration=subnet_configs,
        )

        intra_vpc = ec2.Peer.ipv4(vpc.vpc_cidr_block)
        template_sg = ec2.SecurityGroup(self, "GeneveProxySG", vpc=vpc)
        geneve_port = 6081
        template_sg.connections.allow_from(
            ec2.Peer.any_ipv4(), ec2.Port.tcp(geneve_port)
        )
        # trust all intra-VPC traffic
        template_sg.connections.allow_from(
            intra_vpc, ec2.Port.all_traffic()
        )  # ec2.Port.tcp(22)

        # IAM policies
        # security group(s)
        # launch template

        ami_name = self.node.try_get_context("AmiName")
        ami = ec2.MachineImage.lookup(name=ami_name)

        # role

        instance_role = iam.Role(
            self,
            "InstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonS3ReadOnlyAccess"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonSSMManagedInstanceCore"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "CloudWatchAgentServerPolicy"
                ),
            ],
            inline_policies={
                "logretention": iam.PolicyDocument(
                    assign_sids=True,
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "logs:PutRetentionPolicy",
                            ],
                            effect=iam.Effect.ALLOW,
                            resources=["*"],
                        ),
                    ],
                )
            },
        )

        # enable CW logs access
        # create CW log
        # add code to user data

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
            # key_name=key_name,    # don't need this. SSM console is enabled.
            role=instance_role,
            security_group=template_sg,
            # user_data=user_data,
        )

        # settings for all python Lambda functions
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
                            actions=[
                                "ec2:DescribeVpcEndpointServiceConfigurations",
                                # "ec2:Describe*",
                            ],
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
            log_retention=logs.RetentionDays.ONE_DAY,  # log_retention,
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
        vpc_endpoints = {}
        for az in vpc.availability_zones:
            vpc_endpoints[az] = ec2.CfnVPCEndpoint(
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

        target_group = elbv2.CfnTargetGroup(
            self,
            "GWLBTargetGroup",
            health_check_enabled=True,
            health_check_port="80",
            health_check_protocol="TCP",
            health_check_timeout_seconds=5,
            healthy_threshold_count=3,
            port=geneve_port,
            protocol="GENEVE",
            target_type="instance",
            unhealthy_threshold_count=3,
            vpc_id=vpc.vpc_id,
        )

        subnet_ids = [
            subnet.subnet_id
            for subnet in (vpc.select_subnets(subnet_group_name="APPLIANCE")).subnets
        ]

        asg_name = "gwlb-asg-" + self.stack_name
        asg_arn = f"arn:{self.partition}:autoscaling:{self.region}:{self.account}:autoScalingGroup:*:autoScalingGroupName/{asg_name}"

        asg = autoscaling.CfnAutoScalingGroup(
            self,
            "ASG",
            auto_scaling_group_name=asg_name,  # f"GWLB-ASG-{self.stack_name}",
            vpc_zone_identifier=subnet_ids,
            launch_template=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                launch_template_id=launch_template.launch_template_id,
                version=launch_template.latest_version_number,
            ),
            # cooldown="60",   #Duration.minutes(1),
            desired_capacity="0",  # zero for a reason
            min_size="0",
            max_size=str(max_azs * 2),
            health_check_type="EC2",
            health_check_grace_period=60,  # Duration.minutes(1),
            # group_metrics=[autoscaling.GroupMetrics.all()],
            # metrics_collection=
            # update_policy=autoscaling.UpdatePolicy.rolling_update(),
            target_group_arns=[target_group.ref],
        )

        listener = elbv2.CfnListener(
            self,
            "GWLBListener",
            default_actions=[
                elbv2.CfnListener.ActionProperty(
                    type="forward", target_group_arn=target_group.ref
                )
            ],
            load_balancer_arn=gwlb.ref,
        )

        # routes:
        #  trusted:  default to VPCE per AZ
        #  edge: subnet CIDR to VPCE per AZ

        edge_route_table = ec2.CfnRouteTable(self, "EdgeRouteTable", vpc_id=vpc.vpc_id)

        for az, vpce in vpc_endpoints.items():

            subnets = (
                vpc.select_subnets(subnet_group_name="TRUSTED", availability_zones=[az])
            ).subnets

            for n in range(len(subnets)):
                # add the outbound route
                subnets[n].add_route(
                    f"DefaultRouteFor-{az}-subnet-{n}",
                    router_id=vpce.ref,
                    router_type=ec2.RouterType.VPC_ENDPOINT,
                    destination_cidr_block="0.0.0.0/0",
                )
                # add a return route to the edge route table
                ec2.CfnRoute(
                    self,
                    f"EdgeRoute-{az}",
                    route_table_id=edge_route_table.attr_route_table_id,
                    vpc_endpoint_id=vpce.ref,
                    destination_cidr_block=subnets[n].ipv4_cidr_block,
                )

        # attach the edge route table to the VPC so that return traffic is
        # sent back to the GWLB
        ec2.CfnGatewayRouteTableAssociation(
            self,
            "EdgeRouteTableAssociation",
            route_table_id=edge_route_table.attr_route_table_id,
            gateway_id=vpc.internet_gateway_id,
        )

        # lifeycle hook
        # functions
        # custom resource to set the capacity at the right time

        set_desired_instances_sdk_call = cr.AwsSdkCall(
            service="AutoScaling",
            action="updateAutoScalingGroup",
            parameters={
                "AutoScalingGroupName": asg_name,
                "DesiredCapacity": max_azs,
            },
            physical_resource_id=cr.PhysicalResourceId.of(
                "PutDesiredInstancesSetting" + datetime.now(timezone.utc).isoformat()
            ),
        )

        asg_update_resource = cr.AwsCustomResource(
            self,
            "DesiredInstancesResource",
            on_create=set_desired_instances_sdk_call,
            on_update=set_desired_instances_sdk_call,  # update just does the same thing as create.
            policy=cr.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=["autoscaling:updateAutoScalingGroup"],
                        resources=[asg_arn],
                    )
                ]
            ),
        )

        # cw logs for firewalls

        # now adding the lambda for the launching hook

        acct_instances_arn = self.format_arn(
            partition=self.partition,
            service="ec2",
            region=self.region,
            account=self.account,
            resource="instance",
            resource_name="*",
        )

        managed_policies = [basic_lambda_policy]
        lambda_role = iam.Role(
            self,
            "LaunchingHookRole",
            assumed_by=lambda_principal,
            managed_policies=managed_policies,
            inline_policies={
                "CompleteLaunch": iam.PolicyDocument(
                    assign_sids=True,
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["autoscaling:CompleteLifecycleAction"],
                            resources=[asg_arn],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["ec2:DescribeInstances"],
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["ec2:CreateTags"],
                            resources=[acct_instances_arn],
                        ),
                    ],
                )
            },
        )

        launching_hook_lambda = _lambda.Function(
            self,
            "LaunchingHookLambda",
            runtime=runtime,
            code=_lambda.Code.from_asset(join(lambda_root, "launching_hook")),
            handler="launching_hook.lambda_handler",
            timeout=Duration.seconds(60),
            role=lambda_role,
            log_retention=log_retention,
        )

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.custom_resources/AwsCustomResource.html
        # https://medium.com/@imageryan/using-awscustomresource-to-fill-the-gaps-in-aws-cdk-351c8423fa80

        set_launch_hook_sdk_call = cr.AwsSdkCall(
            service="AutoScaling",
            action="putLifecycleHook",
            parameters={
                "AutoScalingGroupName": asg_name,
                "LifecycleHookName": "InstanceLaunchingHook",
                "DefaultResult": "ABANDON",
                "HeartbeatTimeout": 120,
                "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
                "NotificationMetadata": json.dumps(
                    {"message": "here is some cool metadata"}
                ),
            },
            physical_resource_id=cr.PhysicalResourceId.of(
                "PutInstanceLaunchingHookSetting"
                + datetime.now(timezone.utc).isoformat()
            ),
        )

        launch_hook_resource = cr.AwsCustomResource(
            self,
            "LaunchHookResource",
            on_create=set_launch_hook_sdk_call,
            on_update=set_launch_hook_sdk_call,  # update just does the same thing as create.
            # on_delete   not implemented
            policy=cr.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        actions=[
                            "autoscaling:PutLifecycleHook",
                            "autoscaling:DeleteLifecycleHook",
                        ],
                        resources=[asg_arn],
                    )
                ]
            ),
        )

        launching_rule = events.Rule(
            self,
            "LaunchingHookRule",
            event_pattern=events.EventPattern(
                source=["aws.autoscaling"],
                detail={
                    "LifecycleTransition": ["autoscaling:EC2_INSTANCE_LAUNCHING"],
                    "AutoScalingGroupName": [asg_name],
                },
            ),
            targets=[events_targets.LambdaFunction(launching_hook_lambda)],
        )

        # Make sure the launching rule and lambda are created before the ASG.
        # Bad things can happen if the ASG starts spinning up instances before the
        # lambdas and rules are deployed.
        asg.node.add_dependency(launching_rule)

        # the launch hook resource should not execute until AFTER the ASG been deployed
        launch_hook_resource.node.add_dependency(asg)

        # set desired_instances AFTER the ASG, hook, lambda, and rule are all deployed.
        asg_update_resource.node.add_dependency(asg)
        asg_update_resource.node.add_dependency(launching_rule)
