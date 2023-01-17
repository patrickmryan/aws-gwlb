# https://www.sentiatechblog.com/geneveproxy-an-aws-gateway-load-balancer-reference-application
# https://github.com/sentialabs/geneve-proxy
# https://datatracker.ietf.org/doc/rfc8926/
# https://us-east-1.console.aws.amazon.com/ec2/home?region=us-east-1#ImageDetails:imageId=ami-020a3162e09801a69


from os.path import join
import json
from datetime import datetime, timezone

from aws_cdk import (
    Duration,
    Stack,
    Tags,
    RemovalPolicy,
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
        # key_name = self.node.try_get_context("KeyName")
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
        template_sg.connections.allow_from(intra_vpc, ec2.Port.all_traffic())

        # IAM policies
        # security group(s)
        # launch template

        ami_name = self.node.try_get_context("AmiName")
        ami = ec2.MachineImage.lookup(name=ami_name)

        # role

        instance_role = iam.Role(
            self,
            "FirewallInstanceRole",
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
        lambda_root = "lambda"
        lambda_principal = iam.ServicePrincipal("lambda.amazonaws.com")

        basic_lambda_policy = iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AWSLambdaVPCAccessExecutionRole"
        )

        lambda_settings = {
            "log_retention": logs.RetentionDays.ONE_WEEK,
            "runtime": _lambda.Runtime.PYTHON_3_9,
            "timeout": Duration.seconds(60),
        }

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
            code=_lambda.Code.from_asset(join(lambda_root, "vpce_service")),
            handler="vpce_service.lambda_handler",
            role=service_role,
            # https://docs.aws.amazon.com/lambda/latest/operatorguide/networking-vpc.html
#             vpc=vpc,
#             vpc_subnets=ec2.SubnetSelection(subnet_group_name="NAT"),
            **lambda_settings,
        )

        appliance_subnets = vpc.select_subnets(subnet_group_name="APPLIANCE")
        appliance_subnet_ids = appliance_subnets.subnet_ids

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

        # topic for autoscaling events
        scaling_topic = sns.Topic(self, "AsgScalingEvent")

        asg_name = "gwlb-asg-" + self.stack_name
        asg_arn = f"arn:{self.partition}:autoscaling:{self.region}:{self.account}:autoScalingGroup:*:autoScalingGroupName/{asg_name}"

        asg = autoscaling.CfnAutoScalingGroup(
            self,
            "ASG",
            auto_scaling_group_name=asg_name,  # f"GWLB-ASG-{self.stack_name}",
            vpc_zone_identifier=appliance_subnet_ids,
            launch_template=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                launch_template_id=launch_template.launch_template_id,
                version=launch_template.latest_version_number,
            ),
            # cooldown="60",   #Duration.minutes(1),
            # desired_capacity="0",  # zero for a reason
            min_size="0",
            max_size=str(max_azs * 2),
            health_check_type="EC2",
            health_check_grace_period=60,
            # group_metrics=[autoscaling.GroupMetrics.all()],
            metrics_collection=[
                autoscaling.CfnAutoScalingGroup.MetricsCollectionProperty(
                    granularity="1Minute",
                    metrics=[
                        # "GroupMinSize",
                        # "GroupMaxSize",
                        "GroupDesiredCapacity",
                        "GroupInServiceInstances",
                        # "GroupPendingInstances",
                        # "GroupStandbyInstances",
                        "GroupTerminatingInstances",
                        "GroupTotalInstances",
                        # "GroupInServiceCapacity",
                        # "GroupPendingCapacity",
                        # "GroupStandbyCapacity",
                        # "GroupTerminatingCapacity",
                        "GroupTotalCapacity",
                    ],
                )
            ],
            # update_policy=autoscaling.UpdatePolicy.rolling_update(),
            notification_configurations=[
                autoscaling.CfnAutoScalingGroup.NotificationConfigurationProperty(
                    topic_arn=scaling_topic.topic_arn,
                    notification_types=[
                        "autoscaling:EC2_INSTANCE_LAUNCH",
                        "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
                        "autoscaling:EC2_INSTANCE_TERMINATE",
                        "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
                    ],
                )
            ],
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
                "PutDesiredInstancesSetting"  # + datetime.now(timezone.utc).isoformat()
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
        lifecycle_hook_role = iam.Role(
            self,
            "LifecycleHookRole",
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

        # Make sure the launching rule and lambda are created before the ASG.
        # Bad things can happen if the ASG starts spinning up instances before the
        # lifecycle hook lambdas and rules are deployed.

        launching_rule = self.add_lifecycle_hook(
            construct_id="Launching",
            asg=asg,
            asg_name=asg_name,
            asg_arn=asg_arn,
            lifecycle_hook_role=lifecycle_hook_role,
            lambda_code=_lambda.Code.from_asset(join(lambda_root, "launching_hook")),
            lambda_settings=lambda_settings,
            lambda_handler="launching_hook.lambda_handler",
            # lifecycle_hook_name="Launching",
            lifecycle_transition="autoscaling:EC2_INSTANCE_LAUNCHING",
            default_result="ABANDON",
        )

        asg.node.add_dependency(launching_rule)
        asg_update_resource.node.add_dependency(launching_rule)

        # the launch hook resource should not execute until AFTER the ASG been deployed
        # launch_hook_resource.node.add_dependency(asg)

        terminating_rule = self.add_lifecycle_hook(
            construct_id="Terminating",
            asg=asg,
            asg_name=asg_name,
            asg_arn=asg_arn,
            lifecycle_hook_role=lifecycle_hook_role,
            lambda_code=_lambda.Code.from_asset(join(lambda_root, "terminating_hook")),
            lambda_settings=lambda_settings,
            lambda_handler="terminating_hook.lambda_handler",
            # lifecycle_hook_name="Terminating",
            lifecycle_transition="autoscaling:EC2_INSTANCE_TERMINATING",
            default_result="CONTINUE",
        )
        asg.node.add_dependency(terminating_rule)
        asg_update_resource.node.add_dependency(terminating_rule)

        # set desired_instances AFTER the ASG, hook, lambda, and rule are all deployed.
        asg_update_resource.node.add_dependency(asg)

        # VPC flow logs on APPLIANCE subnets.

        log_group = logs.LogGroup(
            self,
            "VPCFlowLogs",
            removal_policy=RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.ONE_WEEK,
        )

        # https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-cwl.html

        statement = iam.PolicyStatement(
            actions=[
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:CreateLogStream",
                "logs:CreateLogGroup",
                "logs:PutRetentionPolicy",
            ],
            effect=iam.Effect.ALLOW,
            resources=["*"],
        )

        statement.add_account_condition(self.account)
        statement.add_condition(
            "ArnLike",
            {
                "aws:SourceArn": f"arn:{self.partition}:ec2:{self.region}:{self.account}:vpc-flow-log/*"
            },
        )

        flow_log_role = iam.Role(
            self,
            "FlowLogRole",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
            inline_policies={
                "logs": iam.PolicyDocument(
                    assign_sids=True,
                    statements=[statement],
                )
            },
        )

        subnets = appliance_subnets.subnets
        for n in range(len(subnets)):
            ec2.FlowLog(
                self,
                f"ApplianceFlowLog{n}",
                resource_type=ec2.FlowLogResourceType.from_subnet(subnets[n]),
                destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                    log_group, flow_log_role
                ),
                traffic_type=ec2.FlowLogTrafficType.ALL,
                max_aggregation_interval=ec2.FlowLogMaxAggregationInterval.ONE_MINUTE,
                # log_format
            )

        # install logs agent
        # metrics, dashboard

        launch_test_instance_param = self.node.try_get_context("LaunchTestInstance")

        if launch_test_instance_param:
            self.launch_test_instance(
                vpc=vpc,
                vpc_subnets=ec2.SubnetSelection(subnet_group_name="TRUSTED"),
                # key_name=None
            )

    def add_lifecycle_hook(
        self,
        construct_id=None,
        asg=None,
        asg_name=None,
        asg_arn=None,
        lifecycle_hook_role=None,
        lambda_code=None,
        lambda_settings={},
        lambda_handler=None,
        # lifecycle_hook_name=None,
        lifecycle_transition=None,
        default_result=None,
    ):

        hook_lambda = _lambda.Function(
            self,
            construct_id + "HookLambda",
            code=lambda_code,
            handler=lambda_handler,
            role=lifecycle_hook_role,
            **lambda_settings,
        )

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.custom_resources/AwsCustomResource.html
        # https://medium.com/@imageryan/using-awscustomresource-to-fill-the-gaps-in-aws-cdk-351c8423fa80

        lifecycle_hook_name = construct_id + "Hook"

        put_hook_sdk_call = cr.AwsSdkCall(
            service="AutoScaling",
            action="putLifecycleHook",
            parameters={
                "AutoScalingGroupName": asg_name,
                "LifecycleHookName": lifecycle_hook_name,
                "DefaultResult": default_result,
                "HeartbeatTimeout": 120,
                "LifecycleTransition": lifecycle_transition,
                "NotificationMetadata": json.dumps(
                    {"message": "here is some cool metadata"}
                ),
            },
            physical_resource_id=cr.PhysicalResourceId.of(
                construct_id
                + "PutHookSetting"  # + datetime.now(timezone.utc).isoformat()
            ),
        )

        delete_hook_sdk_call = cr.AwsSdkCall(
            service="AutoScaling",
            action="deleteLifecycleHook",
            parameters={
                "AutoScalingGroupName": asg_name,
                "LifecycleHookName": lifecycle_hook_name,
            },
            physical_resource_id=cr.PhysicalResourceId.of(
                # lifecycle_hook_name
                construct_id
                + "DeleteHookSetting"
                # + datetime.now(timezone.utc).isoformat()
            ),
        )

        hook_resource = cr.AwsCustomResource(
            self,
            construct_id + "HookCustomResource",
            on_create=put_hook_sdk_call,
            on_update=put_hook_sdk_call,  # update just does the same thing as create.
            on_delete=delete_hook_sdk_call,
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

        lifecycle_rule = events.Rule(
            self,
            construct_id + "HookRule",
            event_pattern=events.EventPattern(
                source=["aws.autoscaling"],
                detail={
                    "LifecycleTransition": [lifecycle_transition],
                    "AutoScalingGroupName": [asg_name],
                },
            ),
            targets=[events_targets.LambdaFunction(hook_lambda)],
        )

        # Make sure the launching rule and lambda are created before the ASG.
        # Bad things can happen if the ASG starts spinning up instances before the
        # lifecycle hook lambdas and rules are deployed.
        asg.node.add_dependency(lifecycle_rule)

        # the launch hook resource should not execute until AFTER the ASG been deployed
        hook_resource.node.add_dependency(asg)

        return lifecycle_rule

    def launch_test_instance(self, vpc=None, vpc_subnets=None, key_name=None):

        instance_role = iam.Role(
            self,
            "TestInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonS3ReadOnlyAccess"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonSSMManagedInstanceCore"
                ),
            ],
        )

        test_instance = ec2.Instance(
            self,
            "TestInstance",
            vpc=vpc,
            vpc_subnets=vpc_subnets,
            machine_image=ec2.MachineImage.latest_amazon_linux(),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO
            ),
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(10, delete_on_termination=True),
                )
            ],
            role=instance_role,
        )

        return test_instance
