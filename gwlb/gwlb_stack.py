# https://www.sentiatechblog.com/geneveproxy-an-aws-gateway-load-balancer-reference-application
# https://github.com/sentialabs/geneve-proxy
# https://datatracker.ietf.org/doc/rfc8926/

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
    aws_sns_subscriptions as subscriptions,
    aws_ssm as ssm,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as sfn_tasks,
    custom_resources as cr,
)
from constructs import Construct


class SecurityVpcType:  # this really need to be a new construct
    def __init__(self, stack=None):
        self.stack = stack

    def nat_gateway_provider(self):
        return None

    def subnet_configurations(self, subnet_cidr_mask=None):

        return [
            ec2.SubnetConfiguration(
                name="trusted",
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                cidr_mask=subnet_cidr_mask,
            ),
            ec2.SubnetConfiguration(
                name="management",
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                cidr_mask=subnet_cidr_mask,
            ),
        ]

    def add_return_routes(
        self,
        subnet_name=None,
        cidr_ranges=[],
        tg_attachment=None,
        router_id=None,
    ):

        subnets = (self.vpc.select_subnets(subnet_group_name=subnet_name)).subnets

        for subnet_index, subnet in enumerate(subnets):
            for range_index, cidr_range in enumerate(cidr_ranges):

                # Have to do this via CfnRoute instead of subnet.add_route
                # because CDK seems not to know that it can't create
                # a route back to the TG until the attachment is available.
                # So we explicitly add the dependency. Annoying.

                route = ec2.CfnRoute(
                    self.stack,
                    f"{subnet_name}-Route-{subnet_index}-{range_index}",
                    route_table_id=subnet.route_table.route_table_id,
                    transit_gateway_id=router_id,
                    destination_cidr_block=cidr_range,
                )
                route.add_dependency(tg_attachment)

    @staticmethod
    def for_type_named(vpc_type_param, stack=None):

        if vpc_type_param == "NorthSouth":
            return NorthSouth(stack=stack)

        if vpc_type_param == "EastWest":
            return EastWest(stack=stack)

        return None


class NorthSouth(SecurityVpcType):
    def nat_gateway_provider(self):
        return ec2.NatProvider.gateway()

    def subnet_configurations(self, subnet_cidr_mask=None):
        configs = super().subnet_configurations(subnet_cidr_mask=subnet_cidr_mask)

        config = ec2.SubnetConfiguration(
            name="public",
            subnet_type=ec2.SubnetType.PUBLIC,
            cidr_mask=subnet_cidr_mask,
        )
        configs.append(config)

        config = ec2.SubnetConfiguration(
            name="data",  # "delta",
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
            cidr_mask=subnet_cidr_mask,
        )
        configs.append(config)

        return configs


class EastWest(SecurityVpcType):
    pass


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

        if permissions_boundary_policy_arn:
            policy = iam.ManagedPolicy.from_managed_policy_arn(
                self, "PermissionsBoundary", permissions_boundary_policy_arn
            )
            iam.PermissionsBoundary.of(self).apply(policy)

        iam_prefix = "TESTNetwork"

        # apply tags to everything in the stack
        app_tags = self.node.try_get_context("Tags") or {}
        for key, value in app_tags.items():
            Tags.of(self).add(key, value)

        cidr_range = self.node.try_get_context("CidrRange") or "10.0.0.0/16"
        max_azs = self.node.try_get_context("MaxAZs") or 2
        subnet_cidr_mask = 27

        vpc_type = SecurityVpcType.for_type_named("NorthSouth", stack=self)
        subnet_configs = vpc_type.subnet_configurations(
            subnet_cidr_mask=subnet_cidr_mask
        )

        self.vpc = ec2.Vpc(
            self,
            "GwlbVpc",
            ip_addresses=ec2.IpAddresses.cidr(cidr_range),
            enable_dns_hostnames=True,
            enable_dns_support=True,
            max_azs=max_azs,
            nat_gateway_provider=ec2.NatProvider.gateway(),
            subnet_configuration=subnet_configs,
        )

        network_interface_config = self.node.try_get_context("NetworkInterfaceConfig")
        network_ssm_param = ssm.StringParameter(
            self,
            "NetworkInterfaceConfig",
            string_value=json.dumps(network_interface_config, indent=2),
        )

        subnet_names = [config.name for config in subnet_configs]
        for subnet_name in subnet_names:
            subnets = (self.vpc.select_subnets(subnet_group_name=subnet_name)).subnets
            for subnet in subnets:
                Tags.of(subnet).add("ROLE", subnet_name)

        # The GWLB endpoints and the firewall instances all reside in the same subnet.
        intra_vpc = ec2.Peer.ipv4(self.vpc.vpc_cidr_block)
        template_sg = ec2.SecurityGroup(self, "GeneveProxySG", vpc=self.vpc)
        geneve_port = 6081
        template_sg.connections.allow_from(
            intra_vpc,
            ec2.Port.tcp(geneve_port),
        )
        # trust all intra-VPC traffic
        template_sg.connections.allow_from(intra_vpc, ec2.Port.all_traffic())
        Tags.of(template_sg).add("ROLE", "data")

        management_sg = ec2.SecurityGroup(self, "ManagementSG", vpc=self.vpc)
        management_sg.connections.allow_from(intra_vpc, ec2.Port.all_traffic())
        Tags.of(management_sg).add("ROLE", "management")

        ami = ec2.MachineImage.latest_amazon_linux(
            generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
        )

        user_data = ec2.UserData.for_linux()

        user_data.add_commands(
            """
yum -y groupinstall "Development Tools"
yum -y install cmake3
yum -y install tc || true
yum -y install iproute-tc || true
cd /root
git clone https://github.com/aws-samples/aws-gateway-load-balancer-tunnel-handler.git
cd aws-gateway-load-balancer-tunnel-handler
cmake3 .
make

cat > /usr/lib/systemd/system/gwlbtun.service <<__EOF__
[Unit]
Description=AWS GWLB Tunnel Handler"

[Service]
ExecStart=/root/aws-gateway-load-balancer-tunnel-handler/gwlbtun -c /root/aws-gateway-load-balancer-tunnel-handler/example-scripts/create-passthrough.sh -p 80"
Restart=always
RestartSec=5s
__EOF__

systemctl daemon-reload
systemctl enable --now --no-block gwlbtun.service
systemctl start gwlbtun.service
echo

"""
        )

        # role for firewall instance
        resource_name = "FirewallInstanceRole"
        instance_role = iam.Role(
            self,
            resource_name,
            role_name=f"{iam_prefix}-{resource_name}-{self.stack_name}",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonS3ReadOnlyAccess"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonSSMManagedInstanceCore"
                ),
                # iam.ManagedPolicy.from_aws_managed_policy_name(
                #     "CloudWatchAgentServerPolicy"
                # ),
            ],
            # inline_policies={
            #     "logretention": iam.PolicyDocument(
            #         assign_sids=True,
            #         statements=[
            #             iam.PolicyStatement(
            #                 actions=[
            #                     "logs:PutRetentionPolicy",
            #                 ],
            #                 effect=iam.Effect.ALLOW,
            #                 resources=["*"],
            #             ),
            #         ],
            #     )
            # },
        )

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
            security_group=management_sg,
            user_data=user_data,
        )

        # settings for all python Lambda functions
        lambda_root = "lambda"
        lambda_principal = iam.ServicePrincipal("lambda.amazonaws.com")

        basic_lambda_policy = iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AWSLambdaVPCAccessExecutionRole"
        )

        resource_name = "LogRetentionRole"
        log_retention_role = iam.Role(
            self,
            resource_name,
            role_name=f"{iam_prefix}-{resource_name}-{self.stack_name}",
            assumed_by=lambda_principal,
            managed_policies=[
                basic_lambda_policy,
            ],
            inline_policies={
                "SetLogRetention": iam.PolicyDocument(
                    assign_sids=True,
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "logs:DeleteRetentionPolicy",
                                "logs:PutRetentionPolicy",
                            ],
                            effect=iam.Effect.ALLOW,
                            resources=["*"],
                        ),
                    ],
                )
            },
        )

        python_runtime = _lambda.Runtime.PYTHON_3_9
        lambda_settings = {
            "log_retention": logs.RetentionDays.ONE_WEEK,
            "log_retention_role": log_retention_role,
            "runtime": python_runtime,
            "timeout": Duration.seconds(60),
        }

        resource_name = "VpceServiceLambdaExecutionRole"
        service_role = iam.Role(
            self,
            resource_name,
            role_name=f"{iam_prefix}-{resource_name}-{self.stack_name}",
            assumed_by=lambda_principal,
            managed_policies=[
                basic_lambda_policy,
            ],
            inline_policies={
                "ec2read": iam.PolicyDocument(
                    assign_sids=True,
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "ec2:DescribeVpcEndpointService*",
                            ],
                            effect=iam.Effect.ALLOW,
                            resources=["*"],  # maybe narrower
                        ),
                    ],
                )
            },
        )

        # the LB uses the subnets that will be used for eth0
        primary_subnets = self.vpc.select_subnets(
            subnet_group_name=network_interface_config["0"]["ROLE"]
        )

        # get the ROLE name for the subnets that will be used for the GWLBEs
        data_subnet_key = next(
            (
                key
                for key in network_interface_config.keys()
                if network_interface_config[key]["IsTarget"]
            ),
            None,
        )
        data_subnet_name = network_interface_config[data_subnet_key]["ROLE"]

        gwlb_subnets = self.vpc.select_subnets(subnet_group_name=data_subnet_name)
        lambda_subnets = self.vpc.select_subnets(subnet_group_name="management")

        gwlb_name = f"NSB-GWLB-{self.stack_name}"
        gwlb = elbv2.CfnLoadBalancer(
            self,
            "GatewayLoadBalancer",
            name=gwlb_name,
            type="gateway",
            subnets=gwlb_subnets.subnet_ids,
            load_balancer_attributes=[
                elbv2.CfnLoadBalancer.LoadBalancerAttributeProperty(
                    key="load_balancing.cross_zone.enabled", value="true"
                )
            ],
        )

        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
        vpce_service_lambda = _lambda.Function(
            self,
            "VpceServiceLambda",
            code=_lambda.Code.from_asset(join(lambda_root, "vpce_service")),
            handler="vpce_service.lambda_handler",
            role=service_role,
            # https://docs.aws.amazon.com/lambda/latest/operatorguide/networking-vpc.html
            log_retention=logs.RetentionDays.ONE_DAY,
            log_retention_role=log_retention_role,
            runtime=python_runtime,
            timeout=Duration.seconds(240),
        )

        gw_endpoint_service = ec2.CfnVPCEndpointService(
            self,
            "VPCEndpointService",
            acceptance_required=False,
            gateway_load_balancer_arns=[gwlb.ref],
        )

        resource_name = "RetrieveVpceServiceName"
        retrieve_vpce_service_name = CustomResource(
            self,
            resource_name,
            resource_type="Custom::RetrieveAttributes",
            service_token=vpce_service_lambda.function_arn,
            properties={
                "FunctionName": iam_prefix + resource_name,
                "VpceServiceId": gw_endpoint_service.ref,
            },
        )

        # create the VPC endpoints

        service_name = retrieve_vpce_service_name.get_att_string("ServiceName")
        vpc_endpoints = {}
        for az in self.vpc.availability_zones:
            vpc_endpoints[az] = ec2.CfnVPCEndpoint(
                self,
                f"VPCE-{az}",
                vpc_id=self.vpc.vpc_id,
                subnet_ids=(
                    self.vpc.select_subnets(
                        subnet_group_name=data_subnet_name, availability_zones=[az]
                    )
                ).subnet_ids,
                vpc_endpoint_type="GatewayLoadBalancer",
                service_name=service_name,
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
            target_type="ip",
            unhealthy_threshold_count=3,
            vpc_id=self.vpc.vpc_id,
        )

        # topic for autoscaling events
        scaling_topic = sns.Topic(self, "AsgScalingEvent")

        notifications_address = self.node.try_get_context("NotificationsEmailAddress")
        if notifications_address:
            scaling_topic.add_subscription(
                subscriptions.EmailSubscription(
                    email_address=notifications_address,
                )
            )

        asg_name = "NSB-gwlb-asg-" + self.stack_name
        asg_arn = (
            f"arn:{self.partition}:autoscaling:{self.region}:"
            + f"{self.account}:autoScalingGroup:*:autoScalingGroupName/{asg_name}"
        )

        asg = autoscaling.CfnAutoScalingGroup(
            self,
            "ASG",
            auto_scaling_group_name=asg_name,
            vpc_zone_identifier=primary_subnets.subnet_ids,
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
                        "GroupDesiredCapacity",
                        "GroupInServiceInstances",
                        "GroupTerminatingInstances",
                        "GroupTotalInstances",
                        "GroupTotalCapacity",
                    ],
                )
            ],
            new_instances_protected_from_scale_in=False,
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

        edge_route_table = ec2.CfnRouteTable(
            self, "EdgeRouteTable", vpc_id=self.vpc.vpc_id
        )
        Tags.of(edge_route_table).add("Name", "EdgeRouteTable")

        for az, vpce in vpc_endpoints.items():

            subnets = (
                self.vpc.select_subnets(
                    subnet_group_name="trusted", availability_zones=[az]
                )
            ).subnets

            for n, subnet in enumerate(subnets):
                # add the outbound route
                subnet.add_route(
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
                    destination_cidr_block=subnet.ipv4_cidr_block,
                )

        # attach the edge route table to the VPC so that return traffic is
        # sent back to the GWLB
        ec2.CfnGatewayRouteTableAssociation(
            self,
            "EdgeRouteTableAssociation",
            route_table_id=edge_route_table.attr_route_table_id,
            gateway_id=self.vpc.internet_gateway_id,
        )

        # lifeycle hook
        # functions
        # custom resource to set the capacity at the right time

        set_desired_instances_sdk_call = cr.AwsSdkCall(
            service="AutoScaling",
            action="updateAutoScalingGroup",
            parameters={
                "AutoScalingGroupName": asg_name,
                "DesiredCapacity": 0,  # max_azs,
            },
            physical_resource_id=cr.PhysicalResourceId.of("PutDesiredInstancesSetting"),
        )

        resource_name = "DesiredInstancesResource"
        asg_update_resource = cr.AwsCustomResource(
            self,
            resource_name,
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

        flowlogs_log_group = logs.LogGroup(
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

        resource_name = "FlowLogRole"

        flow_log_role = iam.Role(
            self,
            resource_name,
            role_name=f"{iam_prefix}-{resource_name}-{self.stack_name}",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
            inline_policies={
                "logs": iam.PolicyDocument(
                    assign_sids=True,
                    statements=[statement],
                ),
            },
        )

        # Create flow logs on the data subnets.
        for n, subnet in enumerate(gwlb_subnets.subnets):
            ec2.FlowLog(
                self,
                f"VpcFlowLog{n}",
                resource_type=ec2.FlowLogResourceType.from_subnet(subnet),
                destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                    flowlogs_log_group, flow_log_role
                ),
                traffic_type=ec2.FlowLogTrafficType.ALL,
                max_aggregation_interval=ec2.FlowLogMaxAggregationInterval.ONE_MINUTE,
            )

        resource_name = "LifecycleHookRole"
        managed_policies = [basic_lambda_policy]
        lifecycle_hook_role = iam.Role(
            self,
            resource_name,
            role_name=f"{iam_prefix}-{resource_name}-{self.stack_name}",
            assumed_by=lambda_principal,
            managed_policies=managed_policies,
            inline_policies={
                "LaunchHookPolicies": iam.PolicyDocument(
                    assign_sids=True,
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["autoscaling:CompleteLifecycleAction"],
                            resources=[asg_arn],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "elasticloadbalancing:RegisterTargets",
                                "elasticloadbalancing:DeregisterTargets",
                            ],
                            resources=[target_group.ref],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "ec2:Describe*",
                                "ec2:ModifyNetworkInterface*",
                                "ec2:AttachNetworkInterface*",
                                "ec2:CreateTags",
                            ],
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["ec2:CreateTags"],
                            resources=[acct_instances_arn],
                        ),
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["states:StartExecution"],
                            resources=["*"],  #   narrower
                        ),
                    ],
                )
            },
        )
        network_ssm_param.grant_read(lifecycle_hook_role)

        # Make sure the launching rule and lambda are created before the ASG.
        # Bad things can happen if the ASG starts spinning up instances before the
        # lifecycle hook lambdas and rules are deployed

        # Build the state machine

        add_interfaces_lambda = _lambda.Function(
            self,
            "AddInterfaces",
            code=_lambda.Code.from_asset(join(lambda_root, "add_interfaces")),
            handler="add_interfaces.lambda_handler",
            role=lifecycle_hook_role,
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=lambda_subnets.subnets),
            environment={
                "NETWORK_CONFIGURATION_SSM_PARAM": network_ssm_param.parameter_name,
                "TARGET_GROUP_ARN": target_group.ref,
            },
            **lambda_settings,
        )

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_stepfunctions/Choice.html
        start_state = sfn.Pass(self, "StartState")

        add_interfaces_task = sfn_tasks.LambdaInvoke(
            self,
            "AddInterfacesTask",
            lambda_function=add_interfaces_lambda,
            # result_path="$.result"
        )
        start_state.next(add_interfaces_task)

        # add API task for complete_hook
        # add choice task for success/failure

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_stepfunctions_tasks/CallAwsService.html
        # https://pypi.org/project/aws-cdk.aws-stepfunctions-tasks/#aws-sdk
        continue_instance_task = sfn_tasks.CallAwsService(
            self,
            "ContinueInstance",
            service="autoscaling",
            action="completeLifecycleAction",
            iam_resources=[asg_arn],
            parameters={
                "LifecycleActionResult": "CONTINUE",
                "InstanceId": sfn.JsonPath.string_at("$.Payload.EC2InstanceId"),
                **{
                    param: sfn.JsonPath.string_at(f"$.Payload.{param}")
                    for param in [
                        "LifecycleActionToken",
                        "LifecycleHookName",
                        "AutoScalingGroupName",
                    ]
                },
            },
        )

        abandon_instance_task = sfn_tasks.CallAwsService(
            self,
            "AbandonInstance",
            service="autoscaling",
            action="completeLifecycleAction",
            iam_resources=[asg_arn],
            parameters={
                "LifecycleActionResult": "ABANDON",
                "InstanceId": sfn.JsonPath.string_at("$.Payload.EC2InstanceId"),
                **{
                    param: sfn.JsonPath.string_at(f"$.Payload.{param}")
                    for param in [
                        "LifecycleActionToken",
                        "LifecycleHookName",
                        "AutoScalingGroupName",
                    ]
                },
            },
        )

        choice = sfn.Choice(self, "AddedInterfaces?")
        choice.when(
            sfn.Condition.string_equals(
                sfn.JsonPath.string_at("$.Payload.status"), "FAILED"
            ),
            abandon_instance_task,
        )
        choice.when(
            sfn.Condition.string_equals(
                sfn.JsonPath.string_at("$.Payload.status"), "SUCCEEDED"
            ),
            continue_instance_task,
        )

        add_interfaces_task.next(choice)

        wait = sfn.Wait(self, "Wait", time=sfn.WaitTime.duration(Duration.minutes(1)))

        continue_instance_task.next(wait.next(sfn.Pass(self, "SucceededState")))
        abandon_instance_task.next(sfn.Fail(self, "FailedState"))

        # register ENI with target group toward the end

        state_machine = sfn.StateMachine(
            self, "StateMachine", definition=start_state, timeout=Duration.hours(1)
        )

        # Now set up the lifecycle hooks for launching and terminating events.

        launching_rule = self.add_lifecycle_hook(
            construct_id="Launching",
            asg=asg,
            asg_name=asg_name,
            asg_arn=asg_arn,
            lifecycle_hook_role=lifecycle_hook_role,
            lambda_code=_lambda.Code.from_asset(join(lambda_root, "launching_hook")),
            lambda_settings=lambda_settings,
            lambda_handler="launching_hook.lambda_handler",
            lambda_env={
                "TARGET_GROUP_ARN": target_group.ref,
                "NETWORK_CONFIGURATION_SSM_PARAM": network_ssm_param.parameter_name,
                "STATE_MACHINE_ARN": state_machine.state_machine_arn,
            },
            vpc_subnets=ec2.SubnetSelection(subnets=lambda_subnets.subnets),
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
            lambda_env={"TARGET_GROUP_ARN": target_group.ref},
            vpc_subnets=ec2.SubnetSelection(subnets=lambda_subnets.subnets),
            lifecycle_transition="autoscaling:EC2_INSTANCE_TERMINATING",
            default_result="CONTINUE",
        )
        asg.node.add_dependency(terminating_rule)
        asg_update_resource.node.add_dependency(terminating_rule)

        # set desired_instances AFTER the ASG, hook, lambda, and rule are all deployed.
        asg_update_resource.node.add_dependency(asg)

        # install logs agent
        # metrics, dashboard

        launch_test_instance_param = self.node.try_get_context("LaunchTestInstance")

        if launch_test_instance_param:

            resource_name = "TestInstanceRole"
            instance_role = iam.Role(
                self,
                resource_name,
                role_name=f"{iam_prefix}-{resource_name}-{self.stack_name}",
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

            self.launch_test_instance(
                role=instance_role,
                vpc_subnets=ec2.SubnetSelection(subnet_group_name="trusted"),
            )

        # add VPC endpoints for ec2, ssm, secretsmanager, autoscaling, elbv2

        service_names = [
            "ec2",
            "ssm",
            "ssmmessages",
            "ec2messages",
            "secretsmanager",
            "autoscaling",
            "elasticloadbalancing",
            "states",
            "logs",
            # "cloudwatch"
            # "lambda"?
        ]
        subnets = (self.vpc.select_subnets(subnet_group_name="management")).subnets
        for name in service_names:
            endpoint = self.vpc.add_interface_endpoint(
                f"{name}Endpoint",
                service=ec2.InterfaceVpcEndpointAwsService(name),
                subnets=ec2.SubnetSelection(subnets=subnets),
            )
            Tags.of(endpoint).add("Name", f"{name}-{self.stack_name}")

    def add_lifecycle_hook(
        self,
        construct_id=None,
        asg=None,
        asg_name=None,
        asg_arn=None,
        lifecycle_hook_role=None,
        lambda_code=None,
        lambda_settings={},
        lambda_env={},
        lambda_handler=None,
        vpc_subnets=None,
        lifecycle_transition=None,
        default_result=None,
    ):

        hook_lambda = _lambda.Function(
            self,
            construct_id + "HookLambda",
            code=lambda_code,
            handler=lambda_handler,
            role=lifecycle_hook_role,
            environment=lambda_env,
            vpc=self.vpc,
            vpc_subnets=vpc_subnets,
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

        iam_prefix = "Network"
        resource_name = construct_id + "HookCustomResource"
        hook_resource = cr.AwsCustomResource(
            self,
            resource_name,
            # function_name=iam_prefix+resource_name,
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

    def launch_test_instance(self, vpc_subnets=None, role=None, key_name=None):

        optional_params = {}
        if key_name:
            optional_params["key_name"] = key_name

        test_instance = ec2.Instance(
            self,
            "TestInstance",
            vpc=self.vpc,
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
            role=role,
            **optional_params,
        )

        return test_instance

    def flow_log_for_subnets(
        self, contruct_name="", subnets=[], log_group=None, flow_log_role=None
    ):

        # https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-log-records
        for n, subnet in enumerate(subnets):
            ec2.FlowLog(
                self,
                f"{contruct_name}{n}",
                resource_type=ec2.FlowLogResourceType.from_subnet(subnet),
                destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                    log_group, flow_log_role
                ),
                traffic_type=ec2.FlowLogTrafficType.ALL,
                max_aggregation_interval=ec2.FlowLogMaxAggregationInterval.ONE_MINUTE,
                # log_format
            )
