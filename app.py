import os
import aws_cdk as cdk
from gwlb.gwlb_stack import GwlbStack


app = cdk.App()
GwlbStack(
    app,
    "AwsGwlbStack",
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"), region=os.getenv("CDK_DEFAULT_REGION")
    ),
)

app.synth()
