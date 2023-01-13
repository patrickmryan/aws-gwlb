#!/usr/bin/env python3
import os

import aws_cdk as cdk

from cisco_secure_gwlb.cisco_secure_gwlb_stack import CiscoSecureGwlbStack


app = cdk.App()
CiscoSecureGwlbStack(
    app,
    "CiscoSecureGwlbStack",
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"), region=os.getenv("CDK_DEFAULT_REGION")
    ),
)

app.synth()
