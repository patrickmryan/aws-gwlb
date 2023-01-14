import json
import sys
import re

# AvailabilityZone	us-east-1b	-
# DiagInterfaceSecurityGroups	sg-002c827d160d93ed7	-
# InterfaceVpcId	vpc-0a6a6362f2e8cb36d	-
# ManagementSubnetId	subnet-0640667ae41ebd3c5	-
# MgmtInterfaceSecurityGroups	sg-0675b1867089ea472	-
# TrustedInterfaceSecurityGroups	sg-0c74160497a5ed018	-
# TrustedSubnetId	subnet-0390c250c02248967	-
# UntrustedInterfaceSecurityGroups	sg-0c74160497a5ed018	-
# UntrustedSubnetId	subnet-0c4f67e3ef17ff2ca	-

params = {}
prog = re.compile(r"(\S+)\t(.+)\t-")

for line in sys.stdin:
    text = line.strip()
    result = prog.match(text)
    if not result:
        print(f'could not parse "{text}"')
        sys.exit(1)

    params[result.group(1)] = result.group(2)

output = [
    {"ParameterKey": key, "ParameterValue": value} for key, value in params.items()
]

print(json.dumps(output, indent=1))
