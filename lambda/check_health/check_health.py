import sys
import json
import urllib3
from urllib3.util import Timeout
import ssl


def lambda_handler(event, context):

    print(json.dumps(event))

    target_ip = event["target_ip"]

    http_client = urllib3.PoolManager(
        cert_reqs=ssl.CERT_NONE, timeout=Timeout(total=15)
    )
    health_check_url = f"http://{target_ip}:80/"

    unhealthy = {"status": "unhealthy"}

    print("attempting to connect to health check URL " + health_check_url)
    response = http_client.request("GET", health_check_url)

    if not response:
        return unhealthy

    print(response)
    status_code = response.status

    if status_code == 200:
        return {"status": "healthy"}

    return unhealthy


if __name__ == "__main__":
    import pdb

    event = {"target_ip": sys.argv[1]}

    response = lambda_handler(event=event, context={})
    print(response)
