import sys
import json
import urllib3
from urllib3.util import Timeout
from urllib3.exceptions import RequestError, HTTPError


def lambda_handler(event, context):

    print(json.dumps(event))

    target_ip = event["target_ip"]

    http_client = urllib3.PoolManager(timeout=Timeout(total=15))
    health_check_url = f"http://{target_ip}:80/"

    unhealthy = {"status": "UNHEALTHY"}

    print("attempting to connect to health check URL " + health_check_url)

    try:
        response = http_client.request("GET", health_check_url)

    except HTTPError as exc:
        print(f"failed to connect: {exc}")
        return unhealthy

    if not response:
        return unhealthy

    # print(response.data.decode())
    status_code = response.status

    if status_code == 200:
        return {"status": "HEALTHY"}

    return unhealthy


if __name__ == "__main__":
    import pdb

    event = {"target_ip": sys.argv[1]}

    response = lambda_handler(event=event, context={})
    print(response)
