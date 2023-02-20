import sys
import json
import urllib3
from urllib3.util import Timeout
from urllib3.exceptions import RequestError, HTTPError


def lambda_handler(event, context):

    print(json.dumps(event))

    target_ip = event["target_ip"]

    http_client = urllib3.PoolManager(
        # timeout=Timeout(total=15)
        # let the lambda timeout if the target is unresponsive
        timeout=Timeout(total=(context.get_remaining_time_in_millis() * 1000) + 10),
        retries=None,
    )
    health_check_url = f"http://{target_ip}:80/"

    unhealthy = {"status": "UNHEALTHY"}

    print("attempting to connect to health check URL " + health_check_url)

    try:
        response = http_client.request(
            "GET",
            health_check_url,
            timeout=Timeout(total=(context.get_remaining_time_in_millis() * 1000) + 10),
            retries=None,
        )

    except HTTPError as exc:
        print(f"failed to connect: {exc}")
        # raise ValueError(unhealthy)
        return unhealthy

    if not response:
        # raise ValueError(unhealthy)
        return unhealthy

    # print(response.data.decode())
    status_code = response.status

    if status_code == 200:
        return {"status": "HEALTHY"}

    # return unhealthy
    raise ValueError(unhealthy)


if __name__ == "__main__":
    import pdb

    event = {"target_ip": sys.argv[1]}

    response = lambda_handler(event=event, context={})
    print(response)
