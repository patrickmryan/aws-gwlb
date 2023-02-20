import sys
import json
import urllib3
import time
from urllib3.util import Timeout
from urllib3.exceptions import HTTPError


def lambda_handler(event, context):

    print(json.dumps(event))

    target_ip = event["target_ip"]

    http_client = urllib3.PoolManager(
        timeout=Timeout(total=15),
    )
    health_check_url = f"http://{target_ip}:80/"

    while True:
        # keep trying.  let the lambda timeout if the target is unresponsive
        print("attempting to connect to health check URL " + health_check_url)

        wait_and_try_again = False
        response = None

        try:
            response = http_client.request(
                "GET",
                health_check_url,
                timeout=Timeout(
                    total=(context.get_remaining_time_in_millis() * 1000) + 10
                ),
                retries=None,
            )

        except HTTPError as exc:
            print(f"failed to connect: {exc}")
            wait_and_try_again = True

        if not response:
            wait_and_try_again = True

        if wait_and_try_again:
            time.sleep(5)
            continue

        status_code = response.status

        if status_code == 200:
            return {"status": "HEALTHY"}
        # do something if the status code != 200


if __name__ == "__main__":
    import pdb

    event = {"target_ip": sys.argv[1]}

    response = lambda_handler(event=event, context={})
    print(response)
