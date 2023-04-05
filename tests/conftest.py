import json
from datetime import datetime, timedelta, timezone

import pytest

from inlyse import WebClient

TEST_TOKEN = "test"
TEST_URL = "http://inlyse.test"


@pytest.fixture()
def ping_response():
    with open("tests/responses/ping.json") as f:
        return f.read().strip()


@pytest.fixture()
def list_response():
    with open("tests/responses/list.json") as f:
        return json.load(f)


@pytest.fixture()
def stats_response():
    with open("tests/responses/stats.json") as f:
        return json.load(f)


@pytest.fixture()
def download_response():
    with open("tests/responses/download.bin", "rb") as f:
        return f.read()


@pytest.fixture()
def upload_file_response():
    with open("tests/responses/upload_file.json") as f:
        return json.load(f)


@pytest.fixture()
def upload_url_response():
    with open("tests/responses/upload_link.json") as f:
        return json.load(f)


@pytest.fixture()
def upload_owa_response():
    with open("tests/responses/upload_owa.json") as f:
        return json.load(f)


@pytest.fixture()
def check_response():
    with open("tests/responses/analysis.json") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def api():
    return TEST_URL + "{endpoint}"


@pytest.fixture(scope="module")
def client():
    yield WebClient(TEST_TOKEN, url=TEST_URL)


@pytest.fixture(scope="module")
def rate_limit():
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    reset = now + timedelta(minutes=10)
    return {
        "headers": {
            "X-Ratelimit-Limit": "100",
            "X-Ratelimit-Remaining": "99",
            "X-Ratelimit-Reset": reset.strftime("%d-%m-%Y %H:%M:%S"),
        },
        "expected_reset": reset,
        "expected_remaining": "99",
    }
