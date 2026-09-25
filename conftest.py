import json
import typing as t
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import responses
from _pytest.doctest import DoctestItem

from inlyse import WebClient

TEST_TOKEN = "test"
TEST_URL = "http://inlyse.test"
DOCTEST_FILES = [
    Path("/tmp/dairycow_vacalechera.pdf"),
    Path("/tmp/javascript.pdf"),
]


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


@pytest.fixture()
def disarm_response():
    with open("tests/responses/disarmed.pdf", mode="rb") as f:
        return f.read()


@pytest.fixture()
def version_response():
    with open("tests/responses/version.json") as f:
        return f.read().strip()


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


@pytest.fixture(autouse=True)
def add_doctest_fixtures(
    request: pytest.FixtureRequest,
    doctest_namespace: dict[str, t.Any],
) -> None:
    """Configure doctest fixtures for pytest-doctest."""

    def _teardown():
        responses.stop()
        responses.reset()

    if isinstance(request.node, DoctestItem):
        responses.start()
        request.addfinalizer(_teardown)

        for path in DOCTEST_FILES:
            if not path.parent.exists():
                path.parent.mkdir(parents=True)
            path.open("xb").close()
            request.addfinalizer(path.unlink)

        rate_limit = request.getfixturevalue("rate_limit")
        rate_limit["headers"]["X-Ratelimit-Reset"] = datetime(
            2023, 3, 28, 18, 57, 15, tzinfo=timezone.utc
        ).strftime("%d-%m-%Y %H:%M:%S")
        api = "https://malware.ai{endpoint}"
        responses.get(
            api.format(endpoint="/ping"),
            json=request.getfixturevalue("ping_response"),
            content_type="application/json; charset=UTF-8",
            status=200,
        )
        responses.get(
            api.format(endpoint="/version"),
            json=request.getfixturevalue("version_response"),
            content_type="application/json; charset=UTF-8",
            status=200,
        )
        responses.get(
            api.format(endpoint="/api/stats"),
            json=request.getfixturevalue("stats_response"),
            content_type="application/json; charset=UTF-8",
            status=200,
            headers=rate_limit["headers"],
        )
        responses.post(
            api.format(endpoint="/api/files/url"),
            json=request.getfixturevalue("upload_url_response"),
            content_type="application/json; charset=UTF-8",
            status=200,
            headers=rate_limit["headers"],
        )
        responses.post(
            api.format(endpoint="/api/files/owa"),
            json=request.getfixturevalue("upload_owa_response"),
            content_type="application/json; charset=UTF-8",
            status=200,
            headers=rate_limit["headers"],
        )
        responses.post(
            api.format(endpoint="/api/files/"),
            json=request.getfixturevalue("upload_file_response"),
            content_type="application/json; charset=UTF-8",
            status=200,
            headers=rate_limit["headers"],
        )
        responses.post(
            api.format(endpoint="/api/files/disarm"),
            body=request.getfixturevalue("disarm_response"),
            content_type="application/pdf",
            status=200,
            headers=rate_limit["headers"],
        )
        responses.get(
            api.format(
                endpoint="/api/analysis/8f238204-8540-4424-9872-822c46e39c05/disarm"
            ),
            body=request.getfixturevalue("disarm_response"),
            content_type="application/pdf",
            status=200,
            headers=rate_limit["headers"],
        )
        responses.get(
            api.format(
                endpoint="/api/analysis/8f238204-8540-4424-9872-822c46e39c05"
            ),
            json=request.getfixturevalue("check_response"),
            content_type="application/json; charset=UTF-8",
            status=200,
            headers=rate_limit["headers"],
        )
        responses.get(
            api.format(
                endpoint="/api/analysis/1ee54150-1df8-4a74-b8c9-cf12c0647339"
            ),
            json=request.getfixturevalue("check_response"),
            content_type="application/json; charset=UTF-8",
            status=200,
            headers=rate_limit["headers"],
        )
        responses.get(
            api.format(endpoint="/api/analysis"),
            json=request.getfixturevalue("list_response"),
            content_type="application/json; charset=UTF-8",
            status=200,
            headers=rate_limit["headers"],
        )
        responses.get(
            api.format(
                endpoint="/api/analysis/1e65cd90-3fe8-4da8-a4a5-4b63e6ed6133/download"
            ),
            body=request.getfixturevalue("download_response"),
            content_type="application/pdf",
            status=200,
            headers=rate_limit["headers"],
        )
