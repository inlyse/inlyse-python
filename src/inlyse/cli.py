"""The module bundles all available clients for the INLYSE API.
"""

# Standard Library
import functools
import logging
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Union

# Third Party Libraries
from requests.adapters import HTTPAdapter, Retry
from requests.compat import urljoin
from requests.utils import _parse_content_type_header  # type: ignore
from requests_toolbelt import sessions

from inlyse.exceptions import (  # noqa
    InlyseApiError,
    MaxRetriesExceeded,
    RateLimitExceeded,
)

logger = logging.getLogger(__name__)  # Init logger


class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.get("timeout", 5)
        del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


@dataclass
class InlyseResponse:
    """A response of the INLYSE API

    :param endpoint: The API endpoint
    :type endpoint: str
    :param status: The HTTP status code of the response
    :type status: int
    :param rate_limit: The rate limit status. Which includes
                       the time for the next renewal and the
                       remaining number of requests.
    :type rate_limit: dict or None
    :param content_type: The MIME type of the content. In example: `application/json`.
    :type content_type: tuple
    :param content: The content of the response.
    :type content: Any
    """

    endpoint: str
    status: int
    rate_limit: Union[None, dict]
    content_type: tuple
    content: Any


def endpoint(path=None):
    def endpoint_decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            self = args[0]
            if path:
                kwargs["path"] = path
            response = func(*args, **kwargs)
            quota = None
            if "x-ratelimit-remaining" in response.headers:
                quota = {
                    "limit": int(response.headers["x-ratelimit-limit"]),
                    "remaining": int(
                        response.headers["x-ratelimit-remaining"]
                    ),
                    "reset": datetime.strptime(
                        response.headers["x-ratelimit-reset"],
                        "%d-%m-%Y %H:%M:%S",
                    ).replace(tzinfo=timezone.utc),
                }
            content_type = _parse_content_type_header(
                response.headers["content-type"]
            )
            if content_type[0] == "application/json":
                content = response.json()
            else:
                content = response.content
            return InlyseResponse(
                urljoin(self.url, path),
                response.status_code,
                quota,
                content_type,
                content,
            )

        return wrapper

    return endpoint_decorator


class WebClient:
    """INLYSE API web client

    :param license_key: A license key for the INLYSE API
    :type license_key: str
    :param url: (optional) The URL of the INLYSE API. (Default: https://malware.ai)
    :type url: str
    :param timeout: (optional) How long to wait for the server to send
        data before giving up, as a float, or a :ref:`(connect timeout,
        read timeout) <timeouts>` tuple. The excat same behavior like for
        python requests. (Default: (5, 60))
    :type timeout: float or tuple

    **Example**:

    .. sourcecode:: pycon

        >>> from inlyse import WebClient
        >>> with WebClient("<your license key>") as client:
        ...    client.ping()

    It is also possible to use the raw API GET or POST requests like this:

    .. sourcecode:: pycon

        >>> from inlyse import WebClient
        >>> with WebClient("<your license key>") as client:
        ...    client.api.get("/ping")
        ...    response = client.api.get("/api/stats")
        ...    print(response.status_code)
        ...    print(response.json())
        200
        {'AnalysedFiles': 293, 'Traffic': 266161837}

    These methods will return a :class:`requests.Response` object.
    """

    def __init__(
        self,
        license_key: str,
        url: str = "https://malware.ai",
        timeout: Union[float, tuple] = (5, 60),
    ) -> None:
        self.url = url
        self.license_key = license_key
        self.timeout = timeout
        self._api: Union[None, sessions.BaseUrlSession] = None
        self.api: sessions.BaseUrlSession

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    @property
    def api(self) -> sessions.BaseUrlSession:
        if not isinstance(self._api, sessions.BaseUrlSession):
            session = sessions.BaseUrlSession(base_url=self.url)
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 503],
                allowed_methods=["GET"],
                raise_on_status=False,
            )
            adapter = TimeoutHTTPAdapter(
                timeout=self.timeout, max_retries=retry_strategy
            )
            session.headers = {"Authorization": f"Bearer {self.license_key}"}
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._api = session
        return self._api

    @api.setter
    def api(self, value) -> None:
        if value is None:
            self.close()

    def _wait(
        self,
        attempt: int,
        avg_time: float = 0.0,
        cap: int = 40,
        base: float = 0.1,
    ) -> float:
        """Internal wait method till an analysis is ready.

        :param attempt: The current number of attempts
        :type attempt: int
        :param avg_time: (optional) The average waiting time. (Default: 0.0)
        :type avg_time: float
        :param cap: (optional) The maximum backoff time in seconds. (Default: 40)
        :type cap: int
        :param base: (optional) The base backoff time in seconds. (Default: 0.1)
        :type base: float

        :return: The sleeping time.
        :rtype: float
        """
        if attempt == 0:
            logger.debug("Waiting the average response time: %s", avg_time)
            time.sleep(avg_time)
        logger.debug(f"retries: {attempt}")
        back_offtime = random.uniform(0, min(cap, base * 2**attempt))
        logger.debug(f"sleeping for {back_offtime} seconds")
        time.sleep(back_offtime)
        return back_offtime

    @endpoint("/version")
    def version(self, *, path: str) -> InlyseResponse:
        """version()
        Get the version of the API

        * **API endpoint**: `/version`
        * **HTTP Method**: `GET`
        * **Response CONTENT-TYPE**: `application/json`

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              - If the version request was `successful` it returns the HTTP status code `200`
                and the current version.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.version()
            >>> response
            InlyseResponse(
                endpoint='/version',
                status=200,
                rate_limit=None,
                content_type=('application/json', {'charset': 'UTF-8'}),
                content='1.7.4'
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """
        return self.api.get(path)

    @endpoint("/ping")
    def ping(self, *, path: str) -> InlyseResponse:
        """ping()
        Ping the INLYSE API

        * **API endpoint**: `/ping`
        * **HTTP Method**: `GET`
        * **Response CONTENT-TYPE**: `application/json`

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              - If the ping request was `successful` it returns the HTTP status code `200`
                and the string `Pong`.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.ping()
            >>> response
            InlyseResponse(
                endpoint='/ping',
                status=200,
                rate_limit=None,
                content_type=('application/json', {'charset': 'UTF-8'}),
                content='Pong'
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """
        return self.api.get(path)

    @endpoint("/api/stats")
    def stats(self, *, path: str) -> InlyseResponse:
        """stats()
        Get the statistics of the used license key. It shows you how many files
        you have analysed and the traffic in Bytes.

        * **API endpoint**: `/api/stats`
        * **HTTP Method**: `GET`
        * **Response CONTENT-TYPE**: `application/json`

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              - If the request was *successful* it returns the HTTP status code `200`
                and a dictionary with the number of analyzed files and the produced
                trafficfor the configured license key.
            * - 401 - Unauthorized
              - If the request was not authorized. In example if the license key is
                not valid anymore.
            * - 429 - Too Many Requests
              - If the quota is exceed, it returns the HTTP status 429.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.stats()
            >>> response
            InlyseResponse(
                endpoint='/api/stats'
                status=200,
                rate_limit={
                    'remaining': '14993',
                    'reset': datetime.datetime(
                        2023, 3, 20, 19, 45, 38, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/json', {'charset': 'UTF-8'}),
                content={'AnalysedFiles': 201, 'Traffic': 205581688}
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """
        return self.api.get(path)

    def download_link(self, analysis_id: str) -> str:
        """Create a download link for a previous analysis.

        :param analysis_id: The UUID of an analysis.
        :type analysis_id: str

        .. warning::
            The UUID of the analysis gets not validated.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> link = client.download_link("0ef3822b-481d-4368-88ea-6a2417bb2dac")
            >>> link
            'https://malware.ai/api/analysis/0ef3822b-481d-4368-88ea-6a2417bb2dac/download'
            >>> client.close()

        :return: Returns a download link for the file of the specified analysis.
        :rtype: str
        """
        return urljoin(self.url, f"/api/analysis/{analysis_id}/download")

    @endpoint("/api/analysis/{id}/download")
    def download(self, analysis_id: str, *, path: str) -> InlyseResponse:
        """download(analysis_id)
        Download a file of a previous analysis.

        :param analysis_id: The UUID of an analysis.
        :type analysis_id: str

        .. warning::
            Maybe the file has been already deleted. The file gets deleted
            after 30 seconds when the analysis has been completed. INLYSE
            saves only the analysis result permanently.

        * **API endpoint**: `/api/analysis/<id>/download`
        * **HTTP Method**: `GET`
        * **Response CONTENT-TYPE**: `application/pdf`, `application/msexcel`, ..

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              - If the request was *successful*, it returns the HTTP status code `200`
                and the requested file.
            * - 404 - Not Found
              - If the analysis with the given UUID does not exist or the corresponding
                file of the analysis has already been deleted the API returns the status
                code 404 and a short explaination about the error.
            * - 401 - Unauthorized
              - If the request was not authorized. In example if the license key is
                not valid anymore.
            * - 429 - Too Many Requests
              - If the quota is exceed, it returns the HTTP status 429.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> download = client.download("0ef3822b-481d-4368-88ea-6a2417bb2dac")
            >>> download
            InlyseResponse(
                endpoint='/api/analysis/0ef3822b-481d-4368-88ea-6a2417bb2dac/download'
                status=200,
                rate_limit={
                    'remaining': '14980',
                    'reset': datetime.datetime(
                        2023, 3, 20, 19, 45, 38, tzinfo=datetime.timezone.utc
                        )
                    },
                content_type=('application/pdf', {}),
                conent=b'%PDF-1.4...%%EOF'
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """  # noqa: E501
        return self.api.get(path.format(id=analysis_id))

    @endpoint("/api/analysis/{id}/disarm")
    def disarm_analysis(
        self, analysis_id: str, *, path: str
    ) -> InlyseResponse:
        """disarm_analysis(analysis_id)
        Disarm a file of a previous analysis.

        :param analysis_id: The UUID of an analysis.
        :type analysis_id: str

        .. warning::
            Maybe the file has been already deleted. The file gets deleted
            after 30 seconds when the analysis has been completed. INLYSE
            saves only the analysis result permanently.

        * **API endpoint**: `/api/analysis/<id>/disarm`
        * **HTTP Method**: `GET`
        * **Response CONTENT-TYPE**: `application/pdf`

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              - If the request was *successful*, it returns the HTTP status code `200`
                and the disarmed PDF document. Microsoft Office documents get converted
                into PDF documents.
            * - 404 - Not Found
              - If the analysis with the given UUID does not exist or the corresponding
                file of the analysis has already been deleted the API returns the status
                code 404 and a short explaination about the error.
            * - 401 - Unauthorized
              - If the request was not authorized. In example if the license key is
                not valid anymore.
            * - 429 - Too Many Requests
              - If the quota is exceed, it returns the HTTP status 429.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.disarm_analysis("0ef3822b-481d-4368-88ea-6a2417bb2dac")
            >>> response
            InlyseResponse(
                endpoint='/api/analysis/0ef3822b-481d-4368-88ea-6a2417bb2dac/disarm',
                status=200,
                rate_limit={
                    'remaining': '14999',
                    'reset': datetime.datetime(
                        2023, 3, 21, 19, 44, 12, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/pdf', {}),
                content=b'%PDF-1.7...%%EOF'
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """  # noqa: E501
        return self.api.get(path.format(id=analysis_id))

    @endpoint("/api/files/")
    def upload_file(
        self, filename: str, content: bytes, *, path: str
    ) -> InlyseResponse:
        """upload(filename, content)
        Upload a local file.

        :param filename: The name of the file.
        :type filename: str
        :param content: The content of the file.
        :type content: bytes

        * **API endpoint**: `/api/files/`
        * **HTTP Method**: `POST`
        * **Response CONTENT-TYPE**: `application/json`

        **Allowed file types**:
        * Microsoft Office documents
        * PDF documents
        * ZIP files with exactly `1` Microsoft Office document or PDF document

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              - If the request was successful, it returns the HTTP status code 200,
                the UUID of the analysis and an estimated time till the analysis is
                ready.
            * - 401 - Unauthorized
              - If the request was not authorized. In example if the license key is
                not valid anymore.
            * - 429 - Too Many Requests
              - If the quota is exceed, it returns the HTTP status 429.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> with open("/tmp/javascript.pdf", "rb") as fp:
            ...     response = client.upload_file(os.path.basename(fp.name), fp.read())
            >>> response
            InlyseResponse(
                endpoint='/api/files/'
                status=200,
                rate_limit={
                    'remaining': '14977',
                    'reset': datetime.datetime(
                        2023, 3, 20, 19, 45, 38, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/json', {'charset': 'UTF-8'}),
                content={
                    'id': '4e1ae479-583b-4d52-a080-88adf6502364',
                    'EstimatedAnalysisTime': 5.83675
                }
            )
            >>> client.close()


        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """
        return self.api.post(path, files={"file": (filename, content)})

    @endpoint("/api/files/url")
    def upload_url(self, url: str, *, path: str) -> InlyseResponse:
        """upload_url(url)
        Upload a remote file. At the moment we only support http URLs.

        :param url: The download URL of the file.
        :type url: str

        .. warning::
            The URL needs to be public. It's not possible to send URLs which need authentication.

        * **API endpoint**: `/api/files/url`
        * **HTTP Method**: `POST`
        * **Response CONTENT-TYPE**: `application/json`

        **Allowed file types**:
        * Microsoft Office documents
        * PDF documents
        * ZIP files with exactly `1` Microsoft Office document or PDF document

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              -  If the request was successful, it returns the HTTP status code 200,
                 the UUID of the analysis and an estimated time till the analysis is
                 ready.
            * - 401 - Unauthorized
              - If the request was not authorized. In example if the license key is
                not valid anymore.
            * - 429 - Too Many Requests
              - If the quota is exceed, it returns the HTTP status 429.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.upload_url("https://arxiv.org/pdf/2004.14471.pdf")
            >>> response
            InlyseResponse(
                endpoint='/api/files/url'
                status=200,
                rate_limit={
                    'remaining': '14988',
                    'reset': datetime.datetime(
                        2023, 3, 20, 20, 47, 35, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/json', {'charset': 'UTF-8'}),
                content={
                    'id': '1a13ba09-8487-4621-b2a3-b0ff460f7a9e',
                    'EstimatedAnalysisTime': 5.83675
                }
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """
        return self.api.post(path, json={"url": url})

    @endpoint("/api/files/owa")
    def upload_owa(self, url: str, token: str, *, path: str) -> InlyseResponse:
        """upload_owa(url, token)
        Upload an outlook attachment.

        :param url: The download URL of the file.
        :type url: str
        :param token: The token
        :type token: str

        * **API endpoint**: `/api/files/owa`
        * **HTTP Method**: `POST`
        * **Response CONTENT-TYPE**: `application/json`

        **Allowed file types**:
        * Microsoft Office documents
        * PDF documents
        * ZIP files with exactly `1` Microsoft Office document or PDF document

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              -  If the request was successful, it returns the HTTP status code 200,
                 the UUID of the analysis and an estimated time till the analysis is
                 ready.
            * - 401 - Unauthorized
              - If the request was not authorized. In example if the license key is
                not valid anymore.
            * - 429 - Too Many Requests
              - If the quota is exceed, it returns the HTTP status 429.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.upload_owa(
            ... "https://attachments.office.net/owa/Max.Mustermann%40test.com/...",
            ... "iMWFWf1EZh8WM27tqXFlIa1QoNDfmjaZT0Xz7IyaDASBCUamUKcMKUSTVYJTOUm5...")
            >>> response
            InlyseResponse(
                endpoint='/api/files/owa',
                status=200,
                rate_limit={
                    'remaining': '14988',
                    'reset': datetime.datetime(
                        2023, 3, 20, 20, 47, 35, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/json', {'charset': 'UTF-8'}),
                content={
                    'id': '1a13ba09-8487-4621-b2a3-b0ff460f7a9e',
                    'EstimatedAnalysisTime': 5.83675
                }
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """
        return self.api.post(path, json={"url": url, "token": token})

    @endpoint("/api/files/disarm")
    def disarm_file(
        self, filename: str, content: bytes, *, path: str
    ) -> InlyseResponse:
        """disarm_file(filename, content)
        Disarm a local file.

        :param filename: The name of the file.
        :type filename: str
        :param content: The content of the file.
        :type content: bytes

        * **API endpoint**: `/api/files/disarm`
        * **HTTP Method**: `POST`
        * **Response CONTENT-TYPE**: `application/json`

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              - If the request was successful, it returns the HTTP status code 200
                and the disarmed PDF document. Microsoft Office documents get converted
                into PDF documents.
            * - 401 - Unauthorized
              - If the request was not authorized. In example if the license key is
                not valid anymore.
            * - 429 - Too Many Requests
              - If the quota is exceed, it returns the HTTP status 429.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> with open("/tmp/javascript.pdf", "rb") as fp:
            ...     response = client.disarm_file(os.path.basename(fp.name), fp.read())
            >>> response
            InlyseResponse(
                endpoint='/api/files/disarm',
                status=200,
                rate_limit={
                    'remaining': '14999',
                    'reset': datetime.datetime(
                        2023, 3, 21, 19, 44, 12, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/pdf', {}),
                content=b'%PDF-1.7...%%EOF'
            )
            >>> client.close()


        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """
        return self.api.post(path, files={"file": (filename, content)})

    def disarm(self, filename: str, content: bytes):
        response = self.disarm_file(filename, content)
        if response.status == 200:
            return response
        elif response.status == 429:
            raise RateLimitExceeded("Your rate limte exceeded.")
        else:
            raise InlyseApiError(response.content)

    @endpoint("/api/analysis")
    def list_analyses(
        self, filter_: str = "all", *, path: str
    ) -> InlyseResponse:
        """list_analyses(filter)
        Get all analyses.

        :param filter_: Filter the analyses by finished, unfinished, error or all.
        :type filter_: str, optional

        * **API endpoint**: `/api/analysis`
        * **HTTP Method**: `GET`
        * **Response CONTENT-TYPE**: `application/json`

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              - If the request was successful, it returns the HTTP status code 200
                and a list of analysis UUIDs.
            * - 404 - Not Found
              - No analysis found
            * - 401 - Unauthorized
              - If the request was not authorized. In example if the license key is
                not valid anymore.
            * - 429 - Too Many Requests
              - If the quota is exceed, it returns the HTTP status 429.

        It's possible to filter the analyses by:

            * finished
            * unfinished
            * error
            * all [DEFAULT]

        If no filter is applied, you will get all analyses.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.list_analyses()
            >>> response
            InlyseResponse(
                endpoint='/api/analysis',
                status=200,
                rate_limit={
                    'remaining': '14998',
                    'reset': datetime.datetime(
                        2023, 3, 20, 22, 16, 47, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/json', {'charset': 'UTF-8'}),
                conent=[
                    '079211f4-c401-44fc-a846-01f7ff26e47f',
                    '177a9179-c2d2-4d4a-976f-a8e1e4f496a0',
                    '2f02e53e-5722-4fb1-b0a2-5ae053b2f00c',
                    ...
                    '36adec8e-d54f-401b-bc2f-1dd22ea9b099',
                ]
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """
        if filter_ not in ["all", "finished", "unfinished", "error"]:
            logger.warning("Unknown filter %s.", filter_)
            filter_ = "all"
        return self.api.get(path, params={"filter": filter_})

    @endpoint("/api/analysis/{id}")
    def check(self, analysis_id: str, *, path: str) -> InlyseResponse:
        """check(analysis_id)
        Get an analysis by ID

        :param analysis_id: The UUID of the analysis.
        :type analysis_id: str

        * **API endpoint**: `/api/analysis/<id>`
        * **HTTP Method**: `GET`
        * **Response CONTENT-TYPE**: `application/json`

        .. list-table:: HTTP Response Codes
            :header-rows: 1

            * - Status Code
              - Explaination
            * - 200 - OK
              - If the request was successful, it returns the HTTP status code 200
                and the result of the analysis.
            * - 202 - Accepted
              - If the the analysis is not ready yet, it returns the HTTP status code
                202.
            * - 404 - Not Found
              - If the analysis with the given UUID does not exist the API returns
                the status code 404 and a short explaination about the error.
            * - 401 - Unauthorized
              - If the request was not authorized. In example if the license key is
                not valid anymore.
            * - 429 - Too Many Requests
              - If the quota is exceed, it returns the HTTP status 429.

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.check("1a13ba09-8487-4621-b2a3-b0ff460f7a9e")
            >>> response
            InlyseResponse(
                endpoint='/api/analysis/1a13ba09-8487-4621-b2a3-b0ff460f7a9e',
                status=200,
                rate_limit={
                    'remaining': '14997',
                    'reset': datetime.datetime(
                        2023, 3, 20, 22, 16, 47, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/json', {'charset': 'UTF-8'}),
                content={
                    'ID': '1a13ba09-8487-4621-b2a3-b0ff460f7a9e',
                    'MD5': '7cdba4461284f8e5b5646ee0b502ec55',
                    'SHA1': 'e7ccdd6706a1ec8ac8d21e5b7d152d3e60acfe7c',
                    'SHA256': '55e2e5b4752c3c0626c70efa86041c7429a3322beed516bb35d96fa4edd9948b',
                    'SHA512': 'f068074c5b24133fc97febf5d534961a11cecbf0f17ac46246bdc4cb45d60b84d01ff2df77860d1db69cd37d198331fd9fbc7237e49f74a55af3672e532f6d45',
                    'Filename': '2004.14471.pdf',
                    'Size': 1354850,
                    'FileType': 'application/pdf',
                    'Label': 'benign',
                    'ScoreBenign': '0.9507668964520833',
                    'ScoreMalicious': '0.04923310354791669'
                }
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """  # noqa: E501
        return self.api.get(path.format(id=analysis_id))

    def get_analysis(
        self,
        analysis_id: str,
        estimated_time: float = 5.83675,
        max_retries: int = 3,
    ) -> InlyseResponse:
        """Fetch an analysis after uploading a file

        :param analysis_id: The UUID of the analysis.
        :type analysis_id: str
        :param estimated_time: (optional) The estimated time for the analysis. (Default: 5.83675)
        :type estimated_time: float
        :param max_retries: (optional) The maxium number of retries to fetch the analysis. (Default: 3)
        :type max_retries: int

        :raises RateLimitExceeded: The rate limit for this license key exceeded
        :raises MaxRetriesExceeded: The maximum retries to get the analysis exceeded
        :raises InlyseApiError: The INLYSE API returned an error. (e.g. The analysis id could not be found)

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.get_analysis("1a13ba09-8487-4621-b2a3-b0ff460f7a9e", 5.83675, 2)
            >>> response
            InlyseResponse(
                endpoint='/api/analysis/1a13ba09-8487-4621-b2a3-b0ff460f7a9e',
                status=200,
                rate_limit={
                    'remaining': '14995',
                    'reset': datetime.datetime(
                        2023, 3, 20, 22, 16, 47, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/json', {'charset': 'UTF-8'}),
                content={
                    'ID': '1a13ba09-8487-4621-b2a3-b0ff460f7a9e',
                    'MD5': '7cdba4461284f8e5b5646ee0b502ec55',
                    'SHA1': 'e7ccdd6706a1ec8ac8d21e5b7d152d3e60acfe7c',
                    'SHA256': '55e2e5b4752c3c0626c70efa86041c7429a3322beed516bb35d96fa4edd9948b',
                    'SHA512': 'f068074c5b24133fc97febf5d534961a11cecbf0f17ac46246bdc4cb45d60b84d01ff2df77860d1db69cd37d198331fd9fbc7237e49f74a55af3672e532f6d45',
                    'Filename': '2004.14471.pdf',
                    'Size': 1354850,
                    'FileType': 'application/pdf',
                    'Label': 'benign',
                    'ScoreBenign': '0.9507668964520833',
                    'ScoreMalicious': '0.04923310354791669'
                }
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """  # noqa: E501
        retries = 0
        while retries < max_retries:
            response = self.check(analysis_id)
            if response.status == 200:
                return response
            elif response.status == 202:
                self._wait(retries, avg_time=estimated_time)
            elif response.status == 429:
                raise RateLimitExceeded("Your rate limte exceeded.")
            else:
                raise InlyseApiError(response.content)
            retries += 1
        raise MaxRetriesExceeded(
            "Max retries exceeded. Please increase the number of retries or the estimated waiting time."
        )

    def _upload(self, upload_type, max_retries, **kwargs):
        """An upload wrapper method"""
        upload_methods = {
            "file": self.upload_file,
            "url": self.upload_url,
            "owa": self.upload_owa,
        }
        response = upload_methods[upload_type](**kwargs)
        if response.status == 429:
            raise RateLimitExceeded("Your rate limte exceeded.")
        elif response.status > 299 or response.status < 200:
            raise InlyseApiError(response.content)

        estimated_time = response.content["EstimatedAnalysisTime"] * 0.2
        return self.get_analysis(
            response.content["id"], estimated_time, max_retries
        )

    def scan_file(
        self, filename: str, content, max_retries: int = 15
    ) -> InlyseResponse:
        """Uploads a local file and tries to fetch the result.

        :param filename: The name of the file.
        :type filename: str
        :param content: The content of the file.
        :type cotent: bytes
        :param max_retries: (optional) The maxium number of retries to fetch the analysis. (Default: 15)
        :type max_retries: int

        :raises RateLimitExceeded: The rate limit for this license key exceeded
        :raises MaxRetriesExceeded: The maximum retries to get the analysis exceeded
        :raises InlyseApiError: The INLYSE API returned an error. (e.g. The analysis id could not be found)

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> with open("/tmp/javascript.pdf", "rb") as fp:
            ...     response = client.scan_file(os.path.basename(fp.name), fp.read())
            >>> response
            InlyseResponse(
                endpoint='/api/analysis/8f238204-8540-4424-9872-822c46e39c05',
                status=200,
                rate_limit={
                    'remaining': '14992',
                    'reset': datetime.datetime(
                        2023, 3, 20, 22, 16, 47, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/json', {'charset': 'UTF-8'}),
                content={
                    'ID': '8f238204-8540-4424-9872-822c46e39c05',
                    'MD5': '55b47515feeeb8dae78763d662923787',
                    'SHA1': '5af3f43e3169e1e678e06b6372a60d9df22dc6d0',
                    'SHA256': '1fede472c1e339272f2ea27496ea059e86d6594b1ae93cbb6a486eeb118527e1',
                    'SHA512': 'a2fff650ba010c56b51ff4e9f3ee77292651428ad41d467f8c471b4c9091060a3dc64acea22ee875ec6f14abd3e018f944a92e87f4567b71fae05b2d80566880',
                    'Filename': 'javascript.pdf',
                    'Size': 990,
                    'FileType': 'application/pdf',
                    'Label': 'malicious',
                    'ScoreBenign': '0.0008773440468863303',
                    'ScoreMalicious': '0.9991226559531137',
                    'Action': 'DELETE;DISARM'
                }
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """  # noqa: E501
        return self._upload(
            "file", max_retries, filename=filename, content=content
        )

    def scan_url(self, url: str, max_retries: int = 15) -> InlyseResponse:
        """Uploads a remote file and tries to fetch the result.

        :param url: The download URL of the file.
        :type url: str
        :param max_retries: (optional) The maxium number of retries to fetch the analysis. (Default: 15)
        :type max_retries: int

        :raises RateLimitExceeded: The rate limit for this license key exceeded
        :raises MaxRetriesExceeded: The maximum retries to get the analysis exceeded
        :raises InlyseApiError: The INLYSE API returned an error. (e.g. The analysis id could not be found)

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.scan_url("https://arxiv.org/pdf/2004.14471.pdf")
            >>> response
            InlyseResponse(
                endpoint='/api/analysis/98e56af3-0f17-470b-bfcb-5ef7d4c83e07',
                status=200,
                rate_limit={
                    'remaining': '14988',
                    'reset': datetime.datetime(
                        2023, 3, 20, 22, 16, 47, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/json', {'charset': 'UTF-8'}),
                content={
                    'ID': '98e56af3-0f17-470b-bfcb-5ef7d4c83e07',
                    'MD5': '7cdba4461284f8e5b5646ee0b502ec55',
                    'SHA1': 'e7ccdd6706a1ec8ac8d21e5b7d152d3e60acfe7c',
                    'SHA256': '55e2e5b4752c3c0626c70efa86041c7429a3322beed516bb35d96fa4edd9948b',
                    'SHA512': 'f068074c5b24133fc97febf5d534961a11cecbf0f17ac46246bdc4cb45d60b84d01ff2df77860d1db69cd37d198331fd9fbc7237e49f74a55af3672e532f6d45',
                    'Filename': '2004.14471.pdf',
                    'Size': 1354850,
                    'FileType': 'application/pdf',
                    'Label': 'benign',
                    'ScoreBenign': '0.9507668964520833',
                    'ScoreMalicious': '0.04923310354791669'
                }
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """  # noqa: E501
        return self._upload("url", max_retries, url=url)

    def scan_owa(
        self, url: str, token: str, max_retries: int = 15
    ) -> InlyseResponse:
        """Uploads a outlook attachment and tries to fetch the result.

        :param url: The download URL of the file.
        :type url: str
        :param max_retries: (optional) The maxium number of retries to fetch the analysis. (Default: 15)
        :type max_retries: int

        :raises RateLimitExceeded: The rate limit for this license key exceeded
        :raises MaxRetriesExceeded: The maximum retries to get the analysis exceeded
        :raises InlyseApiError: The INLYSE API returned an error. (e.g. The analysis id could not be found)

        **Example**:

        .. sourcecode:: pycon

            >>> from inlyse import WebClient
            >>> client = WebClient(<your license key>)
            >>> response = client.scan_owa(
            ...     "https://attachments.office.net/owa/Max.Mustermann%40test.com/...",
            ...     "iMWFWf1EZh8WM27tqXFlIa1QoNDfmjaZT0Xz7IyaDASBCUamUKcMKUSTVYJTOUm5..."
            ... )
            >>> response
            InlyseResponse(
                endpoint='/api/analysis/98e56af3-0f17-470b-bfcb-5ef7d4c83e07',
                status=200,
                rate_limit={
                    'remaining': '14988',
                    'reset': datetime.datetime(
                        2023, 3, 20, 22, 16, 47, tzinfo=datetime.timezone.utc
                    )
                },
                content_type=('application/json', {'charset': 'UTF-8'}),
                content={
                    'ID': '98e56af3-0f17-470b-bfcb-5ef7d4c83e07',
                    'MD5': '7cdba4461284f8e5b5646ee0b502ec55',
                    'SHA1': 'e7ccdd6706a1ec8ac8d21e5b7d152d3e60acfe7c',
                    'SHA256': '55e2e5b4752c3c0626c70efa86041c7429a3322beed516bb35d96fa4edd9948b',
                    'SHA512': 'f068074c5b24133fc97febf5d534961a11cecbf0f17ac46246bdc4cb45d60b84d01ff2df77860d1db69cd37d198331fd9fbc7237e49f74a55af3672e532f6d45',
                    'Filename': '2004.14471.pdf',
                    'Size': 1354850,
                    'FileType': 'application/pdf',
                    'Label': 'benign',
                    'ScoreBenign': '0.9507668964520833',
                    'ScoreMalicious': '0.04923310354791669'
                }
            )
            >>> client.close()

        :return: Returns an :class:`inlyse.cli.InlyseResponse` object.
        :rtype: InlyseResponse
        """  # noqa: E501
        return self._upload("owa", max_retries, url=url, token=token)

    def close(self) -> None:
        """Close the HTTP session"""
        if isinstance(self._api, sessions.BaseUrlSession):
            self._api.close()
        self._api = None
