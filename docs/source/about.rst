About inlyse-python
===================

The `INLYSE`_ Python library provides convenient access to the `INLYSE API`_
from applications written in the Python language. The `INLYSE API`_ gives you
access to all malware classification services of `INLYSE`_. It serves as the
central access point for all requests to the backend services.

Benefits
--------
1. **Integrate security into the development** - Add a layer of security to detect the most sophisticated email-borne threats whether its client or server-based.
2. **Centralized configuration** - Our SDK provides probabilities to query our CDR or notification endpoints directly, or you can configure the behavior within the INLYSE dashboard in a centralized manner.
3. **Multi-channel deployment** - You can keep your files secure and gatekeep URLs locally or in the cloud. It’s easy; it’s fast; it’s effective.
4. **Scanning files made easy** - Scanning files is as easy as sending only two HTTP requests: one, to upload the file, and two, to grab the analysis results.
5. **On-demand malware scanner** - Build a malware scanner tool using INLYSE’s API or let developers scan for malware where it is required without the messy codes.

Rate Limit
----------
`INLYSE`_ rate limits every API request made to the `INLYSE API`_. This should increase the
stability of the product and prevents abuse. Users who send too many requests in quick succession
may see error responses that show up as status code 429.

.. note::
   Please note that these limits are subject to modification to always offer the best service to
   users.

You can track your rate limit usage by looking at special headers in the response.

Headers
^^^^^^^
Every API request response includes the following headers:

- **X-Ratelimit-Limit** - The maximum number of requests allowed within the window
- **X-Ratelimit-Remaining** - The number of requests this caller has left on this endpoint within the current window
- **X-Ratelimit-Reset** - The time when the next rate limit window begins and the count resets, measured in UTC seconds
  from epoch

Usage
^^^^^
Every endpoint method of the :class:`inlyse.cli.WebClient` returns an object of the type
:class:`inlyse.cli.InlyseResponse` which includes all necessary information about the rate limit:

    .. sourcecode:: pycon

        >>> response.rate_limit
        {
            'limit': '15000',
            'remaining': '14999',
            'reset': datetime.datetime(
                2023, 3, 28, 18, 57, 15, tzinfo=datetime.timezone.utc
            )
        }

Maximal Upload File Size
------------------------
All uploaded documents are restricted in size. It is not allowed to upload documents which are
bigger than 17 MB. Users who send documents bigger than 17 MB may see error responses that show up
as status code 400 and the reason `FILE_TOO_BIG`.

Document Storage Duration
-------------------------
All uploaded documents get deleted after the analysis is completed. INLYSE takes
the security of your personal data very seriously.

Available backend services
--------------------------

Malware Classifications of Office Documents
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The `INLYSE API`_ offers the service to analyze the following document types:

- PDF Documents
- Microsoft Office Documents
- ZIP archives with exactly `1` PDF Document or Microsoft Office Document

The API identifies the type of the file and sends the document automatically
to the correct backend service. The backend service predicts with the help of
modern machine learning techniques the probability of the maliciousness.

To analyze a document it's necessary to upload the document. You can upload a local
file, provide a public HTTP(S) URL or an Outlook On the Web (OWA) link and the
corresponding token:

- :func:`inlyse.cli.WebClient.upload_file`
- :func:`inlyse.cli.WebClient.upload_url`
- :func:`inlyse.cli.WebClient.upload_owa`

The following example shows how to upload a local file:

.. sourcecode:: pycon

    >>> from inlyse import WebClient
    >>> client = WebClient(<your license key>)
    >>> with open("/tmp/javascript.pdf", "rb") as fp:
    ...     response = client.upload_file(os.path.basename(fp.name), fp.read())
    >>> response.content["id"]
    '8f238204-8540-4424-9872-822c46e39c05'

The response of the upload request includes an UUID which uniquely identifies the
analysis and an estimated time for the analysis. In a second step it's necessary
to ask for the result of the analysis.

- :func:`inlyse.cli.WebClient.check`

The following example show how to get the result of the previous uploaded file:

.. sourcecode:: pycon

    >>> from inlyse import WebClient
    >>> client = WebClient(<your license key>)
    >>> response = client.check("8f238204-8540-4424-9872-822c46e39c05")

The result includes the probability of the maliciousness of the document and
some metadata like name, size, type and a few hash digests. Furthermore it includes
also the actions which you have configured in the `dashboard <https://dashboard.inlyse.cloud/app/config_rules>`_.

.. sourcecode:: json

   {
        "ID": "8f238204-8540-4424-9872-822c46e39c05",
        "MD5": "55b47515feeeb8dae78763d662923787",
        "SHA1": "5af3f43e3169e1e678e06b6372a60d9df22dc6d0",
        "SHA256": "1fede472c1e339272f2ea27496ea059e86d6594b1ae93cbb6a486eeb118527e1",
        "SHA512": "a2fff650ba010c56b51ff4e9f3ee77292651428ad41d467f8c471b4c9091060a3dc64acea22ee875ec6f14abd3e018f944a92e87f4567b71fae05b2d80566880",
        "Filename": "javascript.pdf",
        "Size": 990,
        "FileType": "application/pdf",
        "Label": "malicious",
        "ScoreBenign": "0.0008773440468863303",
        "ScoreMalicious": "0.9991226559531137",
        "Action": "DELETE;DISARM"
    }

The library offers you also methods which combine these two steps already:

- :func:`inlyse.cli.WebClient.scan_file`
- :func:`inlyse.cli.WebClient.scan_url`
- :func:`inlyse.cli.WebClient.scan_owa`

Disarm PDF and Microsoft Office Documents
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The `INLYSE API`_ offers the service to disarm PDF and Microsoft Office Documents.

- :func:`inlyse.cli.WebClient.disarm_file`
- :func:`inlyse.cli.WebClient.disarm_analysis`

The following example shows how you disarm a local file:

.. sourcecode:: pycon

    >>> from inlyse import WebClient
    >>> client = WebClient(<your license key>)
    >>> with open("/tmp/javascript.pdf", "rb") as fp:
    ...     response = client.disarm_file(os.path.basename(fp.name), fp.read())

The content of the response is always a signed PDF document.
