# INLYSE Python Library 1.0.3  <!-- semantic release -->

[![pypi](https://img.shields.io/pypi/v/inlyse-python.svg)](https://pypi.org/project/inlyse-python/)
[![python](https://img.shields.io/pypi/pyversions/inlyse-python.svg)](https://pypi.org/project/inlyse-python/)
![GitHub](https://img.shields.io/github/license/inlyse/inlyse-python)
[![docs](https://img.shields.io/badge/docs-inlyse--python-11BBAA)](https://documentation.inlyse.cloud/python)
[![code-style](https://img.shields.io/badge/code--style-black-000000)](https://img.shields.io/badge/code--style-black-000000)

The INLYSE Python library provides convenient access to the INLYSE API
from applications written in the Python language.

## Installation
INLYSE provides a [pypi](https://pypi.org) package. You can install the
package like this at the command line.

~~~Bash
$ pip install inlyse
~~~

## Library Usage
The library needs to be configured with a licenses key
which is available in your account on [INLYSE Dashboard](https://dashboard.inlyse.cloud)

To use inlyse-python in a project:

~~~Python
>>> from inlyse import WebClient
>>> with WebClient("<your license key>") as client:
...     client.ping()
~~~

For more details please checkout our [documentation](https://documentation.inlyse.cloud/python).

## Console Script Usage

### Scan file(s)
~~~Bash
❯ inlyse-scanner -l <your license key> scan file /tmp/exmaple.pdf | jq
Scanning: 100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:03<00:00,  3.97s/file]
{
  "success": {
    "/tmp/example.pdf": {
      "ID": "32313dd2-eccc-4ade-bb54-18f2b29342fa",
      "MD5": "55b47515feeeb8dae78763d662923787",
      "SHA1": "5af3f43e3169e1e678e06b6372a60d9df22dc6d0",
      "SHA256": "1fede472c1e339272f2ea27496ea059e86d6594b1ae93cbb6a486eeb118527e1",
      "SHA512": "a2fff650ba010c56b51ff4e9f3ee77292651428ad41d467f8c471b4c9091060a3dc64acea22ee875ec6f14abd3e018f944a92e87f4567b71fae05b2d80566880",
      "Filename": "example.pdf",
      "Size": 990,
      "FileType": "application/pdf",
      "Label": "malicious",
      "ScoreBenign": "0.0008773440468863303",
      "ScoreMalicious": "0.9991226559531137",
      "Action": "DELETE;DISARM"
    }
  },
  "failures": {}
}
~~~

### Scan URL(s)
~~~Bash
❯ inlyse-scanner -l <your license key> scan url https://arxiv.org/pdf/2004.14471.pdf | jq
Scanning: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:05<00:00,  5.01s/url]
{
  "success": {
    "https://arxiv.org/pdf/2004.14471.pdf": {
      "ID": "8f329d6b-beec-4856-8266-50824299a0ff",
      "MD5": "7cdba4461284f8e5b5646ee0b502ec55",
      "SHA1": "e7ccdd6706a1ec8ac8d21e5b7d152d3e60acfe7c",
      "SHA256": "55e2e5b4752c3c0626c70efa86041c7429a3322beed516bb35d96fa4edd9948b",
      "SHA512": "f068074c5b24133fc97febf5d534961a11cecbf0f17ac46246bdc4cb45d60b84d01ff2df77860d1db69cd37d198331fd9fbc7237e49f74a55af3672e532f6d45",
      "Filename": "2004.14471.pdf",
      "Size": 1354850,
      "FileType": "application/pdf",
      "Label": "benign",
      "ScoreBenign": "0.9507668964520833",
      "ScoreMalicious": "0.04923310354791669"
    }
  },
  "failures": {}
}
~~~

### Disarm file(s)
~~~Bash
❯ inlyse-scanner -l <your license key> disarm /tmp/example.pdf | jq
Disarming: 100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:01<00:00,  1.55s/file]
{
  "success": {
    "/tmp/example.pdf": {
      "dst": "./example.disarmed.pdf"
    }
  },
  "failures": {}
}

~~~

### List analyses
~~~Bash
❯ inlyse-scanner -l <your license key> list -f error | jq
[
  "5d4bbf77-2877-46b7-8552-8dee252fd7fe",
  "bfc2ab18-457c-4b4f-a993-f5c952f0c488",
  "6fb5e39b-c880-43e0-be28-d03a65096280"
]
~~~

### Get analyses
~~~Bash
❯ inlyse-scanner -l <your license key> get f0b843a8-c34c-49c4-bfd8-d881f0ab56a0 | jq
Fetching: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  1.08id/s]
{
  "success": {
    "f0b843a8-c34c-49c4-bfd8-d881f0ab56a0": {
      "ID": "f0b843a8-c34c-49c4-bfd8-d881f0ab56a0",
      "MD5": "52eed303beac5961399b634e8fdc95dc",
      "SHA1": "bebed2aa096eaf031d022bbfc12f44a3b8315b50",
      "SHA256": "c7ff5c769c257a7ab0cc3a906e63b15aea91e1605a269b7dcbcb3911ea07681c",
      "SHA512": "6ca5316181bc7808a697f6a1be90576d5ccb5d62f062d49439e8f3ae883b70bece963b264ef64d48ad885fa88bc4ce67baeab019171f6b39d8d2e6dfb7cd5f79",
      "Filename": "fileAttachment.pdf",
      "Size": 78950,
      "FileType": "application/pdf",
      "Label": "benign",
      "ScoreBenign": "0.5801288570016421",
      "ScoreMalicious": "0.4198711429983579"
    }
  },
  "failures": {}
}
~~~

### Get stats
~~~Bash
❯ inlyse-scanner -l <your license key> stats | jq
{
  "AnalysedFiles": 15,
  "Traffic": 237204
}
~~~


## Development
~~~Bash
$ python3 -m venv .venv && source .venv/bin/activate
$ pip install poetry
$ poetry install
$ pre-commit install
~~~

## Testing

~~~Bash
$ poetry run pytest -vvv
~~~
