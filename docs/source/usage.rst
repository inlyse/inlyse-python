=====
Usage
=====

The library needs to be configured with a licenses key
which is available in your `INLYSE Dashboard`_.

To use inlyse-python in a project.

.. sourcecode:: pycon

    >>> from inlyse import WebClient
    >>> with WebClient("<your license key>") as client:
    ...     response = client.ping()
    ...     print(response.content)
    Pong
