import responses


@responses.activate
def test_ping(client, api, ping_response) -> None:
    responses.get(api.format(endpoint="/ping"), json=ping_response, status=200)
    response = client.ping()
    assert response.status == 200
    assert response.content_type[0] == "application/json"
    assert response.content == "Pong"


@responses.activate
def test_stats(client, api, stats_response, rate_limit) -> None:
    responses.get(
        api.format(endpoint="/api/stats"),
        json=stats_response,
        status=200,
        headers=rate_limit["headers"],
    )
    response = client.stats()
    assert response.status == 200
    assert response.content_type[0] == "application/json"
    assert response.content["AnalysedFiles"] == 10
    assert response.content["Traffic"] == 10000


@responses.activate
def test_download(client, api, download_response, rate_limit) -> None:
    analysis_id = "1e65cd90-3fe8-4da8-a4a5-4b63e6ed6133"
    responses.get(
        api.format(endpoint=f"/api/analysis/{analysis_id}/download"),
        body=download_response,
        content_type="application/pdf",
        status=200,
        headers=rate_limit["headers"],
    )
    response = client.download(analysis_id)
    assert response.status == 200
    assert response.content_type[0] == "application/pdf"
    assert response.content[:8] == b"%PDF-1.7"


@responses.activate
def test_download_link(client, api) -> None:
    analysis_id = "1b02d05d-7c26-4eca-8bd1-fb29eb816775"
    link = client.download_link(analysis_id)
    assert link == api.format(endpoint=f"/api/analysis/{analysis_id}/download")


@responses.activate
def test_upload_file(client, api, upload_file_response, rate_limit) -> None:
    responses.post(
        api.format(endpoint="/api/files/"),
        json=upload_file_response,
        status=200,
        headers=rate_limit["headers"],
    )
    response = client.upload_file("test.pdf", b"%PDF1.7")
    assert response.status == 200
    assert response.content_type[0] == "application/json"
    assert (
        "id" in response.content
        and "EstimatedAnalysisTime" in response.content
    )


@responses.activate
def test_upload_url(client, api, upload_url_response, rate_limit) -> None:
    responses.post(
        api.format(endpoint="/api/files/url"),
        json=upload_url_response,
        status=200,
        headers=rate_limit["headers"],
    )
    response = client.upload_url("https://inlyse.com/test.pdf")
    assert response.status == 200
    assert response.content_type[0] == "application/json"
    assert (
        "id" in response.content
        and "EstimatedAnalysisTime" in response.content
    )


@responses.activate
def test_upload_owa(client, api, upload_owa_response, rate_limit) -> None:
    responses.post(
        api.format(endpoint="/api/files/owa"),
        json=upload_owa_response,
        status=200,
        headers=rate_limit["headers"],
    )
    response = client.upload_owa("https://test.owa.local", "test")
    assert response.status == 200
    assert response.content_type[0] == "application/json"
    assert (
        "id" in response.content
        and "EstimatedAnalysisTime" in response.content
    )


@responses.activate
def test_list(client, api, list_response, rate_limit) -> None:
    responses.get(
        api.format(endpoint="/api/analysis"),
        json=list_response,
        status=200,
        headers=rate_limit["headers"],
    )
    response = client.list_analyses()
    assert response.status == 200
    assert response.content_type[0] == "application/json"
    assert response.content == list_response


@responses.activate
def test_check(client, api, check_response, rate_limit) -> None:
    analysis_id = "1ee54150-1df8-4a74-b8c9-cf12c0647339"
    responses.get(
        api.format(endpoint=f"/api/analysis/{analysis_id}"),
        json=check_response,
        status=200,
        headers=rate_limit["headers"],
    )
    response = client.check(analysis_id)
    assert response.status == 200
    assert response.content_type[0] == "application/json"
    assert response.content == {
        "ID": f"{analysis_id}",
        "MD5": "f5d7470145ba5a8afc9b0ac502231d63",
        "SHA1": "4a1634fdb9cca72ec0a7f094055e4b08a40da66c",
        "SHA256": "11772fdbe266d8214875095b6dc8102838a0fe3d7f25bc75c88a7f6fb6c98af2",  # noqa: E501
        "SHA512": "98b0dbf4f999f1efc1f5d28dbd5edbbb5d49903ddae230e6848fdf90b18332cc90244b290b35fb0d61ca576e180fa3978a5e7491b0b0b7505eb9b87a61b9064e",  # noqa: E501
        "Filename": "dairycow_vacalechera.pdf",
        "Size": 3042676,
        "FileType": "application/pdf",
        "Label": "benign",
        "ScoreBenign": "0.9225084524559095",
        "ScoreMalicious": "0.07749154754409047",
    }
