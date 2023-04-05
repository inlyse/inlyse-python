#!/usr/bin/env python3
import json
import os
import pathlib
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from logging import DEBUG, INFO, WARNING
from multiprocessing import freeze_support
from multiprocessing.pool import ThreadPool as Pool

import click
import requests
from click_params import PUBLIC_URL
from loguru import logger
from tqdm import tqdm

import inlyse

LOGLEVELS = {
    0: WARNING,
    1: INFO,
    2: DEBUG,
}


@dataclass
class ScanFailure:
    asset: str
    error: str


@dataclass
class ScanSuccess:
    asset: str
    response: inlyse.cli.InlyseResponse


def _scan_file(client, filename):
    with open(filename, "rb") as fb:
        return client.scan_file(fb.name, fb.read())


def _disarm_file(client, filename):
    with open(filename, "rb") as fb:
        return client.disarm(fb.name, fb.read())


def _scan_url(client, url):
    return client.scan_url(url)


def _get_analyses(client, analysis_id):
    return client.get_analysis(analysis_id)


def _api_wrapper(asset, method, client):
    mapper = {
        "scan_file": _scan_file,
        "scan_url": _scan_url,
        "disarm_file": _disarm_file,
        "get_analyses": _get_analyses,
    }
    try:
        return ScanSuccess(str(asset), mapper[method](client, asset))
    except Exception as error:
        return ScanFailure(str(asset), error)


def _scan(
    method, assets, asset_unit, url, license_key, threads, timeout, remaining
):
    if remaining < len(assets) * 4:
        click.confirm(
            (
                "Critical Rate-Limit: "
                f"You have just {remaining} requests left."
                "Do you want to continue anyway ..."
            ),
            abort=True,
            err=True,
        )
    scans = {
        "success": {},
        "failures": {},
    }
    with Pool(threads) as pool:
        with inlyse.WebClient(license_key, url, timeout) as client:
            desc = "Scanning"
            if method.startswith("disarm"):
                desc = "Disarming"
            if method.startswith("get"):
                desc = "Fetching"
            for result in tqdm(
                pool.imap_unordered(
                    partial(_api_wrapper, client=client, method=method), assets
                ),
                total=len(assets),
                desc=desc,
                unit=asset_unit,
            ):
                if type(result).__name__ == "ScanSuccess":
                    scans["success"][result.asset] = result.response.content
                else:
                    scans["failures"][result.asset] = str(result.error)
    if method == "disarm_file":
        return scans
    click.echo(json.dumps(scans))


_disarm = _scan


@click.group()
@click.version_option(inlyse.__version__, prog_name="inlyse-scanner")
@click.option(
    "-l",
    "--license-key",
    type=str,
    required=True,
    help="The license key for the INLYSE API.",
)
@click.option(
    "-u",
    "--url",
    type=str,
    default="https://malware.ai",
    show_default=True,
    help="The URL of the INLYSE API.",
)
@click.option(
    "-t",
    "--threads",
    type=int,
    default=4,
    show_default=True,
    help="The number of threads.",
)
@click.option(
    "--timeout",
    type=float,
    default=5.0,
    show_default=True,
    help="The HTTP request timeout.",
)
@click.option("-v", "--verbose", count=True, default=0)
@click.pass_context
def main(ctx, license_key, url, threads, timeout, verbose):
    ctx.ensure_object(dict)
    ctx.obj["LOGLEVEL"] = LOGLEVELS.get(min(len(LOGLEVELS) - 1, verbose))
    ctx.obj["LICENSE_KEY"] = license_key
    ctx.obj["URL"] = url
    ctx.obj["THREADS"] = threads
    ctx.obj["TIMEOUT"] = timeout
    logger.remove()
    logger.add(sys.stderr, level=ctx.obj["LOGLEVEL"])
    logger.debug(f"inlyse-python version: {inlyse.__version__}")
    logger.debug("Python version: {}".format(sys.version.split()[0]))
    logger.debug("Running some pre-checks ...")
    with inlyse.WebClient(license_key, url, timeout) as client:
        try:
            logger.debug("Trying to ping the API ...")
            response = client.ping()
            logger.debug(
                "Tyring to get stats, to check if the license key is valid ..."
            )
            response = client.stats()
            if response.status == 401:
                logger.debug(response)
                click.echo(
                    "Unauthorized: Please provide a valid license key.",
                    err=True,
                )
                sys.exit(1)
            if response.status == 429 or response.rate_limit["remaining"] == 0:
                logger.debug(response)
                continue_in = response.rate_limit["reset"] - datetime.now(
                    timezone.utc
                )
                continue_in = divmod(continue_in.total_seconds(), 60)[0]
                click.echo(
                    f"Rate-Limit Exceeded: Please try again in {continue_in} minutes.",
                    err=True,
                )
                sys.exit(1)
            ctx.obj["REMAINING"] = response.rate_limit["remaining"]
        except requests.exceptions.ReadTimeout as error:
            logger.debug(error)
            click.echo("Timeout: The API request timed out", err=True)
            sys.exit(1)
        except requests.exceptions.ConnectionError as error:
            logger.debug(error)
            click.echo(
                f"Unreachable: The API ({client.url}) is not reachable.",
                err=True,
            )
            sys.exit(1)
        except Exception as error:
            logger.debug(error)
            click.echo(
                "Exception not handled: Please report an issue.", err=True
            )
            sys.exit(1)


@main.group()
@click.pass_context
def scan(ctx):
    """Scan files or URLs"""
    pass


@scan.command(name="file")
@click.pass_context
@click.argument("filenames", nargs=-1, type=click.Path(exists=True))
def scan_file(ctx, filenames):
    """Scan files"""
    _scan(
        "scan_file",
        filenames,
        "file",
        ctx.obj["URL"],
        ctx.obj["LICENSE_KEY"],
        ctx.obj["THREADS"],
        ctx.obj["TIMEOUT"],
        ctx.obj["REMAINING"],
    )


@scan.command(name="url")
@click.pass_context
@click.argument("urls", nargs=-1, type=PUBLIC_URL)
def scan_url(ctx, urls):
    """Scan URLs"""
    _scan(
        "scan_url",
        urls,
        "url",
        ctx.obj["URL"],
        ctx.obj["LICENSE_KEY"],
        ctx.obj["THREADS"],
        ctx.obj["TIMEOUT"],
        ctx.obj["REMAINING"],
    )


@main.command()
@click.pass_context
@click.option(
    "-o",
    "--output-folder",
    default=".",
    show_default=True,
    type=click.Path(exists=True),
    help="The output folder for the disarmed documents.",
)
@click.argument("filenames", nargs=-1, type=click.Path(exists=True))
def disarm(ctx, output_folder, filenames):
    """Disarm files"""
    output = {}
    disarmed_files = _disarm(
        "disarm_file",
        filenames,
        "file",
        ctx.obj["URL"],
        ctx.obj["LICENSE_KEY"],
        ctx.obj["THREADS"],
        ctx.obj["TIMEOUT"],
        ctx.obj["REMAINING"],
    )
    for status, results in disarmed_files.items():
        output[status] = {}
        for asset, result in results.items():
            if status == "success":
                disarmed_file = os.path.join(
                    output_folder,
                    f"{pathlib.Path(asset).stem}.disarmed.pdf",
                )
                with open(disarmed_file, "wb") as fb:
                    fb.write(result)
                output[status][asset] = {"dst": disarmed_file}
            else:
                output[status][asset] = result
    click.echo(json.dumps(output))


@main.command(name="list")
@click.pass_context
@click.option(
    "-f",
    "--filter",
    "analyses_filter",
    default="all",
    show_default=True,
    type=click.Choice(
        ["all", "finished", "unfinished", "error"], case_sensitive=False
    ),
    help="Filter for the list of analyses.",
)
def list_analyses(ctx, analyses_filter):
    """List all analyses"""
    with inlyse.WebClient(
        ctx.obj["LICENSE_KEY"], ctx.obj["URL"], ctx.obj["TIMEOUT"]
    ) as client:
        try:
            response = client.list_analyses(filter_=analyses_filter.lower())
            click.echo(json.dumps(response.content))
        except Exception as error:
            logger.error(error)
            sys.exit(1)


@main.command()
@click.pass_context
def stats(ctx):
    """Get some stats"""
    with inlyse.WebClient(
        ctx.obj["LICENSE_KEY"], ctx.obj["URL"], ctx.obj["TIMEOUT"]
    ) as client:
        try:
            response = client.stats()
            click.echo(json.dumps(response.content))
        except Exception as error:
            logger.error(error)
            sys.exit(1)


@main.command()
@click.pass_context
@click.argument("analysis_ids", nargs=-1, type=click.UUID)
def get(ctx, analysis_ids):
    """Get the analyses result(s)"""
    _scan(
        "get_analyses",
        analysis_ids,
        "id",
        ctx.obj["URL"],
        ctx.obj["LICENSE_KEY"],
        ctx.obj["THREADS"],
        ctx.obj["TIMEOUT"],
        ctx.obj["REMAINING"],
    )


if __name__ == "__main__":
    freeze_support()
    main()
