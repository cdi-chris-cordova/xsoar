"""Synchronize Rapid7 scan engines into the known_scanners_kv collection.

Configure `username` and `password` as sensitive automation arguments in XSOAR.
"""

from CommonServerPython import *
import json
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException
import requests


DEFAULT_URL = "https://rapid7.chdn.com:3780/api/3/scan_engines"
REQUEST_TIMEOUT = 30

KV_APP_NAME = "SplunkEnterpriseSecuritySuite"
KV_COLLECTION_NAME = "known_scanners_kv"
KV_USING = "SplunkPy Notable Incidents - CDI"

EXCLUDED_ENGINE_NAMES = {
    "Local scan engine",
    "Rapid7 Hosted Scan Engine",
}


def _get_arg(name, default=None):
    value = demisto.args().get(name)
    if value is None or value == "":
        return default
    return value


def _execute_command(command, args):
    results = demisto.executeCommand(command, args)
    if not results:
        return_error(f"{command} returned no results.")

    first_result = results[0]
    if first_result.get("Type") == entryTypes["error"]:
        return_error(f"{command} failed: {first_result.get('Contents')}")

    return results


def _normalize_scanner(scanner):
    if not isinstance(scanner, dict):
        return None

    ip = scanner.get("ip")
    host = scanner.get("nt_host")
    if not ip or not host:
        return None
    if host in EXCLUDED_ENGINE_NAMES:
        return None

    return {"ip": str(ip), "nt_host": str(host)}


def _dedupe_and_sort(scanners):
    indexed = {}
    for scanner in scanners:
        normalized = _normalize_scanner(scanner)
        if normalized:
            indexed[(normalized["nt_host"], normalized["ip"])] = normalized

    return [indexed[key] for key in sorted(indexed)]


def _fetch_rapid7_scanners(username, password):
    try:
        response = requests.get(
            DEFAULT_URL,
            headers={"Accept": "application/json"},
            auth=HTTPBasicAuth(username, password),
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except RequestException as exc:
        return_error(f"Failed to query Rapid7 scan engines: {exc}")
    except ValueError as exc:
        return_error(f"Rapid7 returned invalid JSON: {exc}")

    if not isinstance(payload, dict):
        return_error("Rapid7 response was not a JSON object.")

    resources = payload.get("resources", [])
    if not isinstance(resources, list):
        return_error('Rapid7 response did not include a list under "resources".')

    scanners = []
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        scanners.append(
            {
                "ip": resource.get("address"),
                "nt_host": resource.get("name"),
            }
        )

    return _dedupe_and_sort(scanners)


def _load_known_scanners():
    results = _execute_command(
        "splunk-kv-store-collection-data-list",
        {
            "app_name": KV_APP_NAME,
            "kv_store_collection_name": KV_COLLECTION_NAME,
            "limit": 0,
            "using": KV_USING,
        },
    )

    contents = results[0].get("Contents")
    if isinstance(contents, str):
        message = contents.strip()
        try:
            contents = json.loads(message)
        except ValueError:
            normalized_message = message.lower()
            if not message or "no entries" in normalized_message or "no data" in normalized_message:
                return []
            return_error(f"Failed to read {KV_COLLECTION_NAME}: {message}")

    if isinstance(contents, str):
        message = contents.strip()
        normalized_message = message.lower()
        if not message or "no entries" in normalized_message or "no data" in normalized_message:
            return []
        return_error(f"Failed to read {KV_COLLECTION_NAME}: {message}")

    if isinstance(contents, dict):
        contents = [contents]

    if not isinstance(contents, list):
        return_error(f"Unexpected KV store response type: {type(contents).__name__}")

    return _dedupe_and_sort(contents)


def _sync_scanners(remote_scanners, known_scanners):
    remote_index = {(scanner["nt_host"], scanner["ip"]): scanner for scanner in remote_scanners}
    known_index = {(scanner["nt_host"], scanner["ip"]): scanner for scanner in known_scanners}

    added = [remote_index[key] for key in sorted(remote_index.keys() - known_index.keys())]
    removed = [known_index[key] for key in sorted(known_index.keys() - remote_index.keys())]

    return added, removed


def main():
    username = _get_arg("username")
    password = _get_arg("password")

    if not username:
        return_error("Missing required argument: username")
    if not password:
        return_error("Missing required argument: password")

    remote_scanners = _fetch_rapid7_scanners(username, password)
    known_scanners = _load_known_scanners()
    added_scanners, removed_scanners = _sync_scanners(remote_scanners, known_scanners)

    if not added_scanners and not removed_scanners:
        return_results("Lists match. No need to modify list")
        return

    if added_scanners:
        _execute_command(
            "splunk-kv-store-collection-add-entries",
            {
                "kv_store_data": added_scanners,
                "kv_store_collection_name": KV_COLLECTION_NAME,
                "app_name": KV_APP_NAME,
            },
        )
        demisto.setContext("AddedScanners", added_scanners)

    for scanner in removed_scanners:
        _execute_command(
            "splunk-kv-store-collection-delete-entry",
            {
                "value": scanner.get("ip"),
                "kv_store_collection_name": KV_COLLECTION_NAME,
                "app_name": KV_APP_NAME,
            },
        )

    if removed_scanners:
        demisto.setContext("RemovedScanners", removed_scanners)

    return_results(
        f"Updated {KV_COLLECTION_NAME}: added {len(added_scanners)} scanner(s), removed {len(removed_scanners)} scanner(s)."
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
