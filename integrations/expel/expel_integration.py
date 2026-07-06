import json
import re
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, List, Set, Tuple
from urllib.parse import quote, urlparse

import requests


"""Disable Secure Warning"""


#Creating the client class to handle all API interactions.
"""Client Class"""

class Client(BaseClient):
    """
    Client for Expel Workbench API.
    """

    def __init__(self, api_key: str, base_url: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        self.api_key = api_key

        if self.api_key:
            self._headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

    def get_investigations(self, params: Optional[Dict[str, Any]] = None):
        """
        Fetches a list of expel investigations.
        """
        return self._http_request(
            method='GET',
            url_suffix='investigations',
            headers=self._headers,
            params=params,
        )

    def get_investigation_details(self, id, relation=None, params: Optional[Dict[str, Any]] = None):
        """
        Fetches details about the specified investigation.
        """
        self.id = id
        investigation_id = _safe_path_segment(id, "id")

        if relation:
            self.relation = relation
            relation_segment = _safe_path_segment(relation, "relation")

            return self._http_request(
                method='GET',
                url_suffix=f'investigations/{investigation_id}/{relation_segment}',
                params=params,
            )

        else:

            return self._http_request(method='GET', url_suffix=f'investigations/{investigation_id}', params=params)

    def get_alerts(self, params: Optional[Dict[str, Any]] = None):
        """
        Fetches a list of expel alerts.
        """
        return self._http_request(method='GET', url_suffix='expel_alerts', params=params)

    def get_alert_details(self, id, relation=None, params: Optional[Dict[str, Any]] = None):
        """
        Fetches the details of the specified alert.
        """
        self.id = id
        alert_id = _safe_path_segment(id, "id")

        if relation:
            self.relation = relation
            relation_segment = _safe_path_segment(relation, "relation")

            return self._http_request(
                method='GET',
                url_suffix=f'expel_alerts/{alert_id}/{relation_segment}',
                params=params,
            )

        else:

            return self._http_request(method='GET', url_suffix=f'expel_alerts/{alert_id}', params=params)

    def post_context_upload(self, data):
        """
        Uploads context to our Expel workbench instance in the form of JSON Objects
        """
        body = {
            "data": data
        }

        return self._http_request(method='POST', url_suffix='context_variables/actions/upload/single', json_data=body)

    def patch_context_update(self, context_id: str, data: Dict[str, Any]):
        """
        Updates a context variable, its categories, and related context label tags.
        """
        context_id_segment = _safe_path_segment(context_id, "context_id")
        body = {"data": data}
        return self._http_request(
            method="PATCH",
            url_suffix=f"context_variables/actions/update/{context_id_segment}",
            json_data=body,
        )

    def delete_context_variable(self, context_id: str):
        """
        Deletes a context variable and associated labels (if allowed by API).
        """
        context_id_segment = _safe_path_segment(context_id, "context_id")
        return self._http_request(
            method="DELETE",
            url_suffix=f"context_variables/actions/delete/{context_id_segment}",
        )

    def get_alert_count_by_severity(self, params: Optional[Dict[str, Any]] = None):
        """
        Fetches alert counts by severity.
        """
        return self._http_request(
            method="GET",
            url_suffix="expel_alerts/alert_count_by_severity",
            params=params,
        )

    def get_investigation_history_timeline(self, investigation_id: str):
        """
        Fetches investigation history timeline entries.
        """
        investigation_id_segment = _safe_path_segment(investigation_id, "investigation_id")
        return self._http_request(
            method="GET",
            url_suffix=f"investigations/{investigation_id_segment}/history_timeline",
        )

    def get_alert_history_timeline(self, alert_id: str):
        """
        Fetches expel alert history timeline entries.
        """
        alert_id_segment = _safe_path_segment(alert_id, "alert_id")
        return self._http_request(
            method="GET",
            url_suffix=f"expel_alerts/{alert_id_segment}/history_timeline",
        )

    def get_remediation_actions(self, investigation_id: str, params: Optional[Dict[str, Any]] = None):
        """
        Fetches remediation actions related to an investigation.
        """
        investigation_id_segment = _safe_path_segment(investigation_id, "investigation_id")
        return self._http_request(
            method="GET",
            url_suffix=f"investigations/{investigation_id_segment}/remediation_actions",
            headers=self._headers,
            params=params,
        )

    def search_events(self, params: Dict[str, Any]):
        """
        Performs an event search.
        """
        return self._http_request(
            method="GET",
            url_suffix="events/search",
            params=params,
        )

    def get_health(self, auth: bool = False, heartbeat: bool = False, params: Optional[Dict[str, Any]] = None):
        """
        Gets Workbench API health status.
        """
        if heartbeat:
            url_suffix = "health/heartbeat"
        elif auth:
            url_suffix = "auth_health"
        else:
            url_suffix = "health"

        return self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
        )

    def get_info(self):
        """
        Gets Workbench API info.
        """
        return self._http_request(
            method="GET",
            url_suffix="info",
        )

    def get_incident_investigations(
        self,
        since: str,
        limit: int = 50,
        offset: int = 0,
        time_field: str = "created_at",
    ):
        """
        Fetch investigations that are incidents (is_incident=true) updated/created since a given timestamp.
        """
        filters = {
            time_field: f"\u2265{since}",
            "is_incident": "true",
        }
        # Leave scope unfiltered here; combining open and closed scopes can
        # collapse into an empty result set depending on Expel's scope handling.
        args = {
            "limit": limit,
            "offset": offset,
            "sort": f"{time_field},id",
            "filter": filters,
        }
        params = _build_list_params(args)

        demisto.debug(f"fetch-incidents params: {params}")

        return self._http_request(
            method="GET",
            url_suffix="investigations",
            headers=self._headers,
            params=params,
        )


"""Testing Functions"""

def test_module(client: Client) -> str:
    """
    Tests connectivity to the Expel Workbench API.
    """
    try:
        client.get_investigations()
        return 'ok'
    except Exception as e:
        return f'Test failed. Error: {_sanitize_error_text(e, secret_values=[client.api_key])}'



"""Command Functions"""
#These functions are used to interact with the API response data.

SEVERITY_MAP = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

ALLOWED_INVESTIGATION_RELATIONS: Set[str] = {
    "analyst_activity_timeline",
    "assigned_to_actor",
    "close_comment_updated_by",
    "comment_histories",
    "comments",
    "context_label_action_histories",
    "context_label_actions",
    "context_labels",
    "created_by",
    "destination_ip_addresses",
    "emerging_threat_scan_result",
    "escalated_expel_alerts",
    "evidence",
    "expel_alert_histories",
    "expel_alerts",
    "files",
    "findings",
    "hunt_technique",
    "investigation_finding_histories",
    "investigation_histories",
    "investigation_resilience_actions",
    "investigative_action_histories",
    "investigative_actions",
    "ip_addresses",
    "last_published_by",
    "lead_description_updated_by",
    "lead_expel_alert",
    "lookback_result",
    "most_recent_investigative_action",
    "organization",
    "organization_resilience_action_hints",
    "organization_resilience_actions",
    "related_investigations_via_involved_host_ips",
    "remediation_action_asset_histories",
    "remediation_action_assets",
    "remediation_action_histories",
    "remediation_actions",
    "review_requested_by",
    "source_ip_addresses",
    "status_last_up",
    "status_last_updated_by",
}

ALLOWED_ALERT_RELATIONS: Set[str] = {
    "analyst_activity_timeline",
    "vendor",
    "investigation",
    "organization",
    "assigned_to_actor",
    "similar_alerts",
    "status_last_updated_by",
    "hunting_investigation",
    "hunting_investigation_finding",
    "created_by",
    "updated_by",
    "close_comment_updated_by",
    "context_labels",
    "evidence",
    "expel_alert_histories",
    "expel_alert_view_histories",
    "expel_alert_assignable_expel_user_view_histories",
    "expel_alert_rapid_triage_priority_histories",
    "suppression_histories",
    "source_ip_addresses",
    "destination_ip_addresses",
    "suggestions",
    "vendor_alerts",
    "related_investigations",
    "investigative_actions",
    "investigative_action_histories",
    "related_investigations_via_involved_host_ips",
    "originated_context_labels",
    "phishing_submissions",
    "user_tasks",
}

MAX_FETCH_INCIDENTS = 200
MAX_TRACKED_FETCH_IDS = 10000
MAX_REMEDIATION_ACTIONS = 100
MAX_REMEDIATION_TEXT_LENGTH = 1000
MAX_REMEDIATION_FIELD_LENGTH = 15000
MAX_REMEDIATION_CHECKLIST_LENGTH = 15000
DEFAULT_PAGERDUTY_SEARCH_DAYS = 365
DEFAULT_PAGERDUTY_SEARCH_LIMIT = 200
DEFAULT_MIRROR_TIME_FIELD = "updated_at"
MIRRORABLE_TIME_FIELDS: Tuple[str, ...] = (
    "updated_at",
    "status_updated_at",
    "is_incident_status_updated_at",
)
PAGERDUTY_FETCH_STATUSES = "triggered,acknowledged,resolved"
PAGERDUTY_LINK_FIELD_MAP = {
    "pagerdutyincidentid": "pagerdutyincidentid",
    "pagerdutydedupkey": "pagerdutydedupkey",
    "pagerdutyincidenturl": "pagerdutyincidenturl",
    "pagerdutystatus": "pagerdutystatus",
    "pagerdutyservicename": "pagerdutyservicename",
}
REMEDIATION_CLOSED_STATUSES = {
    "closed",
    "complete",
    "completed",
    "done",
    "fixed",
    "mitigated",
    "resolved",
}
BEARER_TOKEN_RE = re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*")

def _to_xsoar_severity(expel_analyst_severity: str) -> int:
    if not expel_analyst_severity:
        return 0
    return SEVERITY_MAP.get(expel_analyst_severity.upper(), 0)


def _normalize_single_value(value: Any, arg_name: str, allow_empty: bool = False) -> Optional[str]:
    if isinstance(value, list):
        if len(value) != 1:
            raise DemistoException(f'{arg_name} must contain exactly one value.')
        value = value[0]
    if value is None:
        return None if allow_empty else ""
    value_str = str(value).strip()
    if not value_str and not allow_empty:
        raise DemistoException(f'{arg_name} cannot be empty.')
    return value_str or None


def _validate_allowed_value(value: Any, arg_name: str, allowed_values: Set[str]) -> Optional[str]:
    value_str = _normalize_single_value(value, arg_name, allow_empty=True)
    if not value_str:
        return None
    if value_str not in allowed_values:
        raise DemistoException(
            f'{arg_name} must be one of the supported values: {", ".join(sorted(allowed_values))}.'
        )
    return value_str


def _truncate_text(value: Any, limit: int) -> Optional[str]:
    if value is None:
        return None
    value_str = str(value)
    if len(value_str) <= limit:
        return value_str
    return f"{value_str[:limit]}..."


def _sanitize_error_text(value: Any, secret_values: Optional[List[str]] = None) -> str:
    text = str(value)
    text = BEARER_TOKEN_RE.sub("Bearer [REDACTED]", text)
    for secret in secret_values or []:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def _validate_base_url(base_url: Any) -> str:
    url = _normalize_single_value(base_url, "url")
    if not url:
        raise DemistoException("url cannot be empty.")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise DemistoException("url must use https.")
    if not parsed.netloc:
        raise DemistoException("url must include a valid host.")
    if parsed.username or parsed.password:
        raise DemistoException("url must not contain embedded credentials.")
    if parsed.query or parsed.fragment:
        raise DemistoException("url must not contain query strings or fragments.")
    return url.rstrip("/") + "/"

def _parse_json_arg(value: Any, arg_name: str) -> Dict[str, Any]:
    if value is None or value == "":
        return {}
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except Exception as exc:
        raise DemistoException(f'Failed parsing "{arg_name}" as JSON: {exc}') from exc


def _parse_iso8601(value: str, arg_name: str) -> datetime:
    if not value:
        raise DemistoException(f'{arg_name} cannot be empty.')
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except Exception as exc:
        raise DemistoException(f'{arg_name} must be ISO 8601 (e.g., 2024-01-01T00:00:00Z).') from exc


def _parse_first_fetch(first_fetch: str) -> str:
    try:
        return parse_date_range(first_fetch)[0]
    except Exception as exc:
        raise DemistoException(f"Could not parse first_fetch value: {first_fetch}") from exc


def _to_datetime(value: Any, arg_name: str) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        dt = _parse_iso8601(value, arg_name)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise DemistoException(f"{arg_name} must be a datetime or ISO 8601 string.")


def _to_iso8601_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_path_segment(value: Any, arg_name: str) -> str:
    if value is None:
        raise DemistoException(f'{arg_name} cannot be empty.')
    value_str = str(value).strip()
    if not value_str:
        raise DemistoException(f'{arg_name} cannot be empty.')
    return quote(value_str, safe="")


def _serialize_remediation_actions(remediation_actions: List[Dict[str, Any]], truncated: bool) -> str:
    payload = {
        "count": len(remediation_actions),
        "truncated": truncated,
        "actions": remediation_actions,
    }
    serialized = json.dumps(payload, default=str, indent=2)
    if len(serialized) <= MAX_REMEDIATION_FIELD_LENGTH:
        return serialized

    reduced_payload = dict(payload)
    reduced_payload["actions"] = [
        {
            "id": action.get("id"),
            "action": action.get("action"),
            "action_type": action.get("action_type"),
            "status": action.get("status"),
            "updated_at": action.get("updated_at"),
        }
        for action in remediation_actions
    ]
    return json.dumps(reduced_payload, default=str, indent=2)


def _normalize_status_token(value: Any) -> str:
    if value is None:
        return ""
    normalized = re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower())
    return normalized.strip("_")


def _is_closed_remediation(action: Dict[str, Any]) -> bool:
    normalized_status = _normalize_status_token(action.get("status"))
    if not normalized_status:
        return False
    return normalized_status in REMEDIATION_CLOSED_STATUSES or normalized_status.startswith("closed_")


def _build_remediation_summary(remediation_actions: List[Dict[str, Any]], truncated: bool) -> Dict[str, Any]:
    open_count = 0
    closed_count = 0
    checklist_lines: List[str] = []

    for action in remediation_actions:
        is_closed = _is_closed_remediation(action)
        if is_closed:
            closed_count += 1
        else:
            open_count += 1

        marker = "x" if is_closed else " "
        title = (
            action.get("action")
            or action.get("template_name")
            or action.get("action_type")
            or f"Remediation {action.get('id') or ''}".strip()
        )
        details = [
            f"Status: {action.get('status') or 'unknown'}",
            f"ID: {action.get('id') or 'unknown'}",
        ]
        if action.get("action_type"):
            details.append(f"Type: {action.get('action_type')}")
        if action.get("asset_count") not in (None, ""):
            details.append(f"Assets: {action.get('asset_count')}")
        if action.get("updated_at"):
            details.append(f"Updated: {action.get('updated_at')}")
        checklist_lines.append(f"[{marker}] {title} | {' | '.join(details)}")

    summary_lines = [
        f"Total remediations: {len(remediation_actions)}",
        f"Open remediations: {open_count}",
        f"Completed remediations: {closed_count}",
    ]
    if checklist_lines:
        summary_lines.append("")
        summary_lines.extend(checklist_lines)
    if truncated:
        summary_lines.extend(("", "Additional remediation actions were truncated."))

    checklist = "\n".join(summary_lines)
    if len(checklist) > MAX_REMEDIATION_CHECKLIST_LENGTH:
        checklist = _truncate_text(checklist, MAX_REMEDIATION_CHECKLIST_LENGTH) or ""

    return {
        "checklist": checklist,
        "total_count": len(remediation_actions),
        "open_count": open_count,
        "closed_count": closed_count,
        "has_open_remediations": open_count > 0,
    }


def _fetch_remediation_actions(client: Client, investigation_id: str) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Fetch all remediation actions for an investigation.
    """
    remediation_actions: List[Dict[str, Any]] = []
    page_size = 50
    offset = 0
    truncated = False

    try:
        while True:
            response = client.get_remediation_actions(
                investigation_id=investigation_id,
                params={
                    "page[limit]": page_size,
                    "page[offset]": offset,
                    "sort": "created_at,id",
                },
            )
            data = response.get("data") or []
            if isinstance(data, dict):
                data = [data]
            page_items = [item for item in data if isinstance(item, dict)]

            for item in page_items:
                attrs = item.get("attributes") or {}
                relationships = item.get("relationships") or {}
                assets_relation = relationships.get("remediation_action_assets") or {}
                asset_data = assets_relation.get("data") or []
                if isinstance(asset_data, dict):
                    asset_count = 1
                elif isinstance(asset_data, list):
                    asset_count = len(asset_data)
                else:
                    asset_count = 0

                remediation_actions.append({
                    "id": item.get("id"),
                    "type": item.get("type"),
                    "action": _truncate_text(attrs.get("action"), MAX_REMEDIATION_TEXT_LENGTH),
                    "action_type": _truncate_text(attrs.get("action_type"), MAX_REMEDIATION_TEXT_LENGTH),
                    "status": _truncate_text(attrs.get("status"), MAX_REMEDIATION_TEXT_LENGTH),
                    "status_updated_at": attrs.get("status_updated_at"),
                    "created_at": attrs.get("created_at"),
                    "updated_at": attrs.get("updated_at"),
                    "close_reason": _truncate_text(attrs.get("close_reason"), MAX_REMEDIATION_TEXT_LENGTH),
                    "comment": _truncate_text(attrs.get("comment"), MAX_REMEDIATION_TEXT_LENGTH),
                    "template_name": _truncate_text(attrs.get("template_name"), MAX_REMEDIATION_TEXT_LENGTH),
                    "version": _truncate_text(attrs.get("version"), MAX_REMEDIATION_TEXT_LENGTH),
                    "asset_count": asset_count,
                })
                if len(remediation_actions) >= MAX_REMEDIATION_ACTIONS:
                    truncated = True
                    break

            if truncated or len(page_items) < page_size:
                break
            offset += page_size
    except Exception as exc:
        demisto.debug(
            f"Failed to fetch remediation actions for investigation {investigation_id}: "
            f"{_sanitize_error_text(exc, secret_values=[client.api_key])}"
        )

    return remediation_actions, truncated


def _utc_days_ago_iso(days: int) -> str:
    return _to_iso8601_utc(datetime.now(timezone.utc) - timedelta(days=days))


def _normalize_id_list(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            return [value]
        if isinstance(parsed, list):
            return [str(item) for item in parsed if item not in (None, "")]
        return [str(parsed)]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def _append_tracked_id(tracked_ids: List[str], tracked_ids_set: Set[str], value: Optional[str], limit: int) -> None:
    if not value or value in tracked_ids_set:
        return
    tracked_ids.append(value)
    tracked_ids_set.add(value)
    while len(tracked_ids) > limit:
        removed_id = tracked_ids.pop(0)
        tracked_ids_set.discard(removed_id)


def _get_mirror_time_field(configured_time_field: str) -> str:
    if configured_time_field in MIRRORABLE_TIME_FIELDS:
        return configured_time_field
    return DEFAULT_MIRROR_TIME_FIELD


def _get_investigation_modified_time_value(item: Dict[str, Any], time_field: str) -> str:
    attrs = item.get("attributes") or {}
    return (
        attrs.get(time_field)
        or attrs.get("updated_at")
        or attrs.get("status_updated_at")
        or attrs.get("created_at")
        or _to_iso8601_utc(datetime.now(timezone.utc))
    )


def _build_get_modified_remote_data_response(modified_incident_ids: List[str], last_update: str) -> Any:
    response_cls = globals().get("GetModifiedRemoteDataResponse")
    if callable(response_cls):
        for kwargs in (
            {"modified_incident_ids": modified_incident_ids, "last_update": last_update},
            {"modified_incident_ids": modified_incident_ids},
        ):
            try:
                return response_cls(**kwargs)
            except TypeError:
                continue
    return {
        "modified_incident_ids": modified_incident_ids,
        "last_update": last_update,
    }


def _build_get_remote_data_response(
    mirrored_object: Dict[str, Any],
    last_update: str,
    remote_data: Dict[str, Any],
    entries: Optional[List[Dict[str, Any]]] = None,
) -> Any:
    response_cls = globals().get("GetRemoteDataResponse")
    entries = entries or []
    if callable(response_cls):
        for kwargs in (
            {
                "mirrored_object": mirrored_object,
                "last_update": last_update,
                "remote_data": remote_data,
                "entries": entries,
            },
            {
                "mirrored_object": mirrored_object,
                "remote_data": remote_data,
                "entries": entries,
            },
            {
                "mirrored_object": mirrored_object,
                "last_update": last_update,
                "entries": entries,
            },
            {
                "mirrored_object": mirrored_object,
                "entries": entries,
            },
        ):
            try:
                return response_cls(**kwargs)
            except TypeError:
                continue
    return {
        "mirrored_object": mirrored_object,
        "last_update": last_update,
        "remote_data": remote_data,
        "entries": entries,
    }


def _build_xsoar_incident_from_investigation(
    client: Client,
    item: Dict[str, Any],
    incident_type: str,
    time_field: str,
) -> Dict[str, Any]:
    attrs = item.get("attributes") or {}
    incident_id = item.get("id")
    incident_id_str = str(incident_id) if incident_id is not None else ""
    workbench_url = f"https://workbench.expel.io/investigations/{incident_id_str}" if incident_id_str else None
    rel = item.get("relationships") or {}
    org_id = (rel.get("organization") or {}).get("data") or {}
    assigned_actor_id = (rel.get("assigned_to_actor") or {}).get("data") or {}
    created_by_id = (rel.get("created_by") or {}).get("data") or {}
    updated_by_id = (rel.get("updated_by") or {}).get("data") or {}
    lead_desc_updated_by_id = (rel.get("lead_description_updated_by") or {}).get("data") or {}

    created_at = attrs.get("created_at") or ""
    title = attrs.get("title") or f"Expel Investigation {item.get('id')}"
    analyst_sev = attrs.get("analyst_severity") or ""
    time_value = _get_investigation_modified_time_value(item, time_field)
    details = (
        attrs.get("lead_description")
        or attrs.get("open_summary")
        or attrs.get("close_comment")
        or title
    )
    occurred = _to_iso8601_utc(_to_datetime(created_at or time_value, time_field))
    remediation_actions, remediation_truncated = (
        _fetch_remediation_actions(client, incident_id_str) if incident_id_str else ([], False)
    )
    remediation_summary = _build_remediation_summary(remediation_actions, remediation_truncated)
    if remediation_actions:
        details = (
            f"{details}\n\nRemediation actions synced: {len(remediation_actions)}"
            f"{'+' if remediation_truncated else ''}"
            f" (open: {remediation_summary['open_count']}, completed: {remediation_summary['closed_count']})"
        )

    custom_fields = {
        "expelinvestigationid": incident_id,
        "expelshortlink": attrs.get("short_link"),
        "expelworkbenchurl": workbench_url,
        "expelcreatedat": attrs.get("created_at"),
        "expelupdatedat": attrs.get("updated_at"),
        "expelstatusupdatedat": attrs.get("status_updated_at"),
        "expelisincidentstatusupdatedat": attrs.get("is_incident_status_updated_at"),
        "expeldeletedat": attrs.get("deleted_at"),
        "expelanalystseverity": attrs.get("analyst_severity"),
        "expelthreattype": attrs.get("threat_type"),
        "expelattackvector": attrs.get("attack_vector"),
        "expeldetectiontype": attrs.get("detection_type"),
        "expelattacktiming": attrs.get("attack_timing"),
        "expelattacklifecycle": attrs.get("attack_lifecycle"),
        "expelmalwarefamilycf": attrs.get("malware_family"),
        "expelinitialattackvector": attrs.get("initial_attack_vector"),
        "expelleaddescription": attrs.get("lead_description"),
        "expeldecision": attrs.get("decision"),
        "expelclosecomment": attrs.get("close_comment"),
        "expelcriticalcomment": attrs.get("critical_comment"),
        "expelopensummary": attrs.get("open_summary"),
        "expelopenreason": attrs.get("open_reason"),
        "expelnextstepscf": attrs.get("next_steps"),
        "expelsourcereason": attrs.get("source_reason"),
        "expeldefaultpluginslug": attrs.get("default_plugin_slug"),
        "expelorgid": org_id.get("id"),
        "expelassignedactorid": assigned_actor_id.get("id"),
        "expelcreatedbyactorid": created_by_id.get("id"),
        "expelupdatedbyactorid": updated_by_id.get("id"),
        "expelleaddescupdatedbyactorid": lead_desc_updated_by_id.get("id"),
        "expelremediationactions": _serialize_remediation_actions(
            remediation_actions,
            remediation_truncated,
        ),
        "expelremediationchecklist": remediation_summary["checklist"],
        "expelremediationcount": str(remediation_summary["total_count"]),
        "expelopenremediationcount": str(remediation_summary["open_count"]),
        "expelclosedremediationcount": str(remediation_summary["closed_count"]),
    }

    clean_custom_fields = {
        k: v if isinstance(v, str) else str(v)
        for k, v in custom_fields.items()
        if v is not None
    }

    raw_item = dict(item)
    if workbench_url:
        raw_item["workbench_url"] = workbench_url
    raw_item["remediation_actions"] = {
        "count": len(remediation_actions),
        "truncated": remediation_truncated,
        "actions": remediation_actions,
        "summary": {
            "total_count": remediation_summary["total_count"],
            "open_count": remediation_summary["open_count"],
            "closed_count": remediation_summary["closed_count"],
            "has_open_remediations": remediation_summary["has_open_remediations"],
        },
    }

    return {
        "name": title,
        "details": details,
        "occurred": occurred,
        "type": incident_type,
        "severity": _to_xsoar_severity(analyst_sev),
        "dbotMirrorId": incident_id_str or None,
        "CustomFields": clean_custom_fields,
        "rawJSON": json.dumps(raw_item, default=str),
    }


def _build_set_incident_args_from_mirrored_object(mirrored_object: Dict[str, Any]) -> Dict[str, Any]:
    set_incident_args: Dict[str, Any] = {
        "name": mirrored_object.get("name"),
        "details": mirrored_object.get("details"),
        "severity": mirrored_object.get("severity"),
    }
    for field_name, field_value in (mirrored_object.get("CustomFields") or {}).items():
        set_incident_args[field_name] = field_value
    return set_incident_args


def _build_incident_sync_payload(mirrored_object: Dict[str, Any]) -> Dict[str, Any]:
    custom_fields = mirrored_object.get("CustomFields") or {}
    payload = {
        "InvestigationID": str(custom_fields.get("expelinvestigationid") or mirrored_object.get("dbotMirrorId") or ""),
        "name": mirrored_object.get("name"),
        "details": mirrored_object.get("details"),
        "severity": mirrored_object.get("severity"),
        "occurred": mirrored_object.get("occurred"),
        "dbotMirrorId": mirrored_object.get("dbotMirrorId"),
        "custom_fields": custom_fields,
    }
    return {key: value for key, value in payload.items() if value not in (None, "", [], {})}


def _get_platform_command_executor():
    executor = getattr(demisto, "executeCommand", None)
    if callable(executor):
        return executor
    return None


def _platform_commands_supported() -> bool:
    return _get_platform_command_executor() is not None


def _set_current_incident_fields(set_incident_args: Dict[str, Any]) -> List[str]:
    skipped_fields: List[str] = []
    system_args = {
        field_name: field_value
        for field_name, field_value in set_incident_args.items()
        if field_name in {"name", "details", "severity"}
    }
    custom_field_args = {
        field_name: field_value
        for field_name, field_value in set_incident_args.items()
        if field_name not in system_args
    }

    if system_args:
        _execute_platform_command("setIncident", system_args)

    for field_name, field_value in custom_field_args.items():
        try:
            _execute_platform_command("setIncident", {field_name: field_value})
        except DemistoException as exc:
            skipped_fields.append(field_name)
            demisto.debug(
                f'Skipping incident field "{field_name}" during sync: '
                f'{_sanitize_error_text(exc, secret_values=[str(field_value)])}'
            )

    return skipped_fields


def _sync_current_incident_from_investigation(
    client: Client,
    item: Dict[str, Any],
    incident_type: str,
    time_field: str,
) -> List[str]:
    mirrored_object = _build_xsoar_incident_from_investigation(
        client=client,
        item=item,
        incident_type=incident_type,
        time_field=time_field,
    )
    return _set_current_incident_fields(_build_set_incident_args_from_mirrored_object(mirrored_object))


def get_modified_remote_data_command(client: Client, last_update: str, first_fetch: str, fetch_time_field: str) -> Any:
    mirror_time_field = _get_mirror_time_field(fetch_time_field)
    since = last_update or _parse_first_fetch(first_fetch)
    try:
        since_dt = _to_datetime(since, "last_update")
    except Exception:
        since = _parse_first_fetch(first_fetch)
        since_dt = _to_datetime(since, "last_update")
    since_str = _to_iso8601_utc(since_dt)

    fetched_ids_set = set(_normalize_id_list(demisto.getLastRun().get("fetched_ids")))
    modified_ids: List[str] = []
    modified_ids_set: Set[str] = set()
    offset = 0
    page_size = 50
    newest_dt = since_dt

    while True:
        response = client.get_incident_investigations(
            since=since_str,
            limit=page_size,
            offset=offset,
            time_field=mirror_time_field,
        )
        data = response.get("data") or []
        if not data:
            break

        for item in data:
            incident_id = item.get("id")
            incident_id_str = str(incident_id) if incident_id is not None else ""
            if not incident_id_str:
                continue

            modified_dt = _to_datetime(
                _get_investigation_modified_time_value(item, mirror_time_field),
                mirror_time_field,
            )
            if modified_dt > newest_dt:
                newest_dt = modified_dt

            if fetched_ids_set and incident_id_str not in fetched_ids_set:
                continue
            if incident_id_str not in modified_ids_set:
                modified_ids.append(incident_id_str)
                modified_ids_set.add(incident_id_str)

        if len(data) < page_size:
            break
        offset += page_size

    return _build_get_modified_remote_data_response(
        modified_incident_ids=modified_ids,
        last_update=_to_iso8601_utc(newest_dt),
    )


def get_remote_data_command(client: Client, remote_id: str, incident_type: str, fetch_time_field: str) -> Any:
    if not remote_id:
        raise DemistoException("the remote incident id cannot be empty.")

    response = client.get_investigation_details(remote_id)
    item = response.get("data") or {}
    if not isinstance(item, dict) or not item:
        raise DemistoException(f"Expel investigation {remote_id} was not found.")

    mirror_time_field = _get_mirror_time_field(fetch_time_field)
    mirrored_object = _build_xsoar_incident_from_investigation(
        client=client,
        item=item,
        incident_type=incident_type,
        time_field=mirror_time_field,
    )
    remote_data = json.loads(mirrored_object["rawJSON"])
    last_update = _to_iso8601_utc(
        _to_datetime(_get_investigation_modified_time_value(item, mirror_time_field), mirror_time_field)
    )
    return _build_get_remote_data_response(
        mirrored_object=mirrored_object,
        last_update=last_update,
        remote_data=remote_data,
        entries=[],
    )


def _get_current_incident_value(field_name: str) -> Optional[str]:
    incident = demisto.incident() or {}
    custom_fields = incident.get("CustomFields") or incident.get("customFields") or {}
    value = custom_fields.get(field_name)
    if value in (None, ""):
        value = incident.get(field_name)
    if value in (None, ""):
        return None
    return str(value)


def _execute_platform_command(command: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
    sanitized_args = {k: v for k, v in args.items() if v not in (None, "", [], {})}
    executor = _get_platform_command_executor()
    if executor is None:
        raise DemistoException(
            "Platform command execution is unavailable in the current integration runtime. "
            "This XSOAR server cannot run setIncident from an integration command."
        )
    try:
        result = executor(command, sanitized_args)
    except Exception as exc:
        raise DemistoException(
            f'{command} raised an exception: '
            f'{_sanitize_error_text(exc, secret_values=[str(v) for v in sanitized_args.values()])}'
        ) from exc
    if isError(result):
        raise DemistoException(
            f'{command} failed: {_sanitize_error_text(get_error(result), secret_values=[str(v) for v in sanitized_args.values()])}'
        )
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        return [result]
    raise DemistoException(f"{command} returned an unsupported response type.")


def _extract_first_entry_contents(command_results: List[Dict[str, Any]]) -> Any:
    for entry in command_results:
        if entry.get("Type") == entryTypes.get("error"):
            continue
        if "Contents" in entry:
            return entry.get("Contents")
    return None


def _extract_pagerduty_incident_from_results(command_results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    contents = _extract_first_entry_contents(command_results)
    if isinstance(contents, list):
        for item in contents:
            if isinstance(item, dict):
                return item
    if isinstance(contents, dict):
        incident = contents.get("incident")
        if isinstance(incident, dict):
            return incident
    return None


def _extract_pagerduty_incidents_from_results(command_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    contents = _extract_first_entry_contents(command_results)
    if isinstance(contents, list):
        return [item for item in contents if isinstance(item, dict)]
    if isinstance(contents, dict):
        if isinstance(contents.get("incidents"), list):
            return [item for item in contents.get("incidents", []) if isinstance(item, dict)]
        incident = contents.get("incident")
        if isinstance(incident, dict):
            return [incident]
    return []


def _get_pagerduty_incident_by_id(incident_id: str) -> Dict[str, Any]:
    results = _execute_platform_command("PagerDuty-get-incident-data", {"incident_id": incident_id})
    incident = _extract_pagerduty_incident_from_results(results)
    if not incident:
        raise DemistoException(f"PagerDuty incident {incident_id} was not found.")
    return incident


def _get_pagerduty_incident_by_key(incident_key: str) -> Optional[Dict[str, Any]]:
    results = _execute_platform_command(
        "PagerDuty-incidents",
        {
            "incident_key": incident_key,
            "status": PAGERDUTY_FETCH_STATUSES,
            "limit": 1,
        },
    )
    return _extract_pagerduty_incident_from_results(results)


def _get_expel_pagerduty_search_terms() -> List[str]:
    search_terms: List[str] = []
    for value in (
        _get_current_incident_value("expelinvestigationid"),
        _get_current_incident_value("expelshortlink"),
        _get_current_incident_value("dbotMirrorId"),
    ):
        if not value:
            continue
        normalized_value = str(value).strip()
        if normalized_value and normalized_value not in search_terms:
            search_terms.append(normalized_value)
    return search_terms


def _stringify_pagerduty_details(details: Any) -> str:
    if isinstance(details, str):
        return details
    if details in (None, "", [], {}):
        return ""
    try:
        return json.dumps(details, default=str)
    except Exception:
        return str(details)


def _score_pagerduty_incident_match(incident: Dict[str, Any], search_terms: List[str]) -> Tuple[int, str]:
    incident_key = str(incident.get("incident_key") or "")
    summary = str(incident.get("summary") or "")
    details = _stringify_pagerduty_details(
        (((incident.get("first_trigger_log_entry") or {}).get("channel") or {}).get("details"))
    )
    combined_text = " ".join(part for part in (summary, details) if part).lower()

    best_score = 0
    best_reason = ""
    for term in search_terms:
        term_lc = term.lower()
        if incident_key and incident_key.lower() == term_lc:
            return 100, f'incident_key matched "{term}"'
        if summary and term_lc in summary.lower():
            score = 90
            reason = f'summary contained "{term}"'
        elif details and term_lc in details.lower():
            score = 80
            reason = f'details contained "{term}"'
        elif combined_text and term_lc in combined_text:
            score = 70
            reason = f'pagerduty incident contained "{term}"'
        else:
            continue

        if score > best_score:
            best_score = score
            best_reason = reason

    return best_score, best_reason


def _find_pagerduty_incident_for_current_expel(search_terms: List[str]) -> Optional[Tuple[Dict[str, Any], str]]:
    for term in search_terms:
        direct_match = _get_pagerduty_incident_by_key(term)
        if direct_match:
            return direct_match, f'incident_key matched "{term}"'

    results = _execute_platform_command(
        "PagerDuty-incidents",
        {
            "since": _utc_days_ago_iso(DEFAULT_PAGERDUTY_SEARCH_DAYS),
            "status": PAGERDUTY_FETCH_STATUSES,
            "limit": DEFAULT_PAGERDUTY_SEARCH_LIMIT,
        },
    )
    incidents = _extract_pagerduty_incidents_from_results(results)
    if not incidents:
        return None

    scored_matches: List[Tuple[int, str, Dict[str, Any]]] = []
    for incident in incidents:
        score, reason = _score_pagerduty_incident_match(incident, search_terms)
        if score > 0:
            scored_matches.append((score, reason, incident))

    if not scored_matches:
        return None

    scored_matches.sort(
        key=lambda item: (
            item[0],
            str(item[2].get("last_status_change_at") or item[2].get("created_at") or ""),
        ),
        reverse=True,
    )
    top_score = scored_matches[0][0]
    top_matches = [match for match in scored_matches if match[0] == top_score]
    if len(top_matches) > 1:
        candidate_ids = [str(match[2].get("id") or "") for match in top_matches[:5]]
        raise DemistoException(
            "Multiple PagerDuty incidents matched the current Expel investigation references. "
            f"Provide pagerduty_incident_id or pagerduty_incident_key explicitly. Candidates: {', '.join(candidate_ids)}"
        )

    best_score, best_reason, best_incident = scored_matches[0]
    if best_score < 80:
        return None
    return best_incident, best_reason


def _set_pagerduty_link_fields(pagerduty_incident: Dict[str, Any]) -> None:
    service = pagerduty_incident.get("service") or {}
    set_incident_args = {
        PAGERDUTY_LINK_FIELD_MAP["pagerdutyincidentid"]: pagerduty_incident.get("id"),
        PAGERDUTY_LINK_FIELD_MAP["pagerdutydedupkey"]: pagerduty_incident.get("incident_key"),
        PAGERDUTY_LINK_FIELD_MAP["pagerdutyincidenturl"]: pagerduty_incident.get("html_url"),
        PAGERDUTY_LINK_FIELD_MAP["pagerdutystatus"]: pagerduty_incident.get("status"),
        PAGERDUTY_LINK_FIELD_MAP["pagerdutyservicename"]: service.get("summary") or service.get("name"),
    }
    _execute_platform_command("setIncident", set_incident_args)


def link_pagerduty_incident_command(args: Dict[str, Any]) -> CommandResults:
    pagerduty_incident_id = _normalize_single_value(args.get("pagerduty_incident_id"), "pagerduty_incident_id", allow_empty=True)
    pagerduty_incident_key = _normalize_single_value(args.get("pagerduty_incident_key"), "pagerduty_incident_key", allow_empty=True)
    existing_pagerduty_incident_id = _get_current_incident_value("pagerdutyincidentid")
    existing_dedup_key = _get_current_incident_value("pagerdutydedupkey")
    search_reason = ""
    link_notice = ""

    pagerduty_incident: Optional[Dict[str, Any]] = None
    if pagerduty_incident_id:
        pagerduty_incident = _get_pagerduty_incident_by_id(pagerduty_incident_id)
        search_reason = f'pagerduty_incident_id matched "{pagerduty_incident_id}"'
    elif pagerduty_incident_key:
        pagerduty_incident = _get_pagerduty_incident_by_key(pagerduty_incident_key)
        if not pagerduty_incident:
            raise DemistoException(f'PagerDuty incident key "{pagerduty_incident_key}" was not found.')
        search_reason = f'pagerduty_incident_key matched "{pagerduty_incident_key}"'
    elif existing_pagerduty_incident_id:
        pagerduty_incident = _get_pagerduty_incident_by_id(existing_pagerduty_incident_id)
        search_reason = f'existing PagerDuty incident ID "{existing_pagerduty_incident_id}" was refreshed'
    elif existing_dedup_key:
        pagerduty_incident = _get_pagerduty_incident_by_key(existing_dedup_key)
        if pagerduty_incident:
            search_reason = f'existing PagerDuty dedup key "{existing_dedup_key}" was refreshed'

    if not pagerduty_incident:
        search_terms = _get_expel_pagerduty_search_terms()
        if search_terms:
            auto_match = _find_pagerduty_incident_for_current_expel(search_terms)
            if auto_match:
                pagerduty_incident, search_reason = auto_match

    if not pagerduty_incident:
        search_terms = _get_expel_pagerduty_search_terms()
        search_hint = ", ".join(search_terms) if search_terms else "none"
        return CommandResults(
            readable_output=(
                "No PagerDuty action taken. "
                f'No existing PagerDuty incident matched the Expel references: {search_hint}. '
                "Provide pagerduty_incident_id or pagerduty_incident_key explicitly if needed."
            ),
            outputs_prefix="Expel.PagerDutyLink",
            outputs={
                "Linked": False,
                "SearchTerms": search_terms,
            },
        )

    if _platform_commands_supported():
        _set_pagerduty_link_fields(pagerduty_incident)
    else:
        link_notice = (
            "Current incident fields were not updated because this XSOAR integration runtime "
            "does not support setIncident from integration commands."
        )
    service = pagerduty_incident.get("service") or {}
    output = {
        "Linked": True,
        "UpdatedIncidentFields": not bool(link_notice),
        "IncidentID": pagerduty_incident.get("id"),
        "IncidentKey": pagerduty_incident.get("incident_key"),
        "Status": pagerduty_incident.get("status"),
        "HtmlUrl": pagerduty_incident.get("html_url"),
        "ServiceName": service.get("summary") or service.get("name"),
        "SearchReason": search_reason,
    }
    readable_output = tableToMarkdown("PagerDuty Link", [output], removeNull=True)
    if link_notice:
        readable_output = f"{readable_output}\n\n{link_notice}"
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Expel.PagerDutyLink",
        outputs_key_field="IncidentID",
        outputs=output,
        raw_response=pagerduty_incident,
    )


def _normalize_filter_value(value: Any) -> Any:
    if isinstance(value, str):
        if value.startswith(">="):
            return f"\u2265{value[2:]}"
        if value.startswith("<="):
            return f"\u2264{value[2:]}"
    return value


def _add_nested_params(params: Dict[str, Any], prefix: str, obj: Dict[str, Any]) -> None:
    for key, value in obj.items():
        if isinstance(value, dict):
            _add_nested_params(params, f"{prefix}[{key}]", value)
        else:
            if prefix.startswith("filter"):
                value = _normalize_filter_value(value)
            params[f"{prefix}[{key}]"] = value


def _build_list_params(args: Dict[str, Any], default_filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    params: Dict[str, Any] = {}

    include = args.get("include")
    sort = args.get("sort")
    limit = arg_to_number(args.get("limit")) if args.get("limit") is not None else None
    offset = arg_to_number(args.get("offset")) if args.get("offset") is not None else None

    if include:
        if not str(include).strip():
            raise DemistoException("include cannot be empty when provided.")
        params["include"] = include
    if sort:
        if not str(sort).strip():
            raise DemistoException("sort cannot be empty when provided.")
        params["sort"] = sort
    if limit is not None:
        if limit < 0:
            raise DemistoException("limit must be a non-negative integer.")
        params["page[limit]"] = limit
    if offset is not None:
        if offset < 0:
            raise DemistoException("offset must be a non-negative integer.")
        params["page[offset]"] = offset

    filter_arg = args.get("filter")
    if filter_arg:
        filters = _parse_json_arg(filter_arg, "filter")
    else:
        filters = default_filters or {}

    if filters and not isinstance(filters, dict):
        raise DemistoException('filter must be a JSON object.')

    if filters:
        _add_nested_params(params, "filter", filters)

    flag_arg = args.get("flag")
    if flag_arg:
        flags = _parse_json_arg(flag_arg, "flag")
        if flags and not isinstance(flags, dict):
            raise DemistoException('flag must be a JSON object.')
        if flags:
            _add_nested_params(params, "flag", flags)

    return params


def get_investigations_command(client: Client) -> CommandResults:
    """
    Cortex XSOAR command to get Expel investigations.
    """
    demisto.log('Fetching investigations...')
    params = _build_list_params(
        demisto.args(),
        default_filters={"created_at": f"\u2265{_utc_days_ago_iso(7)}"},
    )
    response = client.get_investigations(params=params)

    if response is None:
        raise DemistoException(f'Request failed: the response from the server did not include {response}')

    jdata = response.get("data") or []

    # Empty list for Investigation objects
    investigations = []

    for i in range(0,len(jdata)):
        investigations.append({"type":jdata[i]["type"], "id":jdata[i]["id"], "title":jdata[i]["attributes"]["title"], "created":jdata[i]["attributes"]["created_at"]})

    # Sorting list by time
    investigations = sorted(investigations, key=lambda x: x['created'], reverse=True)

    # Create a human-readable table
    readable_output = tableToMarkdown(
        name='Expel Investigations',
        t=investigations,
        headers=['type', 'id', 'title', 'created'],
        #headerTransform=string_to_markdown
    )

    # Return the results
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='expel.investigations',
        outputs_key_field='id',
        outputs=investigations,
        raw_response=response
    )

def get_investigation_details_command(
    client: Client,
    id: str,
    relation=None,
    sync_to_incident: bool = False,
    incident_type: str = "Expel Investigation",
    time_field: str = DEFAULT_MIRROR_TIME_FIELD,
) -> CommandResults:
    """
    Cortex XSOAR command to get the specified Expel investigation details.
    """

    if not id:
        raise DemistoException('the id argument cannot be empty.')

    params = _build_list_params(demisto.args())
    relation = _validate_allowed_value(relation, "relation", ALLOWED_INVESTIGATION_RELATIONS)

    if relation:

        demisto.log('Fetching investigation details...')

        response = client.get_investigation_details(id=id, relation=relation, params=params)

        if response is None:
            raise DemistoException(f'Request failed: the response from the server did not include {response}')


        # Create a human-readable table
        readable_output = tableToMarkdown(
            name='Expel Investigation Details',
            t=response.get('data', []),
            headers=['id', 'attributes'],
            #headerTransform=string_to_markdown
        )

        # Return the results
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='Expel.Investigation.Details',
            outputs_key_field='id',
            outputs=response.get('data', []),
            raw_response=response
        )
    #Else statement if the relation argument doesn't exist.
    else:
        demisto.log('Fetching investigation details...')

        response = client.get_investigation_details(id, params=params)

        if response is None:
            raise DemistoException(f'Request failed: the response from the server did not include {response}')

        response_data = response.get("data") or {}
        skipped_sync_fields: List[str] = []
        sync_notice = ""
        if sync_to_incident and isinstance(response_data, dict) and response_data:
            if _platform_commands_supported():
                skipped_sync_fields = _sync_current_incident_from_investigation(
                    client=client,
                    item=response_data,
                    incident_type=incident_type,
                    time_field=_get_mirror_time_field(time_field),
                )
            else:
                sync_notice = (
                    "Direct incident sync was skipped because this XSOAR 6.14 integration runtime "
                    "does not support setIncident from integration commands. "
                    "Use inbound mirroring for automatic Expel updates, or a separate automation "
                    "if you need on-demand incident field synchronization."
                )

        # Create a human-readable table
        readable_output = tableToMarkdown(
            name='Expel Investigation Details',
            t=response.get('data', []),
            headers=['id', 'attributes'],

        )
        if skipped_sync_fields:
            readable_output = (
                f"{readable_output}\n\n"
                "Incident sync skipped unsupported or unavailable fields: "
                f"{', '.join(skipped_sync_fields)}. "
                "Import the latest Expel custom fields if you want these values populated."
            )
        if sync_notice:
            readable_output = f"{readable_output}\n\n{sync_notice}"

    # Return the results
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='Expel.Investigation.Details',
            outputs_key_field='id',
            outputs=response.get('data', []),
            raw_response=response
        )



def get_incident_sync_data_command(
    client: Client,
    id: str,
    incident_type: str = "Expel Investigation",
    time_field: str = DEFAULT_MIRROR_TIME_FIELD,
) -> CommandResults:
    """
    Returns the normalized incident payload for an Expel investigation so an automation
    can apply it to the current XSOAR incident on-demand.
    """
    if not id:
        raise DemistoException('the id argument cannot be empty.')

    response = client.get_investigation_details(id=id, params=_build_list_params(demisto.args()))
    if response is None:
        raise DemistoException(f'Request failed: the response from the server did not include {response}')

    item = response.get("data") or {}
    if not isinstance(item, dict) or not item:
        raise DemistoException(f"Expel investigation {id} was not found.")

    mirrored_object = _build_xsoar_incident_from_investigation(
        client=client,
        item=item,
        incident_type=incident_type,
        time_field=_get_mirror_time_field(time_field),
    )
    payload = _build_incident_sync_payload(mirrored_object)
    summary_row = {
        "InvestigationID": payload.get("InvestigationID"),
        "Name": payload.get("name"),
        "Severity": payload.get("severity"),
        "CustomFieldCount": len(payload.get("custom_fields") or {}),
    }
    return CommandResults(
        readable_output=tableToMarkdown("Expel Investigation Sync Payload", [summary_row], removeNull=True),
        outputs_prefix="Expel.Investigation.SyncPayload",
        outputs_key_field="InvestigationID",
        outputs=payload,
        raw_response={
            "payload": payload,
            "investigation": response,
        },
    )


def get_alerts_command(client: Client) -> CommandResults:
    """
    Cortex XSOAR command to get Expel alerts.
    """

    demisto.log('Fetching alerts...')
    params = _build_list_params(
        demisto.args(),
        default_filters={"created_at": f"\u2265{_utc_days_ago_iso(1)}"},
    )
    response = client.get_alerts(params=params)

    if response is None:
        raise DemistoException(f'Request failed: the response from the server did not include {response}')

    jdata = response.get("data") or []

    # Empty list for alert objects
    alerts = []

    for i in range(0,len(jdata)):
        alerts.append({"type":jdata[i]["type"], "id":jdata[i]["id"], "title":jdata[i]["attributes"]["expel_name"], "created":jdata[i]["attributes"]["created_at"], "severity":jdata[i]["attributes"]["expel_severity"],})

    # Sorting list by time
    alerts = sorted(alerts, key=lambda x: x['created'], reverse=True)

    # Create a human-readable table
    readable_output = tableToMarkdown(
        name='Expel Alerts',
        t=alerts,
        headers=['type', 'id', 'title', 'created', 'severity'],

    )

    # Return the results
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='expel.alerts',
        outputs_key_field='id',
        outputs=alerts,
        raw_response=response,
    )


def get_alert_details_command(client: Client, id: str, relation=None) -> CommandResults:
    """
    Cortex XSOAR command to get the specified Expel investigation details.
    """

    if not id:
        raise DemistoException('the id argument cannot be empty.')

    params = _build_list_params(demisto.args())
    relation = _validate_allowed_value(relation, "alert_relation", ALLOWED_ALERT_RELATIONS)

    if relation:

        demisto.log('Fetching alert details...')
        response = client.get_alert_details(id=id, relation=relation, params=params)

        if response is None:
            raise DemistoException(f'Request failed: the response from the server did not include {response}')

        # Create a human-readable table
        readable_output = tableToMarkdown(
            name='Expel Alert Details',
            t=response.get('data', []),
            headers=['id', 'attributes'],
            #headerTransform=string_to_markdown
        )

        # Return the results
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='Expel.Alerts.Details',
            outputs_key_field='id',
            outputs=response.get('data', []),
            raw_response=response
        )
    else:

        demisto.log('Fetching alert details...')
        response = client.get_alert_details(id=id, params=params)

        if response is None:
            raise DemistoException(f'Request failed: the response from the server did not include {response}')

        # Create a human-readable table
        readable_output = tableToMarkdown(
            name='Expel Alert Details',
            t=response.get('data', []),
            headers=['id', 'attributes'],
            #headerTransform=string_to_markdown
        )

        # Return the results
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='Expel.Alerts.Details',
            outputs_key_field='id',
            outputs=response.get('data', []),
            raw_response=response
        )



def post_context_upload_command(client: Client, data):

    """
    Cortex XSOAR command to upload context to our Expel Workbench instance.
    """

    if not data:
        raise DemistoException('the data argument cannot be empty.')

    else:

         demisto.log('Posting context to Expel Workbench...')
         response = client.post_context_upload(data)

         readable_output = tableToMarkdown(
             name='Expel Context Upload',
             t=response.get('data', response),
         )

         return CommandResults(
             readable_output=readable_output,
             outputs_prefix='Expel.Context.Upload',
             outputs=response.get('data', response),
             raw_response=response,
         )


def patch_context_update_command(client: Client, context_id: str, data: Optional[Dict[str, Any]]) -> CommandResults:
    if not context_id:
        raise DemistoException('the context_id argument cannot be empty.')

    if not data:
        raise DemistoException('the data argument cannot be empty.')

    demisto.log('Updating context in Expel Workbench...')
    response = client.patch_context_update(context_id=context_id, data=data)

    readable_output = tableToMarkdown(
        name='Expel Context Update',
        t=response.get('data', response),
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expel.Context.Update',
        outputs=response.get('data', response),
        raw_response=response,
    )


def delete_context_variable_command(client: Client, context_id: str) -> CommandResults:
    if not context_id:
        raise DemistoException('the context_id argument cannot be empty.')

    demisto.log('Deleting context variable in Expel Workbench...')
    response = client.delete_context_variable(context_id=context_id)

    readable_output = tableToMarkdown(
        name='Expel Context Delete',
        t=response if isinstance(response, dict) else {"result": response},
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expel.Context.Delete',
        outputs=response,
        raw_response=response,
    )


def get_alert_count_by_severity_command(client: Client) -> CommandResults:
    params = _build_list_params(demisto.args())
    response = client.get_alert_count_by_severity(params=params)

    readable_output = tableToMarkdown(
        name='Expel Alert Count By Severity',
        t=response.get('data', response),
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expel.Alerts.CountBySeverity',
        outputs=response.get('data', response),
        raw_response=response,
    )


def get_investigation_history_timeline_command(client: Client, investigation_id: str) -> CommandResults:
    if not investigation_id:
        raise DemistoException('the investigation_id argument cannot be empty.')

    response = client.get_investigation_history_timeline(investigation_id=investigation_id)
    readable_output = tableToMarkdown(
        name='Expel Investigation History Timeline',
        t=response.get('data', response),
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expel.Investigation.History',
        outputs=response.get('data', response),
        raw_response=response,
    )


def get_alert_history_timeline_command(client: Client, alert_id: str) -> CommandResults:
    if not alert_id:
        raise DemistoException('the alert_id argument cannot be empty.')

    response = client.get_alert_history_timeline(alert_id=alert_id)
    readable_output = tableToMarkdown(
        name='Expel Alert History Timeline',
        t=response.get('data', response),
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expel.Alert.History',
        outputs=response.get('data', response),
        raw_response=response,
    )


def search_events_command(client: Client) -> CommandResults:
    args = demisto.args()
    filter_obj = _parse_json_arg(args.get("filter"), "filter") if args.get("filter") else {}

    name = args.get("name")
    ip = args.get("ip")
    hostname = args.get("hostname")
    username = args.get("username")
    file_hash = args.get("file_hash") or args.get("fileHash")
    time_from = args.get("from")
    time_to = args.get("to")
    phrase = args.get("phrase")
    organization_id = args.get("organization_id")
    vendor_name = args.get("vendor_name")

    if name:
        filter_obj["name"] = name
    if ip:
        filter_obj["ip"] = ip
    if hostname:
        filter_obj["hostname"] = hostname
    if username:
        filter_obj["username"] = username
    if file_hash:
        filter_obj["fileHash"] = file_hash
    if time_from:
        _parse_iso8601(time_from, "from")
        filter_obj["from"] = time_from
    if time_to:
        _parse_iso8601(time_to, "to")
        filter_obj["to"] = time_to
    if phrase:
        filter_obj["phrase"] = phrase
    if organization_id:
        filter_obj.setdefault("organization", {})["id"] = organization_id
    if vendor_name:
        filter_obj.setdefault("vendor", {})["name"] = vendor_name

    if time_from and time_to:
        if _parse_iso8601(time_to, "to") < _parse_iso8601(time_from, "from"):
            raise DemistoException('"to" must be greater than or equal to "from".')

    if not any(filter_obj.get(k) for k in ("name", "ip", "hostname", "username", "fileHash", "phrase")):
        raise DemistoException(
            'At least one of name, ip, hostname, username, fileHash, or phrase must be provided for event search.'
        )

    params: Dict[str, Any] = {}
    _add_nested_params(params, "filter", filter_obj)

    response = client.search_events(params=params)
    readable_output = tableToMarkdown(
        name='Expel Event Search Results',
        t=response.get('data', response),
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expel.Events.Search',
        outputs=response.get('data', response),
        raw_response=response,
    )


def get_health_command(client: Client) -> CommandResults:
    args = demisto.args()
    auth = argToBoolean(args.get("auth")) if args.get("auth") is not None else False
    heartbeat = argToBoolean(args.get("heartbeat")) if args.get("heartbeat") is not None else False
    component = args.get("component")

    if auth and heartbeat:
        raise DemistoException('auth and heartbeat cannot both be true.')

    params: Dict[str, Any] = {}
    if component:
        _add_nested_params(params, "filter", {"component": component})

    response = client.get_health(auth=auth, heartbeat=heartbeat, params=params or None)

    readable_output = tableToMarkdown(
        name='Expel Health',
        t=response.get('data', response),
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expel.Health',
        outputs=response.get('data', response),
        raw_response=response,
    )


def get_info_command(client: Client) -> CommandResults:
    response = client.get_info()
    readable_output = tableToMarkdown(
        name='Expel API Info',
        t=response.get('data', response),
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Expel.Info',
        outputs=response.get('data', response),
        raw_response=response,
    )


def fetch_incidents(
    client: Client,
    last_run: Dict[str, Any],
    first_fetch: str,
    max_fetch: int,
    incident_type: str,
    time_field: str,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if max_fetch < 1 or max_fetch > MAX_FETCH_INCIDENTS:
        raise DemistoException(f"max_fetch must be between 1 and {MAX_FETCH_INCIDENTS}.")

    last_fetch = last_run.get("last_fetch")
    last_ids = set(_normalize_id_list(last_run.get("last_ids")))
    fetched_ids = _normalize_id_list(last_run.get("fetched_ids"))[-MAX_TRACKED_FETCH_IDS:]
    fetched_ids_set = set(fetched_ids)
    if last_fetch:
        since = last_fetch
    else:
        since = _parse_first_fetch(first_fetch)

    try:
        since_dt = _to_datetime(since, "last_fetch")
    except Exception:
        since = _parse_first_fetch(first_fetch)
        since_dt = _to_datetime(since, "first_fetch")
        last_ids = set()
        fetched_ids = []
        fetched_ids_set = set()
    since_str = _to_iso8601_utc(since_dt)

    incidents: List[Dict[str, Any]] = []
    offset = 0
    page_size = min(max_fetch, 50)
    newest_dt = since_dt
    newest_ids = list(last_ids)
    newest_ids_set = set(last_ids)

    while len(incidents) < max_fetch:
        resp = client.get_incident_investigations(
            since=since_str,
            limit=page_size,
            offset=offset,
            time_field=time_field,
        )
        data = resp.get("data") or []
        if not data:
            break

        for item in data:
            incident_id = item.get("id")
            incident_id_str = str(incident_id) if incident_id is not None else ""
            time_dt = _to_datetime(_get_investigation_modified_time_value(item, time_field), time_field)
            if time_dt > newest_dt:
                newest_dt = time_dt
                newest_ids = []
                newest_ids_set = set()
            if time_dt == newest_dt and incident_id_str and incident_id_str not in newest_ids_set:
                newest_ids.append(incident_id_str)
                newest_ids_set.add(incident_id_str)
            # Fetch creates the incident once; inbound mirroring handles later remote updates.
            if incident_id_str and incident_id_str in fetched_ids_set:
                continue
            if time_dt == since_dt and incident_id_str and incident_id_str in last_ids:
                continue
            incidents.append(_build_xsoar_incident_from_investigation(
                client=client,
                item=item,
                incident_type=incident_type,
                time_field=time_field,
            ))
            _append_tracked_id(fetched_ids, fetched_ids_set, incident_id_str, MAX_TRACKED_FETCH_IDS)

            if len(incidents) >= max_fetch:
                break

        if len(data) < page_size:
            break

        offset += page_size

    next_run = {
        "last_fetch": _to_iso8601_utc(newest_dt),
        "last_ids": newest_ids,
        "fetched_ids": fetched_ids,
    }
    return next_run, incidents


def main() -> None:
    """
    Main function for the Expel Workbench integration.
    """
    #Assigning variables to XSOAR arguments and parameters
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('apikey',{}).get('password')
    base_url = _validate_base_url(params.get('url'))
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    first_fetch = params.get("first_fetch", "7 days")
    max_fetch = int(params.get("max_fetch", 50))
    incident_type = params.get("incident_type", "Expel Investigation")
    fetch_time_field = params.get("fetch_time_field", "updated_at")

    if not verify:
        requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


    demisto.debug(f'Command being called is {command}')


    try:
        client = Client(
            api_key=api_key,
            base_url=base_url,
            verify=verify,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'expel-get-investigations':
            return_results(get_investigations_command(client))
        # Add more command handlers here
        elif command == 'expel-get-investigation-details':
            investigationID = args.get('investigationID')
            sync_to_incident = argToBoolean(args.get("sync_to_incident")) if args.get("sync_to_incident") is not None else False
            if args.get('relation'):
                relation = args.get('relation')
                return_results(
                    get_investigation_details_command(
                        client,
                        id=investigationID,
                        relation=relation,
                        sync_to_incident=sync_to_incident,
                        incident_type=incident_type,
                        time_field=fetch_time_field,
                    )
                )
            else:
                return_results(
                    get_investigation_details_command(
                        client,
                        id=investigationID,
                        sync_to_incident=sync_to_incident,
                        incident_type=incident_type,
                        time_field=fetch_time_field,
                    )
                )
        elif command == 'expel-get-incident-sync-data':
            investigationID = args.get('investigationID') or args.get('investigation_id')
            return_results(
                get_incident_sync_data_command(
                    client,
                    id=investigationID,
                    incident_type=incident_type,
                    time_field=fetch_time_field,
                )
            )
        # Add more command handlers here
        elif command == 'expel-get-alerts':
            return_results(get_alerts_command(client))
        # Add more command handlers here
        elif command == 'expel-get-alert-details':
            alertID = args.get('alertID')
            if args.get('alert_relation'):
                alert_relation = args.get('alert_relation')
                return_results(get_alert_details_command(client, id=alertID, relation=alert_relation))
            else:
                return_results(get_alert_details_command(client, id=alertID))
        elif command == 'expel-post-context-upload':
            data = args.get('contextData')
            return_results(post_context_upload_command(client, data=data))
        elif command == 'expel-context-update':
            context_id = args.get('context_id')
            data_arg = args.get('contextUpdate') or args.get('contextData')
            if data_arg:
                data = _parse_json_arg(data_arg, "contextUpdate")
                if not isinstance(data, dict):
                    raise DemistoException('contextUpdate must be a JSON object.')
            else:
                categories = args.get("categories")
                tags = args.get("tags")
                if categories:
                    categories = _parse_json_arg(categories, "categories")
                if tags:
                    tags = _parse_json_arg(tags, "tags")
                data = {
                    "name": args.get("name"),
                    "description": args.get("description"),
                    "surface_context": argToBoolean(args.get("surface_context")) if args.get("surface_context") is not None else None,
                    "value": args.get("value"),
                    "categories": categories,
                    "tags": tags,
                }
                data = {k: v for k, v in data.items() if v is not None}
            return_results(patch_context_update_command(client, context_id=context_id, data=data))
        elif command == 'expel-context-delete':
            context_id = args.get('context_id')
            return_results(delete_context_variable_command(client, context_id=context_id))
        elif command == 'expel-get-alert-count-by-severity':
            return_results(get_alert_count_by_severity_command(client))
        elif command == 'expel-get-investigation-history':
            investigation_id = args.get('investigationID') or args.get('investigation_id')
            return_results(get_investigation_history_timeline_command(client, investigation_id=investigation_id))
        elif command == 'expel-get-alert-history':
            alert_id = args.get('alertID') or args.get('alert_id')
            return_results(get_alert_history_timeline_command(client, alert_id=alert_id))
        elif command == 'expel-search-events':
            return_results(search_events_command(client))
        elif command == 'expel-get-health':
            return_results(get_health_command(client))
        elif command == 'expel-get-info':
            return_results(get_info_command(client))
        elif command == 'expel-link-pagerduty-incident':
            return_results(link_pagerduty_incident_command(args))
        elif command == 'get-modified-remote-data':
            last_update = args.get("lastUpdate") or args.get("last_update") or ""
            return_results(
                get_modified_remote_data_command(
                    client,
                    last_update=last_update,
                    first_fetch=first_fetch,
                    fetch_time_field=fetch_time_field,
                )
            )
        elif command == 'get-remote-data':
            remote_id = (
                args.get("id")
                or args.get("remoteId")
                or args.get("remote_id")
                or args.get("remoteIncidentId")
                or args.get("remote_incident_id")
                or args.get("incident_id")
            )
            return_results(
                get_remote_data_command(
                    client,
                    remote_id=remote_id,
                    incident_type=incident_type,
                    fetch_time_field=fetch_time_field,
                )
            )
        elif command == 'fetch-incidents':
            # XSOAR calls this branch on the periodic fetch interval when Fetch incidents is enabled.
            if fetch_time_field not in ("created_at", "updated_at", "status_updated_at", "is_incident_status_updated_at"):
                raise DemistoException(
                    'fetch_time_field must be one of "created_at", "updated_at", "status_updated_at", or "is_incident_status_updated_at".'
                )
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch,
                max_fetch=max_fetch,
                incident_type=incident_type,
                time_field=fetch_time_field,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        # Add more command handlers here
        else:
            raise NotImplementedError(f'Command not implemented: {command}')

    except Exception as e:
        demisto.error(_sanitize_error_text(traceback.format_exc(), secret_values=[api_key]))
        if isinstance(e, DemistoException):
            return_error(f'Failed to execute {command} command. Error: {_sanitize_error_text(e, secret_values=[api_key])}')
        return_error(f'Failed to execute {command} command. Error: unexpected error. Review server logs for details.')



""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
