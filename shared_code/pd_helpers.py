import requests
from os import getenv
import logging
from shared_code.models import BeaconEvents, PagerDutyIncident, PagerDutyIncidentPayload
from datetime import datetime, timezone


def get_headers():
    token_var_name = "PAGERDUTY_API_TOKEN"
    api_key = getenv(token_var_name)
    if not api_key:
        raise ValueError(
            f"PagerDuty API Token is Missing | Set via {token_var_name} environment variable"
        )
    return {
        "Authorization": f"Token token={api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def get_summary(alert_type: BeaconEvents) -> str:
    if alert_type == BeaconEvents.ATTESTATION_MISSED:
        return "ETH Staking Nodes exceeded Missed Attestation threshold"
    return ""


def build_incident(alert_type: BeaconEvents, details: dict = None) -> PagerDutyIncident:
    payload = PagerDutyIncidentPayload(
        summary=get_summary(alert_type),
        source="sometest.source",
        custom_details=details,
    )
    incident = PagerDutyIncident(
        payload=payload, dedup_key=f"BeaconBot/{alert_type.value}"
    )
    print(incident.json(exclude_none=True))
    return incident


def post_alert(alert_type: BeaconEvents, details: dict = None):
    if getenv("SURPRESS_ALERTS"):
        logging.info(f'Alert Supressed via "SURPRESS_ALERTS" Environment Variable')
        return
    url = getenv("PAGERDUTY_URL")
    headers = get_headers()
    incident = build_incident(alert_type, details)
    response = requests.post(
        url, headers=headers, data=incident.json(exclude_none=True)
    )
    logging.info(
        f"Triggered PagerDuty Alert | Type: {alert_type} | Response Status Code: {response.status_code}"
    )
    logging.debug(f"Response Data: {response.json()}")
    return
