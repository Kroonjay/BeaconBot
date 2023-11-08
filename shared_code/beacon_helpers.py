from os import getenv
from shared_code.db_helpers import (
    get_recent_record_count,
    update_alerted_records,
    init_db,
    read_slashing_events,
    create_policy_violation,
)
from shared_code.models import BeaconEvents, BeaconNotification, PolicyViolations
from shared_code.pd_helpers import post_alert
import logging
from pydantic import ValidationError


def parse_beacon_notification(data: dict) -> BeaconNotification:
    try:
        return BeaconNotification(**data)
    except ValidationError as ve:
        logging.critical(f"Failed to Parse BeaconNotification | Msg: {ve.json()}")
    return None


def missed_attestation_threshold_exceeded():
    interval = getenv("MISSED_ATTESTATION_INTERVAL_MINUTES")
    threshold = int(getenv("MISSED_ATTESTATION_THRESHOLD"))
    recently_missed = get_recent_record_count(interval, BeaconEvents.ATTESTATION_MISSED)
    logging.info(
        f"Missed Attestation Check | Threshold: {threshold} | Missed: {recently_missed}"
    )
    details = {"total": recently_missed}
    policy_violation = False
    if recently_missed >= threshold:
        create_policy_violation(PolicyViolations.MISSED_ATTESTATIONS, details)
        update_alerted_records(BeaconEvents.ATTESTATION_MISSED)
        policy_violation = True
    logging.info(
        f"Missed Attestation Check Complete | Policy Violation: {policy_violation} | Total Events: {recently_missed}"
    )
    return


def missed_block_threshold_exceeded():
    interval = getenv("MISSED_BLOCK_INTERVAL_MINUTES")
    threshold = int(getenv("MISSED_BLOCK_THRESHOLD"))
    recently_missed = get_recent_record_count(interval, BeaconEvents.BLOCK_MISSED)
    details = {"total": recently_missed}
    policy_violation = False
    if recently_missed >= threshold:
        create_policy_violation(PolicyViolations.MISSED_PROPOSALS, details)
        update_alerted_records(BeaconEvents.BLOCK_MISSED)
        policy_violation = True
    logging.info(
        f"Missed Proposal Check Complete | Incident Created: {policy_violation} | Total Events: {recently_missed}"
    )
    return


def validator_was_slashed():
    policy_violation = False
    slashing_events = read_slashing_events()
    if slashing_events:
        details = {
            "validator_indexes": [(event.validator_index) for event in slashing_events],
            "total": len(slashing_events),
        }
        create_policy_violation(PolicyViolations.SLASHED, details)
        policy_violation = True
        update_alerted_records(BeaconEvents.SLASHED)
    logging.info(
        f"Slashing Check Complete | Policy Violation: {policy_violation} | Total: {len(slashing_events)}"
    )
    return


def check_all():
    missed_attestation_threshold_exceeded()
    missed_block_threshold_exceeded()
    validator_was_slashed()
