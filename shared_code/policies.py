from os import getenv
from shared_code.models import (
    NodeNotification,
    PolicyViolations,
    AttestationEvent,
    ProposalEvent,
    EpochInfo,
    EventStatus,
)
from shared_code.db_helpers import (
    read_policy_violations,
    create_policy_violation,
    update_alerted_policies,
)
from shared_code.pd_helpers import post_alert
from typing import List
import logging

logger = logging.getLogger("Policies")


def was_missed(event, epoch: EpochInfo, interval: int) -> bool:
    min_epoch = epoch.epoch - interval
    if event.status == EventStatus.MISSED:
        if epoch.is_final and epoch.epoch >= event.epoch >= min_epoch:
            return True
    return False


def execution_block_height_match(nn: NodeNotification) -> bool:
    tolerance = int(getenv("BLOCK_HEIGHT_MISMATCH_TOLERANCE"))
    return (
        True
        if abs(nn.execution_block_height - nn.public_block_height) < tolerance
        else False
    )


def beacon_peer_count_above_threshold(nn: NodeNotification) -> bool:
    minimum = int(getenv("MINIMUM_BEACON_PEERS"))
    return True if nn.beacon_peer_count > minimum else False


def beacon_is_healthy(nn: NodeNotification) -> bool:
    return True if nn.beacon_health_status == 200 else False


def check_missed_attestation_policy_violations(
    attestations: List[AttestationEvent], epoch: EpochInfo
) -> bool:
    threshold = int(getenv("MISSED_ATTESTATION_THRESHOLD"))
    interval = int(getenv("MISSED_ATTESTATION_INTERVAL_EPOCHS"))
    missed_count = 0
    details = {"threshold": {threshold}, "interval_epochs": {interval}}
    for att in attestations:
        if was_missed(att, epoch, interval):
            missed_count += 1
            logger.debug(
                f"Found Missed Attestation | Total: {missed_count} | Data: {str(att)}"
            )
    logger.info(
        f"Missed Attestation Check Complete | Total Att: {len(attestations)} | Missed: {missed_count}"
    )
    logger.debug(
        f"Missed Attestation Check Config | Threshold: {threshold} | Interval: {interval}"
    )
    details.update({"total_missed": missed_count})
    if missed_count > threshold:
        create_policy_violation(PolicyViolations.MISSED_ATTESTATIONS, details=details)
    return


def check_missed_proposal_policy_violations(
    proposals: List[ProposalEvent], epoch: EpochInfo
) -> bool:
    threshold = int(getenv("MISSED_BLOCK_THRESHOLD"))
    interval = int(getenv("MISSED_BLOCK_INTERVAL_EPOCHS"))
    missed_count = 0
    details = {"threshold": threshold, "interval_epochs": interval}
    for prop in proposals:
        if was_missed(prop, epoch, interval):
            missed_count += 1
            logger.debug(
                f"Found Missed Proposal | Total: {missed_count} | Data: {str(prop)}"
            )
    logger.info(
        f"Missed Proposal Check Complete | Total Props: {len(proposals)} | Missed: {missed_count}"
    )
    logger.debug(
        f"Missed Proposal Check Config | Threshold: {threshold} | Interval: {interval}"
    )
    details.update({"missed_count": missed_count})
    if missed_count > threshold:
        create_policy_violation(PolicyViolations.MISSED_PROPOSALS, details=details)
    return


def check_node_notification_policy_violations(node_notification: NodeNotification):
    details = None
    if not node_notification.beacon_is_connected:
        create_policy_violation(PolicyViolations.BEACON_OFFLINE, details=details)
    if not node_notification.execution_is_connected:
        create_policy_violation(PolicyViolations.EXECUTION_OFFLINE, details=details)
    if not node_notification.beacon_is_synced:
        create_policy_violation(PolicyViolations.BEACON_NOT_SYNCED, details=details)
    if not node_notification.execution_is_synced:
        create_policy_violation(PolicyViolations.EXECUTION_NOT_SYNCED, details=details)
    if not beacon_is_healthy(node_notification):
        create_policy_violation(PolicyViolations.BEACON_UNHEALTHY, details=details)
    if not beacon_peer_count_above_threshold(node_notification):
        create_policy_violation(PolicyViolations.NOT_ENOUGH_PEERS, details=details)
    if not execution_block_height_match(node_notification):
        create_policy_violation(PolicyViolations.BEHIND_ON_BLOCKS, details=details)
    return


def review_policy_violations():
    alert_fired = False
    violations = read_policy_violations()
    if violations:
        post_alert(violations[0].policy_type, violations[0].details)
        alert_fired = True
        update_alerted_policies()
    logging.info(
        f"Policy Violation Check Complete | Alert Fired: {alert_fired} | Total Violations: {len(violations)}"
    )
    return
