import logging
from sqlalchemy import String, Integer, DateTime, create_engine, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy.sql import func
from pydantic import BaseModel, AnyHttpUrl, Field, validator, ValidationError
from datetime import datetime, timezone, timedelta
from sqlalchemy_utils import database_exists, create_database
from shared_code.models import (
    BeaconEvents,
    BeaconAlert,
    Base,
    BeaconNotification,
    AttestationEvent,
    ProposalEvent,
    NodeNotification,
    NodeReport,
    PolicyViolations,
    PolicyViolationBase,
    PolicyViolation,
)
from shared_code.pd_helpers import post_alert
from sqlalchemy.exc import IntegrityError
from os import getenv
import json
import re
from typing import List


def init_db():
    db_url = getenv("DB_CONNECTION_STRING")
    if not database_exists(db_url):
        create_database(db_url)
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    return engine


def create_beacon_alert_from_notification(bn: BeaconNotification) -> BeaconAlert:
    engine = init_db()
    with Session(engine) as session:
        alert = BeaconAlert(
            alert_type=bn.event.event_type.value,
            epoch=bn.event.epoch,
            validator_index=bn.event.validator_index,
        )
        session.add(alert)
        session.commit()
    return


def create_beacon_alert_from_attestation(ae: AttestationEvent):
    engine = init_db()
    with Session(engine) as session:
        alert = BeaconAlert(
            alert_type=ae.alert_type.value,
            epoch=ae.epoch,
            validator_index=ae.validator_index,
        )
        session.add(alert)
        try:
            session.commit()
        except IntegrityError as ie:
            logging.info(
                f"Unique Constraint Violation for Attestation | Epoch: {ae.epoch} | Index: {ae.validator_index}"
            )
    return


def create_beacon_alert_from_proposal(pe: ProposalEvent):
    engine = init_db()
    with Session(engine) as session:
        alert = BeaconAlert(
            alert_type=pe.alert_type.value, epoch=pe.epoch, validator_index=pe.proposer
        )


def get_interval_start(interval_minutes: str) -> timedelta:
    try:
        interval = int(interval_minutes)
        return datetime.now(tz=timezone.utc) - timedelta(minutes=interval)
    except ValueError as ve:
        logging.critical(
            f"Failed to Calculate Interval Start | Input is Not an Integer | Type: {type(interval_minutes)} | Value: {interval_minutes}"
        )
    return None


def get_recent_record_count(interval: str, alert_type: BeaconEvents) -> int:
    if not isinstance(alert_type, BeaconEvents):
        raise ValueError(
            f"Alert Type must be BeaconEvents enum member | Got: {type(alert_type)} | Value: {alert_type}"
        )
    interval_start = get_interval_start(interval)
    if not interval_start:
        logging.critical(f"Failed to Get Recent Records | Interval Start is None")
        return None
    total = 0
    engine = init_db()
    stmt = (
        select(BeaconAlert)
        .where(BeaconAlert.alert_type == alert_type.value)
        .where(BeaconAlert.alert_fired == False)
        .filter(BeaconAlert.created_at >= interval_start)
    )
    with Session(engine) as session:
        total = len(session.scalars(stmt).all())
    return total


def update_alerted_records(alert_type: BeaconEvents):
    if not isinstance(alert_type, BeaconEvents):
        logging.critical(
            f"Failed to Update Alerted Records | Alert Type must be BeaconEvents enum member | Got: {type(alert_type)}"
        )
        return
    if alert_type == BeaconEvents.ATTESTATION_MISSED:
        interval_start = get_interval_start(
            getenv("MISSED_ATTESTATION_INTERVAL_MINUTES")
        )
    elif alert_type == BeaconEvents.BLOCK_MISSED:
        interval_start = get_interval_start(getenv("MISSED_BLOCK_INTERVAL_MINUTES"))
    else:
        interval_start = None
    engine = init_db()
    if interval_start:
        update_stmt = (
            update(BeaconAlert)
            .where(BeaconAlert.alert_type == alert_type.value)
            .where(BeaconAlert.created_at >= interval_start)
            .values(alert_fired=True)
        )
    else:
        update_stmt = (
            update(BeaconAlert)
            .where(BeaconAlert.alert_type == alert_type.value)
            .values(alert_fired=True)
        )
    with Session(engine) as session:
        session.execute(update_stmt)
        session.commit()
    logging.info("Successfully Updated Alerted Records")
    return


def read_slashing_events():
    engine = init_db()
    alerts = []
    incident_created = False
    with Session(engine) as session:
        select_stmt = (
            select(BeaconAlert)
            .where(BeaconAlert.alert_type == BeaconEvents.SLASHED.value)
            .where(BeaconAlert.alert_fired == False)
        )
        alerts = session.scalars(select_stmt).all()
    logging.debug(f"Read Slashing Events | Total: {len(alerts)}")
    return alerts


def create_node_report_from_notification(ne: NodeNotification):
    engine = init_db()
    with Session(engine) as session:
        report = NodeReport(**ne.dict())
        session.add(report)
        session.commit()
    logging.debug("Created Node Report from Notification")
    return


def create_policy_violation(pv_type: PolicyViolations, details: dict = None):
    if not details:
        details = {}
    detail_str = json.dumps(details)
    engine = init_db()
    with Session(engine) as session:
        pv = PolicyViolationBase(policy_type=pv_type.value, details=detail_str)
        session.add(pv)
        session.commit()
    logging.debug(
        f"Created Policy Violation | Type: {str(pv_type)} | Details: {str(details)}"
    )
    return


def read_policy_violations():
    engine = init_db()
    interval_start = get_interval_start(getenv("POLICY_VIOLATION_INTERVAL_MINUTES"))
    policy_violations = []
    stmt = (
        select(PolicyViolationBase)
        .where(PolicyViolationBase.alert_fired == False)
        .filter(PolicyViolationBase.created_at >= interval_start)
    )
    with Session(engine) as session:
        pvs = session.scalars(stmt).all()
    for pv in pvs:
        policy_violations.append(PolicyViolation(**pv.__dict__))
    logging.debug(f"Read All Policy Violations | Total: {len(policy_violations)}")
    return policy_violations


def update_alerted_policies():
    engine = init_db()
    interval_start = get_interval_start(getenv("POLICY_VIOLATION_INTERVAL_MINUTES"))
    update_stmt = (
        update(PolicyViolationBase)
        .where(PolicyViolationBase.created_at >= interval_start)
        .where(PolicyViolationBase.alert_fired == False)
        .values(alert_fired=True)
    )
    with Session(engine) as session:
        session.execute(update_stmt)
        session.commit()
    logging.debug("Successfully Updated Policy Violations")
    return


def check_node_healthcheck_policy_violations():
    engine = init_db()
    with Session(engine) as session:
        node_names = session.query(NodeReport.name).distinct()
    logging.info(f"Node Names: {node_names}")
