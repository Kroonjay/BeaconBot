from enum import Enum
from pydantic import BaseModel, Field, AnyHttpUrl, Field, validator
from datetime import datetime
from typing import Optional, Dict
from os import getenv
import re
from sqlalchemy import String, Integer, DateTime, Boolean, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func
import json


# Find these at https://github.com/gobitfly/eth2-beaconchain-explorer/blob/master/types/frontend.go#L27
class BeaconEvents(Enum):
    ATTESTATION_MISSED = "validator_attestation_missed"
    BLOCK_MISSED = "validator_proposal_missed"
    BALANCE_DECREASED = "validator_balance_decreased"
    SLASHED = "validator_got_slashed"


class PolicyViolations(Enum):
    MISSED_ATTESTATIONS = 0
    MISSED_PROPOSALS = 1
    BALANCE_DECREASED = 2
    SLASHED = 3
    BEACON_OFFLINE = 4
    EXECUTION_OFFLINE = 5
    VALIDATOR_OFFLINE = 6
    NOT_ENOUGH_PEERS = 7
    BEACON_UNHEALTHY = 8
    BEACON_NOT_SYNCED = 9
    EXECUTION_NOT_SYNCED = 10
    BEHIND_ON_BLOCKS = 11


class EventStatus(Enum):
    MISSED = 0
    ACCEPTED = 1


class IncidentSeverity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    ERROR = "error"
    INFO = "info"


class Base(DeclarativeBase):
    pass


class BeaconAlert(Base):
    __tablename__ = "beacon_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_type: Mapped[str] = mapped_column(String(30))
    epoch: Mapped[int] = mapped_column(Integer)
    validator_index: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    alert_fired: Mapped[bool] = mapped_column(Boolean, default=False)
    UniqueConstraint(alert_type, validator_index, epoch)


class PolicyViolationBase(Base):
    __tablename__ = "policy_violations"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_type: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    alert_fired: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[str] = mapped_column(String)


class PolicyViolation(BaseModel):
    id: int
    policy_type: PolicyViolations
    created_at: datetime
    alert_fired: bool
    details: Dict

    @validator("details", pre=True, always=True)
    def load_details(cls, v):
        if isinstance(v, str):
            return json.loads(v)
        return v


class ValidatorStats(Base):
    __tablename__ = "validator_stats"

    id: Mapped[int] = mapped_column(primary_key=True)
    validator_index: Mapped[int] = mapped_column(Integer)
    day: Mapped[int] = mapped_column(Integer)
    day_end: Mapped[datetime] = mapped_column(DateTime)
    day_start: Mapped[datetime] = mapped_column(DateTime)
    balance: Mapped[int] = mapped_column(Integer)
    missed_attestations: Mapped[int] = mapped_column(Integer)
    missed_proposals: Mapped[int] = mapped_column(Integer)
    orphaned_attestations: Mapped[int] = mapped_column(Integer)
    orphaned_proposals: Mapped[int] = mapped_column(Integer)
    attester_slashings: Mapped[int] = mapped_column(Integer)
    proposer_slashings: Mapped[int] = mapped_column(Integer)
    withdrawals: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    UniqueConstraint(validator_index, day)


class NodeReport(Base):
    __tablename__ = "node_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(30), nullable=False)
    beacon_is_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    beacon_is_synced: Mapped[bool] = mapped_column(Boolean, default=False)
    execution_is_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    execution_is_synced: Mapped[bool] = mapped_column(Boolean, default=False)
    beacon_health_status: Mapped[int] = mapped_column(Integer)
    beacon_peer_count: Mapped[int] = mapped_column(Integer)
    execution_block_height: Mapped[int] = mapped_column(Integer)
    public_block_height: Mapped[int] = mapped_column(Integer)
    beacon_version: Mapped[str] = mapped_column(String)
    execution_version: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())


class BeaconSyncStatus(BaseModel):
    head_slot: int
    sync_distance: int
    is_syncing: bool
    is_optimistic: bool
    el_offline: bool


class NodeNotification(BaseModel):
    name: str
    beacon_is_connected: bool
    execution_is_connected: bool
    beacon_is_synced: bool
    beacon_health_status: int
    beacon_peer_count: int
    beacon_version: str
    execution_block_height: int
    execution_is_synced: bool
    execution_version: str
    public_block_height: int = 0


class PagerDutyIncidentPayload(BaseModel):
    summary: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: IncidentSeverity = Field(default=IncidentSeverity.WARNING)
    source: str
    group: str = Field(default="staking-alerts")
    custom_details: Optional[Dict] = None


# Based on https://developer.pagerduty.com/api-reference/368ae3d938c9e-send-an-event-to-pager-duty
class PagerDutyIncident(BaseModel):
    payload: PagerDutyIncidentPayload
    routing_key: str = Field(default=getenv("PAGERDUTY_ROUTING_KEY"))
    dedup_key: str
    event_action: str = Field(default="trigger")
    client: str = Field(default="BeaconBot Monitoring Service")


class BeaconRequest(BaseModel):
    String: str
    Valid: bool


class BeaconWebhook(BaseModel):
    id: int
    url: AnyHttpUrl
    retries: int
    response: BeaconRequest
    request: BeaconRequest
    destination: BeaconRequest


class BeaconEvent(BaseModel):
    network: str
    event_type: BeaconEvents = Field(alias="event")
    title: str
    description: str
    epoch: int
    target: str
    validator_index: Optional[int] = Field(default=0, validate_always=True)

    @validator("validator_index", pre=True, always=True)
    def extract_validator_number(cls, v, values):
        description = values.get("description")
        if description:
            match = re.search(r"Validator (\d+)", description)
            if match:
                return match.group(1)
        print(f"Failed to parse Validator Index | Data: {description}")
        return 0


class BeaconNotification(BaseModel):
    webhook: BeaconWebhook = Field(alias="Webhook")
    event: BeaconEvent


class ValidatorInfo(BaseModel):
    public_key: str = Field(alias="publickey")
    valid_signature: bool
    validator_index: int = Field(alias="validatorindex")


class AttestationEvent(BaseModel):
    alert_type: BeaconEvents = BeaconEvents.ATTESTATION_MISSED
    attester_slot: int = Field(alias="attesterslot")
    committee_index: int = Field(alias="committeeindex")
    epoch: int
    inclusion_slot: int = Field(alias="inclusionslot")
    status: EventStatus
    validator_index: int = Field(alias="validatorindex")
    week: int
    week_start: datetime
    week_end: datetime


class EpochInfo(BaseModel):
    total_attestations: int = Field(alias="attestationscount")
    total_attester_slashings: int = Field(alias="attesterslashingscount")
    average_balance: int = Field(alias="averagevalidatorbalance")
    total_blocks: int = Field(alias="blockscount")
    total_deposits: int = Field(alias="depositscount")
    eligible_ether: int = Field(alias="eligibleether")
    epoch: int
    is_final: bool = Field(alias="finalized")
    participation_rate: float = Field(alias="globalparticipationrate")
    missed_blocks: int = Field(alias="missedblocks")
    orphaned_blocks: int = Field(alias="orphanedblocks")
    proposed_blocks: int = Field(alias="proposedblocks")
    total_proposer_slashings: int = Field(alias="proposerslashingscount")
    rewards_exported: bool
    scheduled_blocks: int = Field(alias="scheduledblocks")
    total_validator_balance: int = Field(alias="totalvalidatorbalance")
    created_at: datetime = Field(alias="ts")
    total_validators: int = Field(alias="validatorscount")
    total_exits: int = Field(alias="voluntaryexitscount")
    voted_ether: int = Field(alias="votedether")
    total_withdrawals: int = Field(alias="withdrawalcount")


class ProposalEvent(BaseModel):
    alert_type: BeaconEvents = BeaconEvents.BLOCK_MISSED
    total_attestations: int = Field(alias="attestationscount")
    total_attester_slashings: int = Field(alias="attesterslashingscount")
    block_root: str = Field(alias="blockroot")
    total_deposits: int = Field(alias="depositscount")
    epoch: int
    eth1_data_blockhash: str = Field(alias="eth1data_blockhash")
    eth1_data_total_deposits: int = Field(alias="eth1data_depositcount")
    eth1_data_deposit_root: str = Field(alias="eth1data_depositroot")
    exec_base_fee_per_gas: int
    exec_block_hash: str
    exec_block_number: int
    exec_extra_data: str
    exec_fee_recipient: str
    exec_gas_limit: int
    exec_gas_used: int
    exec_logs_bloom: str
    exec_parent_hash: str
    exec_random: str
    exec_receipts_root: str
    exec_state_root: str
    created_at: datetime = Field(alias="exec_timestamp")
    exec_total_transactions: int = Field(alias="exec_transactions_count")
    graffiti_raw: str = Field(alias="graffiti")
    graffiti_text: str
    parent_root: str = Field(alias="parentroot")
    proposer: int
    total_proposer_slashings: int = Field(alias="proposerslashingscount")
    randaoreveal: str
    signature: str
    slot: int
    state_root: str = Field(alias="stateroot")
    status: EventStatus
    sync_aggregate_bits: str = Field(alias="syncaggregate_bits")
    sync_aggregate_participation: float = Field(alias="syncaggregate_participation")
    sync_aggregate_signature: str = Field(alias="syncaggregate_signature")
    total_exits: int = Field(alias="voluntaryexitscount")

    @validator("status", pre=True, always=True)
    def convert_string_status(cls, v):
        if isinstance(v, str):
            return int(v)
        return v


class ValidatorEvent(BaseModel):
    attester_slashings: int
    day: int
    day_end: datetime
    day_start: datetime
    deposits: int
    deposits_amount: int
    end_balance: int
    end_effective_balance: int
    max_balance: int
    min_effective_balance: int
    missed_attestations: int
    missed_blocks: int
    missed_sync: int
    orphaned_attestations: int
    orphaned_blocks: int
    orphaned_sync: int
    participated_sync: int
    proposed_blocks: int
    proposer_slashings: int
    start_balance: int
    start_effective_balance: int
    validator_index: int
    withdrawals: int
    withdrawals_amount: int
