import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from os import getenv
import logging
from urllib.parse import urljoin
from shared_code.models import (
    ValidatorInfo,
    AttestationEvent,
    EpochInfo,
    EventStatus,
    ProposalEvent,
)
from shared_code.db_helpers import (
    create_beacon_alert_from_attestation,
    create_beacon_alert_from_proposal,
)
from pydantic import ValidationError


def parse_model(Model, data: dict):
    try:
        return Model(**data)
    except ValidationError as ve:
        logging.error(f"Failed to Parse Model | Model: {str(Model)} | Msg: {ve.json()}")
    return None


def get_session():
    if not getenv("BEACONCHAIN_API_KEY"):
        logging.critical("BeaconChain API Key is Not Set!")
        return None
    s = requests.Session()
    s.headers.update({"apikey": getenv("BEACONCHAIN_API_KEY")})
    max_retries = getenv("BEACONCHAIN_API_MAX_RETRIES")
    retries = Retry(total=max_retries, backoff_factor=0.1)
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


# Check if attestation or proposal status is 0 for any finalized epochs.
def was_missed(event, epoch: EpochInfo) -> bool:
    if event.status == EventStatus.MISSED:
        if epoch.is_final and epoch.epoch >= event.epoch:
            return True
    return False


def get_public_block_height():
    api_url = getenv("BLOCKCYPHER_API_URL")
    response = requests.get(api_url)
    if not response.ok:
        logging.error(
            f"Failed to Fetch Public Block Height | BlockCypher API Error | Status Code {response.status_code}"
        )
    return response.json().get("height")


class BeaconAPIClient:
    def __init__(self):
        self.session = get_session()
        self.logger = logging.getLogger("BeaconApiClient")
        self.withdrawal_address = getenv("ETH_WITHDRAWAL_ADDRESS")
        self.beaconchain_base_url = "https://beaconcha.in"
        self.validators = []
        self.attestations = []
        self.proposals = []
        self.missed_attestations = []
        self.missed_proposals = []
        self.epoch = None

    def get_url(self, endpoint: str):
        return urljoin(self.beaconchain_base_url, endpoint)

    def make_request(self, endpoint: str):
        url = self.get_url(endpoint)
        try:
            response = self.session.get(url)
            return response.json().get("data")
        except requests.exceptions.RequestException as re:
            logging.error(f"Beaconchain API Request Failure | Max Retries Exceeded")
            return None  # Not sure if we should raise here...

    def get_all_validators(self):
        endpoint = f"/api/v1/validator/eth1/{self.withdrawal_address}"
        data = self.make_request(endpoint)
        if not data:
            logging.error("Failed to Load Validators due to Beaconchain API Error")
            return
        for item in data:
            vi = parse_model(ValidatorInfo, item)
            if vi:
                self.validators.append(vi)
        return self

    def get_validator_stats(self, vi: ValidatorInfo) -> ValidatorInfo:
        endpoint = f"/api/v1/validator/stats/{vi.validator_index}"
        data = self.make_request(endpoint)
        if not data:
            logging.error("Failed to Load Validator Stats due to Beaconchain API Error")
            return
        return self

    def get_validator_indexes(self):
        # Attestation endpoint accepts up to 100 validator indexes
        batch_size = 100
        indexes = [(val.validator_index) for val in self.validators]
        for i in range(0, len(indexes), batch_size):
            chunk = indexes[i : i + batch_size]
            yield "".join([(f"{val},") for val in chunk])[:-1]  # Strip trailing comma

    def get_latest_finalized_epoch(self) -> EpochInfo:
        epoch = "finalized"
        url = self.get_url(f"/api/v1/epoch/{epoch}")
        data = self.make_request(url)
        try:
            self.epoch = parse_model(EpochInfo, data)
            return self
        except ValidationError as ve:
            logging.error(
                f"Failed to Parse EpochInfo from Beaconchain API Response | Msg: {ve.json()}"
            )
        return self

    def get_attestations(self):
        if not self.validators:
            logging.info("Validator List is Empty, Fetching Latest from Beaconchain")
            self.get_all_validators()
        for indexes in self.get_validator_indexes():
            endpoint = f"api/v1/validator/{indexes}/attestations"
            data = self.make_request(endpoint)
            if not data:
                logging.error(
                    "Failed to Load Attestations due to Beaconchain API Error"
                )
                return self
            for item in data:
                att = parse_model(AttestationEvent, item)
                if att:
                    self.attestations.append(att)
        return self

    def get_proposals(self):
        for indexes in self.get_validator_indexes():
            url = self.get_url(f"api/v1/validator/{indexes}/proposals")
            data = self.make_request(url)
            logging.debug(f"Proposal Data: {data}")
            if not data:
                logging.error("Beaconchain returned No proposals for Past 100 Epochs")
                return self
            for item in data:
                prop = parse_model(ProposalEvent, item)
                if prop:
                    self.proposals.append(prop)
        return self

    def get_missed_attestations(self):
        if not self.validators:
            logging.info("Validator List is Empty, Fetching Latest from Beaconchain")
            self.get_all_validators()
        if not self.epoch:
            logging.info("Current Epoch Not Set, Fetching Latest from Beaconchain")
            self.get_latest_finalized_epoch()
        if not self.attestations:
            logging.info("Attestation List is Empty, Fetching Latest from Beaconchain")
            self.get_attestations()
        for attestation in self.attestations:
            if was_missed(attestation, self.epoch):
                self.missed_attestations.append(attestation)
                create_beacon_alert_from_attestation(attestation)
        logging.info(
            f"Missed Attestation List Created | Total Att: {len(self.attestations)} | Missed Att: {len(self.missed_attestations)}"
        )
        return self

    def get_missed_proposals(self):
        if not self.validators:
            logging.info("Validator List is Empty, Fetching Latest from Beaconchain")
            self.get_all_validators()
        if not self.epoch:
            logging.info("Current Epoch Not Set, Fetching Latest from Beaconchain")
            self.get_latest_finalized_epoch()
        if not self.proposals:
            logging.info("Proposal List is Empty, Fetching Latest from Beaconchain")
            self.get_proposals()
        for proposal in self.proposals:
            if was_missed(proposal, self.epoch):
                self.missed_proposals.append(proposal)
                create_beacon_alert_from_proposal(proposal)

        logging.info(
            f"Missed Proposal Check Complete | Total Proposals: {len(self.proposals)} | Missed Proposals: {len(self.missed_proposals)}"
        )

    def run(self):
        self.get_all_validators()
        self.get_latest_finalized_epoch()
        self.get_attestations()
        self.get_proposals()


def main():
    bac = BeaconAPIClient()
    bac.get_all_validators()


if __name__ == "__main__":
    main()
