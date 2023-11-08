import datetime
import logging

import azure.functions as func
from shared_code.api_helpers import BeaconAPIClient
from shared_code.policies import (
    check_missed_attestation_policy_violations,
    check_missed_proposal_policy_violations,
    review_policy_violations,
)


def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )

    bac = BeaconAPIClient()
    bac.run()
    check_missed_attestation_policy_violations(bac.attestations, bac.epoch)
    check_missed_proposal_policy_violations(bac.proposals, bac.epoch)
    review_policy_violations()
