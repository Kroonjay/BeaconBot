import datetime
import logging

import azure.functions as func
from shared_code.api_helpers import BeaconAPIClient
from shared_code.db_helpers import create_beacon_alert_from_attestation

def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    bac = BeaconAPIClient()
    bac.run()
    logging.info(f"Total Validators: {len(bac.validators)}")
    logging.info(f"Total Missed Attestations: {len(bac.missed_attestations)}")
    logging.info(f"Total Missed Proposals: {len(bac.missed_proposals)}")
    logging.info(f"Current Epoch: {bac.epoch}") 
    # if mytimer.past_due:
    #     logging.info('The timer is past due!')

    # logging.info('Python timer trigger function ran at %s', utc_timestamp)
