import logging
import azure.functions as func
from shared_code.beacon_helpers import check_all, parse_beacon_notification
from shared_code.db_helpers import create_beacon_alert_from_notification


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Beacon Alert Webhook Received is Processing a New Request")
    try:
        req_body = req.get_json()
    except ValueError:
        req_body = None

    if not req_body:
        return func.HttpResponse("No Data Provided to Endpoint", status_code=400)
    notification = parse_beacon_notification(req_body)
    if notification:
        alert = create_beacon_alert_from_notification(notification)
    check_all()
    return func.HttpResponse("BeaconHook Executed Successfully", status_code=200)
