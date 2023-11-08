import logging
import azure.functions as func
from shared_code.models import NodeNotification
from shared_code.db_helpers import create_node_report_from_notification
from shared_code.api_helpers import get_public_block_height
from shared_code.policies import check_node_notification_policy_violations, review_policy_violations
from pydantic import ValidationError

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    notification = None
    try:
        req_body = req.get_json()
    except ValueError:
        logging.error("NodeTrigger Failed to Process Request Body")
        return func.HttpResponse("Failed to Parse Request Payload", status_code=400)
    try:
        notification = NodeNotification(**req_body, public_block_height=get_public_block_height())
    except ValidationError as ve:
        logging.error(f"ValidationError for NodeTrigger Request Body | Msg: {ve.json()}")
    if not notification:
        return func.HttpResponse("Failed to Parse Request Payload", status_code=400)
    check_node_notification_policy_violations(notification)
    review_policy_violations()
    create_node_report_from_notification(notification)
    
    return func.HttpResponse(
        "NodeTrigger Successfully Posted New Event",
        status_code=200
    )
