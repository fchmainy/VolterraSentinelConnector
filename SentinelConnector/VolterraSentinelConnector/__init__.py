import requests
import json
import datetime
from requests.auth import HTTPBasicAuth
import azure.functions as func
import base64
import hmac
import hashlib
import os
import tempfile
import logging
import re
from .state_manager import StateManager

workspace_id = os.environ['WORKSPACE_ID'] 
workspaceKey = os.environ['workspaceKey']
authToken = os.environ['authToken']

volterraTenant = os.environ['VOLTERRA_TENANT']
namespace = os.environ['VOLTERRA_NAMESPACE']

connection_string = os.environ['CONNECTION_STRING']

log_type = 'LOG_TYPE'
events_api_endpoint = "https://" + volterraTenant + ".console.ves.volterra.io/api/data/namespaces/" + namespace + "/app_security/events"

logging.info("DEBUG: Volterra Endpoint is {}".format(events_api_endpoint))

def generate_date():
    current_date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    logging.info("DEBUG: Current date is {}".format(current_date))
    state = StateManager(connection_string=connection_string)
    previous_date = state.get()
    if previous_date is not None:
        logging.info("DEBUG: The latest time stamp is: {}".format(past_time))
    else:
        logging.info("DEBUG: There is no previous timestamp, trying to get events for the last hour.")
        previous_date = (datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

    state.post(current_date)
    return (previous_date, current_date)


def get_result_request(start_date, end_date):
    try:

        headers = {
            'Authorization': 'APIToken ' + authToken,
            'Content-Type': 'application/json'
        }

        body = {
            'start_time': '%s' % start_date,
            'end_time': '%s' % end_date,
            'namespace': namespace, 
            'limit': 1
        }

        r = requests.post(events_api_endpoint,
                            headers=headers,
                            json=body
                         )
        if r.status_code == 200:
            logging.error("DEBUG: Response is: {}".format(r.json()))
            events = json.loads(r.text)
            return events['events']
        elif r.status_code == 401:
            logging.error("The authentication token may be incorrect. Error code: {}".format(r.status_code))
        elif r.status_code == 403:
            logging.error("Check permissions. Error code: {}".format(r.status_code))
        else:
            logging.error("Something wrong. Error code: {}".format(r.status_code))
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))


def get_result(date_range):
    start_date = date_range[0]
    end_date = date_range[1]
    limit = 1
    
    result = get_result_request(start_date, end_date)

    for item in result:
        json_data = json.loads(item)
        post_status_code = post_data(workspace_id, workspaceKey, json_data, log_type)
        logging.warning("Status Code: {}".format(post_status_code))
            
    logging.info("Processed {} events to Azure Sentinel. Time period: from {} to {}.".format(len(result),start_date, end_date))


def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash.decode('utf-8'))
    return authorization


def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(json.dumps(body))
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,json=body, headers=headers)
    logging.warning(response.text)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('Accepted')
    else:
        print("Response code: {}".format(response.status_code))


def main(timer: func.TimerRequest)  -> None:
    logging.info("DEBUG: Main function")
    if timer.past_due:
        logging.info('DEBUG: The timer is past due!')
    logging.info('DEBUG: Starting program')
    get_result(generate_date())

