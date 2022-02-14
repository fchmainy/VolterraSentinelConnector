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
workspace_key = os.environ['WORKSPACE_KEY']
authToken = os.environ['AUTH_TOKEN']

volterraTenant = os.environ['VOLTERRA_TENANT']
namespace = os.environ['VOLTERRA_NAMESPACE']

connection_string = os.environ['CONNECTION_STRING']

log_type = 'LOG_TYPE'
events_api_endpoint = "https://" + volterraTenant + ".console.ves.volterra.io/api/data/namespaces/" + namespace + "/app_security/events"


def generate_date():
    current_date = datetime.datetime.utcnow().replace(second=0, microsecond=0) - datetime.timedelta(minutes=10)
    state = StateManager(connection_string=connection_string)
    previous_date = state.get()
    if previous_date is not None:
        logging.info("The latest time stamp is: {}".format(past_time))
    else:
        logging.info("There is no previous timestamp, trying to get events for the last hour.")
        previous_date = (current_date - datetime.timedelta(minutes=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    state.post(current_date.strftime("%Y-%m-%dT%H:%M:%SZ"))
    return (previous_date, current_time.strftime("%Y-%m-%dT%H:%M:%SZ"))


def get_result_request(start_date, end_date, limit):
    try:

        headers = {
            'Authorization': 'APIToken ' + authToken,
            'Content-Type': 'application/json'
        }

        body = {
            'start_time': start_date,
            'end_time': end_date,
            'namespace': namespace, 
            'limit': 1
        }

        r = requests.post(events_api_endpoint,
                            headers=headers,
                            data=json.dumps(body)
                         )
        if r.status_code == 200:
            return r.json().get("records")
        elif r.status_code == 401:
            logging.error("The authentication token may be incorrect. Error code: {}".format(r.status_code))
        elif r.status_code == 403:
            logging.error("Check permissions. Error code: {}".format(r.status_code))
        else:
            logging.error("Something wrong. Error code: {}".format(r.status_code))
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))


def get_result(date_range):
    start_date = time_range[0]
    end_date = time_range[1]
    limit = 1
    element_count = None
    global_element_count = 0
    while element_count != 0:
        result = get_result_request(start_date, end_date, limit)
        element_count = len(result.json())
        if offset == 0 and element_count == 0:
            logging.info("No events were found. Time period: from {} to {}.".format(from_time,to_time))
        elif offset != 0 and element_count != 0:
            logging.info("Processing {} events".format(element_count))
        
        if element_count > 0:
            post_status_code = post_data(workspace_id, workspace_key, json.dumps(result), log_type)
            
    logging.info("Processed {} events to Azure Sentinel. Time period: from {} to {}.".format(global_element_count,from_time, to_time))


def build_signature(workspaceID, workspaceKEY, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash).encode('utf-8')
    decoded_key = base64.b64decode(workspaceKEY)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(workspaceID,encoded_hash)
    return authorization


def post_data(workspaceID, workspaceKEY, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(workspaceID, workspaceKEY, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + workspaceID + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print 'Accepted'
        print 'Response: ' + str(response)
        return response.status_code
    else:
        print "Response code: {}".format(response.status_code)
        return None


def main(timer: func.TimerRequest)  -> None:
    if timer.past_due:
        logging.info('The timer is past due!')
    logging.info('Starting program')
    get_result(generate_date())

