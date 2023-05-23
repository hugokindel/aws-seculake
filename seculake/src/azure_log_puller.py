#!/usr/bin/env python3
# coding: utf-8

import os
import msal
import json
import boto3
import logging
import argparse
import requests
from datetime import timedelta, datetime
from enum import Enum


class AzureAdLogTypes(str, Enum):
    """
    Azure AD log types.
    """
    SIGN_IN = "signIns"
    AUDIT = "directoryAudits"


def pull_log_channel_from_azure_ad(graph_url, log_type, token):
    """
    Pulls a log channel from Azure Active Directory.

    Parameters
    ----------
    graph_url: str
        The Azure Graph API URL.
    log_type: AzureAdLogTypes
        The log type to pull.
    token: dict
        The token to use to authenticate to Azure.

    Returns
    -------
    list
        The list of log records.
    """
    logging.info(f"Pulling Azure AD '{log_type}' log records...")

    filter_name = "createdDateTime" if log_type == AzureAdLogTypes.SIGN_IN else "activityDateTime"
    # Floor to the latest 5 minutes timeframe (e.g. %Y-%m-%dT%H:10:00Z, %Y-%m-%dT%H:25:00Z, ...).
    utcnow = ((datetime.utcnow()) - timedelta(minutes=datetime.utcnow().minute % 5))
    date_min_str = (utcnow - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:00Z")
    date_max_str = (utcnow - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:00Z")

    rq = f"{graph_url}/auditLogs/{log_type}?$filter={filter_name} ge {date_min_str} and {filter_name} lt {date_max_str}"

    logging.info(f"GET:  {rq}")

    r = requests.get(rq, headers=token)

    logging.info(r.content.decode("utf-8"))

    if r.ok:
        logs = r.json()["value"]
        logging.info(f"Successfully pulled {len(logs)} log record(s) from Azure AD '{log_type}'.")
        return logs

    logging.critical(f"Failed to pull log records from Azure AD '{log_type}'.")
    logging.critical("Make sure the app registration has the following applicative permissions: "
                     "`AuditLog.Read.All` and `Directory.Read.All`.")
    return []


def pull_all_logs_from_azure_ad(azure_client_id, azure_client_secret, azure_tenant_id):
    """
    Pulls all logs from Azure Active Directory.

    Parameters
    ----------
    azure_client_id: str
        The Azure application's client ID.
    azure_client_secret: str
        The Azure application's client secret.
    azure_tenant_id: str
        The Azure environment tenant ID.

    Returns
    -------
    list
        The list of Azure AD Sign-In and Audit logs.
    """
    authority = f"https://login.microsoftonline.com/{azure_tenant_id}"
    scopes = ["https://graph.microsoft.com/.default"]
    graph_url = "https://graph.microsoft.com/v1.0"

    # Connects to MSAL API.
    app = msal.ConfidentialClientApplication(client_id=azure_client_id, client_credential=azure_client_secret,
                                             authority=authority)

    # Check for a suitable token in cache.
    token_request = app.acquire_token_silent(scopes, account=None)

    # If there is no suitable token in cache, tries to get a new one from AAD.
    if not token_request:
        token_request = app.acquire_token_for_client(scopes=scopes)

    # If we did not successfully get a suitable token, prints the error and exits.
    if "access_token" not in token_request:
        logging.critical(token_request.get("error"))
        logging.critical(token_request.get("error_description"))
        logging.critical(token_request.get("correlation_id"))
        return 1

    # Prepares the token for the next requests.
    token = {"Authorization": f"Bearer {token_request['access_token']}"}

    # Get all recent logs.
    logs_azure_ad_sign_in = pull_log_channel_from_azure_ad(graph_url, AzureAdLogTypes.SIGN_IN, token)
    logs_azure_ad_audit = pull_log_channel_from_azure_ad(graph_url, AzureAdLogTypes.AUDIT, token)

    return logs_azure_ad_sign_in, logs_azure_ad_audit


def send_logs_through_firehose(firehose, stream_name, records):
    """
    Sends a list of logs to a given AWS Firehose.

    Parameters
    ----------
    firehose: boto3.client
        The AWS Firehose client.
    stream_name: str
        The AWS Firehose stream name.
    records: list
        The list of records to send.

    Returns
    -------
    int
        The number of failures.
    """
    logging.info(f"Sending {len(records)} log record(s) to Firehose stream '{stream_name}'...")

    r = firehose.put_record_batch(DeliveryStreamName=stream_name,
                                  Records=[{"Data": json.dumps(x).encode("utf-8")} for x in
                                           records])

    if r["FailedPutCount"] == 0:
        logging.critical(f"Successfully sent all log records.")
    else:
        logging.critical(f"{r['FailedPutCount']} record(s) might have failed to be sent.")

    return r["FailedPutCount"]


# noinspection PyUnusedLocal
def main(event, context):
    """
    Extracts JSON logs from security events in an Azure Active Directory.

    Parameters
    ----------
    event: dict
        The event which triggered this function.
    context: Context
        The context of the function.

    Returns
    -------
    int
        The error code.
    """
    parser = argparse.ArgumentParser(
        description="Tool to extract JSON logs from various sources and send them to different Firehose streams.\n"
        "\n"
        "You need to define multiple environment variables:\n"
        "- AZURE_CLIENT_ID:                 Azure application's secretsmanager ID.\n"
        "- AZURE_CLIENT_SECRET:             Azure application's secretsmanager secret.\n"
        "- AZURE_TENANT_ID:                 Azure environment tenant ID.\n"
        "- AWS_REGION:                      AWS region where the resources lives (no need to define it in Lambda).\n"
        "- AWS_SECRETSMANAGER_SECRET_ID:    AWS secret ID where the secrets are stored.\n"
        "- AWS_FIREHOSE_AZURE_AD_SIGN_IN:   AWS firehose stream name where the Azure AD Sign-In data is sent.\n"
        "- AWS_FIREHOSE_AZURE_AD_AUDIT:     AWS firehose stream name where the Azure AD Audit data is sent.\n",
        formatter_class=argparse.RawTextHelpFormatter)
    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)

    aws_region = os.environ.get("AWS_REGION", "")

    if not aws_region:
        logging.critical("You need to specify an AWS region (AWS_REGION).")
        return 1

    azure_client_id = os.environ.get("AZURE_CLIENT_ID", "")
    azure_client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")
    azure_tenant_id = os.environ.get("AZURE_TENANT_ID", "")
    aws_secretsmanager_secret_id = os.environ.get("AWS_SECRETSMANAGER_SECRET_ID", "")
    aws_firehose_azure_ad_sign_in = os.environ.get("AWS_FIREHOSE_AZURE_AD_SIGN_IN", "")
    aws_firehose_azure_ad_audit = os.environ.get("AWS_FIREHOSE_AZURE_AD_AUDIT", "")

    session = boto3.session.Session()

    if aws_secretsmanager_secret_id:
        secretsmanager = session.client(service_name="secretsmanager", region_name=aws_region)

        try:
            secrets = json.loads(secretsmanager.get_secret_value(SecretId=aws_secretsmanager_secret_id)["SecretString"])

            if not azure_client_id and "AZURE_CLIENT_ID" in secrets:
                azure_client_id = secrets["AZURE_CLIENT_ID"]
            if not azure_client_secret and "AZURE_CLIENT_SECRET" in secrets:
                azure_client_secret = secrets["AZURE_CLIENT_SECRET"]
            if not azure_tenant_id and "AZURE_TENANT_ID" in secrets:
                azure_tenant_id = secrets["AZURE_TENANT_ID"]
            if not aws_firehose_azure_ad_sign_in and "AWS_FIREHOSE_AZURE_AD_SIGN_IN" in secrets:
                aws_firehose_azure_ad_sign_in = secrets["AWS_FIREHOSE_AZURE_AD_SIGN_IN"]
            if not aws_firehose_azure_ad_audit and "AWS_FIREHOSE_AZURE_AD_AUDIT" in secrets:
                aws_firehose_azure_ad_audit = secrets["AWS_FIREHOSE_AZURE_AD_AUDIT"]
        except Exception as error:
            logging.critical(error)

    if not azure_client_id or not azure_client_secret or not azure_tenant_id or not aws_firehose_azure_ad_sign_in \
       or not aws_firehose_azure_ad_audit:
        if not azure_client_id:
            logging.critical("You need to specify an Azure client ID (AZURE_CLIENT_ID).")
        if not azure_client_secret:
            logging.critical("You need to specify an Azure client secret (AZURE_CLIENT_SECRET).")
        if not azure_tenant_id:
            logging.critical("You need to specify an Azure tenant ID (AZURE_TENANT_ID).")
        if not aws_firehose_azure_ad_sign_in:
            logging.critical("You need to specify an AWS Firehose stream name (AWS_FIREHOSE_AZURE_AD_SIGN_IN).")
        if not aws_firehose_azure_ad_audit:
            logging.critical("You need to specify an AWS Firehose stream name (AWS_FIREHOSE_AZURE_AD_AUDIT).")
        return 1

    logs_azure_ad_sign_in, logs_azure_ad_audit = pull_all_logs_from_azure_ad(azure_client_id, azure_client_secret,
                                                                             azure_tenant_id)

    len_logs = len(logs_azure_ad_sign_in) + len(logs_azure_ad_audit)

    if len_logs > 0:
        logging.info(f"{len_logs} record(s) to send.")

        num_failures = 0

        firehose = session.client("firehose", region_name=aws_region)

        if len(logs_azure_ad_sign_in) > 0:
            num_failures += send_logs_through_firehose(firehose, aws_firehose_azure_ad_sign_in, logs_azure_ad_sign_in)
        if len(logs_azure_ad_audit) > 0:
            num_failures += send_logs_through_firehose(firehose, aws_firehose_azure_ad_audit, logs_azure_ad_audit)

        if num_failures == 0:
            logging.critical("Record(s) sent successfully.")
        else:
            logging.critical(f"{num_failures} record(s) might have failed to be sent.")
    else:
        logging.info("Nothing to send.")

    return 0


if __name__ == '__main__':
    exit(main({}, None))
