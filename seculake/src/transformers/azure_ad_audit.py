#!/usr/bin/env python3
# coding: utf-8

# From: Azure AD Audit
# To: OCSF Cloud API [99938001]

from datetime import datetime
# noinspection PyPackages
from .transformer import transform


def time_formating_function(original_data):
    parts = original_data["activityDateTime"].split(".")

    if len(parts) == 1:
        date = original_data["activityDateTime"]
    else:
        date = parts[0]

    return datetime.strptime(date.split("Z")[0], "%Y-%m-%dT%H:%M:%S")


def data_transformation_function(original_data):
    unmapped = {
        "category": original_data["category"],
        "operationType": original_data["operationType"],
        "targetResources": original_data["targetResources"],
        "additionalDetails": original_data["additionalDetails"]
    }

    if original_data["initiatedBy"]["user"]:
        src_endpoint = {
            "ip": original_data["initiatedBy"]["user"]["ipAddress"],
        }

        unmapped["user"] = {
            "email_addr": original_data["initiatedBy"]["user"]["userPrincipalName"],
            "uid": original_data["initiatedBy"]["user"]["id"]
        }
    elif original_data["initiatedBy"]["app"]:
        src_endpoint = {
            "svc_name": original_data["initiatedBy"]["app"]["displayName"],
            "uid": original_data["initiatedBy"]["app"]["appId"],
        }
    else:
        src_endpoint = None

    return {
        "activity_name": "IAM",
        "activity_id": 2,
        "category_name": "Cloud Activity",
        "category_uid": 99938,
        "class_name": "Cloud API",
        "class_uid": 99938001,
        "time": int(time_formating_function(original_data).timestamp()),
        "message": original_data["activityDisplayName"],
        "metadata": {
            "correlation_uid": original_data["correlationId"],
            "uid": original_data["id"],
            'product': {
                'vendor_name': 'Microsoft',
                'name': original_data["loggedByService"]
            },
            'version': '1.0.0-rc2'
        },
        "severity": "Informational",
        "severity_id": 1,
        "src_endpoint": src_endpoint,
        "status": "Success" if original_data["result"] == "success" else "Failure",
        "status_detail": original_data["resultReason"],
        "status_id": 1 if original_data["result"] == "success" else 2,
        "type_uid": 9993800102,
        "type_name": "Cloud API: IAM",
        "unmapped": unmapped
    }


def main(event, context):
    return transform(event, context, time_formating_function, data_transformation_function)
