#!/usr/bin/env python3
# coding: utf-8

# From: Azure AD Sign-in
# To: OCSF Authentication [3002]

from datetime import datetime
# noinspection PyPackages
from .transformer import transform


def time_formating_function(original_data):
    parts = original_data["createdDateTime"].split(".")

    if len(parts) == 1:
        date = original_data["createdDateTime"]
    else:
        date = parts[0]

    return datetime.strptime(date.split("Z")[0], "%Y-%m-%dT%H:%M:%S")


def data_transformation_function(original_data):
    if original_data["status"]["additionalDetails"]:
        message = original_data["status"]["additionalDetails"]
    elif original_data["status"]["errorCode"] == 0:
        message = "Authentication successful"
    else:
        message = "Authentication failed"

    return {
        "activity_name": "Logon",
        "activity_id": 1,
        "auth_protocol": "Unknown",
        "auth_protocol_id": 0,
        "category_name": "Audit Activity",
        "category_uid": 3,
        "class_name": "Authentication",
        "class_uid": 3002,
        "is_cleartext": False,
        "dst_endpoint": {
            "svc_name": original_data["appDisplayName"],
            "uid": original_data["appId"],
        },
        "time": int(time_formating_function(original_data).timestamp()),
        "logon_type": "Interactive" if original_data["isInteractive"] else "Cached Interactive",
        "logon_type_id": 2 if original_data["isInteractive"] else 11,
        "message": message,
        "metadata": {
            "correlation_uid": original_data["correlationId"],
            "uid": original_data["id"],
            'product': {
                'vendor_name': 'Microsoft',
                'name': original_data["resourceDisplayName"]
            },
            'version': '1.0.0-rc2'
        },
        "severity": "Informational",
        "severity_id": 1,
        "src_endpoint": {
            "location": {
                "city": original_data["location"]["city"],
                "coordinates": [
                    original_data["location"]["geoCoordinates"]["longitude"],
                    original_data["location"]["geoCoordinates"]["latitude"]
                ],
                "country": original_data["location"]["countryOrRegion"],
            },
            "ip": original_data["ipAddress"],
            "svc_name": original_data["clientAppUsed"]
        },
        "status": "Success" if original_data["status"]["errorCode"] == 0 else "Failure",
        "status_code": original_data["status"]["errorCode"],
        "status_detail": original_data["status"]["failureReason"],
        "status_id": 1 if original_data["status"]["errorCode"] == 0 else 2,
        "type_uid": 300201,
        "type_name": "Authentication Audit: Logon",
        "user": {
            "account_type": "Azure AD Account",
            "account_type_id": 6,
            "email_addr": original_data["userPrincipalName"],
            "name": original_data["userDisplayName"],
            "uid": original_data["userId"]
        },
        "unmapped": {
            "conditionalAccessStatus": original_data["conditionalAccessStatus"],
            "resourceId": original_data["resourceId"],
            "deviceDetail": original_data["deviceDetail"],
            "location": {
                "state": original_data["location"]["state"],
            },
            "appliedConditionalAccessPolicies": original_data["appliedConditionalAccessPolicies"]
        }
    }


def main(event, context):
    return transform(event, context, time_formating_function, data_transformation_function)
