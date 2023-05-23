#!/usr/bin/env python3
# coding: utf-8

import os
import boto3
import logging
import argparse


# noinspection PyUnusedLocal
def main(event, context):
    """
    Updates the partitions of seculake Glue tables when new content is added to the S3 to make it available in Athena.

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
        description="Updates the partitions of seculake Glue tables when new content is added to the S3 to make it "
        "available in Athena.\n"
        "\n"
        "You need to define multiple environment variables:\n"
        "- AWS_REGION:                            AWS region where the resources lives (no need to define it in "
                    "Lambda).\n"
        "- AZURE_AD_SIGN_IN_FOLDER_PATH:          Azure AD sign-in logs folder path.\n"
        "- AZURE_AD_AUDIT_FOLDER_PATH:            Azure AD audit logs folder path.\n"
        "- AWS_CLOUD_TRAIL_FOLDER_PATH:           AWS CloudTrail logs folder path.\n"
        "- AWS_ROUTE53_FOLDER_PATH:               AWS Route53 logs folder path.\n"
        "- AWS_VPC_FLOW_LOGS_FOLDER_PATH:         AWS VPC Flow Logs folder path.\n"
        "- AWS_SECURITY_FINDINGS_FOLDER_PATH:     AWS Security Findings folder path.\n"
        "- AWS_GLUE_DATABASE:                     AWS Glue database name.\n"
        "- AWS_GLUE_AZURE_SIGN_IN_TABLE:          AWS Glue table name for the sign-in logs.\n"
        "- AWS_GLUE_AZURE_AUDIT_TABLE:            AWS Glue table name for the audit logs.\n"
        "- AWS_GLUE_AWS_CLOUD_TRAIL_TABLE:        AWS Glue table name for the CloudTrail logs.\n"
        "- AWS_GLUE_AWS_ROUTE53_TABLE:            AWS Glue table name for the Route53 logs.\n"
        "- AWS_GLUE_AWS_VPC_FLOW_LOGS_TABLE:      AWS Glue table name for the VPC Flow Logs.\n"
        "- AWS_GLUE_AWS_SECURITY_FINDINGS_TABLE:  AWS Glue table name for the Security Findings.\n",
        formatter_class=argparse.RawTextHelpFormatter)
    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)

    aws_region = os.environ.get("AWS_REGION", "")

    if not aws_region:
        logging.critical("You need to specify an AWS region (AWS_REGION).")
        return 1

    azure_sign_in_folder_path = os.environ.get("AZURE_AD_SIGN_IN_FOLDER_PATH", "")
    azure_audit_folder_path = os.environ.get("AZURE_AD_AUDIT_FOLDER_PATH", "")
    aws_cloud_trail_folder_path = os.environ.get("AWS_CLOUD_TRAIL_FOLDER_PATH", "")
    aws_route53_folder_path = os.environ.get("AWS_ROUTE53_FOLDER_PATH", "")
    aws_vpc_flow_logs_folder_path = os.environ.get("AWS_VPC_FLOW_LOGS_FOLDER_PATH", "")
    aws_security_findings_folder_path = os.environ.get("AWS_SECURITY_FINDINGS_FOLDER_PATH", "")
    aws_glue_database = os.environ.get("AWS_GLUE_DATABASE", "")
    aws_glue_azure_sign_in_table = os.environ.get("AWS_GLUE_AZURE_SIGN_IN_TABLE", "")
    aws_glue_azure_audit_table = os.environ.get("AWS_GLUE_AZURE_AUDIT_TABLE", "")
    aws_glue_aws_cloudtrail_table = os.environ.get("AWS_GLUE_AWS_CLOUD_TRAIL_TABLE", "")
    aws_glue_aws_route53_table = os.environ.get("AWS_GLUE_AWS_ROUTE53_TABLE", "")
    aws_glue_aws_vpc_flow_logs_table = os.environ.get("AWS_GLUE_AWS_VPC_FLOW_LOGS_TABLE", "")
    aws_glue_aws_security_findings_table = os.environ.get("AWS_GLUE_AWS_SECURITY_FINDINGS_TABLE", "")

    if not azure_sign_in_folder_path or not azure_audit_folder_path:
        if not azure_sign_in_folder_path:
            logging.critical("You need to specify the Azure AD Sign-In folder path (AZURE_AD_SIGN_IN_FOLDER_PATH).")
        if not azure_audit_folder_path:
            logging.critical("You need to specify the Azure AD Audit folder path (AZURE_AD_AUDIT_FOLDER_PATH).")
        if not aws_cloud_trail_folder_path:
            logging.critical("You need to specify the AWS Cloud Trail folder path (AWS_CLOUD_TRAIL_FOLDER_PATH).")
        if not aws_route53_folder_path:
            logging.critical("You need to specify the AWS Route 53 folder path (AWS_ROUTE53_FOLDER_PATH).")
        if not aws_vpc_flow_logs_folder_path:
            logging.critical("You need to specify the AWS VPC Flow Logs folder path (AWS_VPC_FLOW_LOGS_FOLDER_PATH).")
        if not aws_security_findings_folder_path:
            logging.critical("You need to specify the AWS Security Findings folder path ("
                             "AWS_SECURITY_FINDINGS_FOLDER_PATH).")
        if not aws_glue_database:
            logging.critical("You need to specify the AWS Glue database name (AWS_GLUE_DATABASE).")
        if not aws_glue_azure_sign_in_table:
            logging.critical("You need to specify the AWS Glue Azure Sign-In table name (AWS_GLUE_AZURE_SIGN_IN_TABLE)"
                             ".")
        if not aws_glue_azure_audit_table:
            logging.critical("You need to specify the AWS Glue Azure Audit table name (AWS_GLUE_AZURE_AUDIT_TABLE).")
        if not aws_glue_aws_cloudtrail_table:
            logging.critical("You need to specify the AWS Glue AWS Cloud Trail table name ("
                             "AWS_GLUE_AWS_CLOUD_TRAIL_TABLE).")
        if not aws_glue_aws_route53_table:
            logging.critical("You need to specify the AWS Glue AWS Route 53 table name (AWS_GLUE_AWS_ROUTE53_TABLE).")
        if not aws_glue_aws_vpc_flow_logs_table:
            logging.critical("You need to specify the AWS Glue AWS VPC Flow Logs table name ("
                             "AWS_GLUE_AWS_VPC_FLOW_LOGS_TABLE).")
        if not aws_glue_aws_security_findings_table:
            logging.critical("You need to specify the AWS Glue AWS Security Findings table name ("
                             "AWS_GLUE_AWS_SECURITY_FINDINGS_TABLE).")
        return 1

    session = boto3.session.Session()

    glue = session.client(service_name="glue", region_name=aws_region)

    logging.info(f"Event: {event}")

    for record in event["Records"]:
        bucket_name = record["s3"]["bucket"]["name"]
        object_key = record["s3"]["object"]["key"].replace("%3D", "=")

        if object_key.startswith(azure_sign_in_folder_path) or object_key.startswith(azure_audit_folder_path):
            partitions = [
                object_key.split("event_hour=")[1].split("/")[0]
            ]
        else:
            partitions = [
                object_key.split("region=")[1].split("/")[0],
                object_key.split("account_id=")[1].split("/")[0],
                object_key.split("event_hour=")[1].split("/")[0]
            ]

        if object_key.startswith(azure_sign_in_folder_path):
            aws_glue_table = aws_glue_azure_sign_in_table
        elif object_key.startswith(azure_audit_folder_path):
            aws_glue_table = aws_glue_azure_audit_table
        elif object_key.startswith(aws_cloud_trail_folder_path):
            aws_glue_table = aws_glue_aws_cloudtrail_table
        elif object_key.startswith(aws_route53_folder_path):
            aws_glue_table = aws_glue_aws_route53_table
        elif object_key.startswith(aws_vpc_flow_logs_folder_path):
            aws_glue_table = aws_glue_aws_vpc_flow_logs_table
        elif object_key.startswith(aws_security_findings_folder_path):
            aws_glue_table = aws_glue_aws_security_findings_table
        else:
            logging.critical(f"Unknown object key: {object_key}")
            return 1

        partition_input = {
            "Values": partitions,
            "StorageDescriptor": {
                "Location": f"s3://{bucket_name}/{object_key.rsplit('/', 1)[0]}",
                "Compressed": False,
                "NumberOfBuckets": 0,
                "StoredAsSubDirectories": False,
                "InputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
                },
                "Parameters": {
                    "partition.filtering": "true"
                },
                "Columns": [],
                "SortColumns": [],
            }
        }

        logging.info(f"Bucket name: {bucket_name}")
        logging.info(f"Creating partition in {aws_glue_database}/{aws_glue_table}: {partitions}")
        logging.info(f"Partition input: {partition_input}")

        try:
            r = glue.create_partition(DatabaseName=aws_glue_database, TableName=aws_glue_table,
                                      PartitionInput=partition_input)
            logging.info(f"Partition created: {partitions}")
        except glue.exceptions.AlreadyExistsException:
            logging.info(f"Partition already exists: {partitions}")
        except Exception as e:
            logging.critical(f"Error while creating partition: {e}")
            return 1

    return 0
