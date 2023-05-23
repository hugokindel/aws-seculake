#!/usr/bin/env python3
# coding: utf-8

import os
import threading
import boto3
import logging
import argparse


def bucket_processing(session, from_bucket_name, from_bucket_region, to_bucket_name, to_bucket_region):
    """
    Thread function.

    Parameters
    ----------
    session: Session
        The AWS session.
    to_bucket_region: str
        The region of the destination bucket.
    to_bucket_name: str
        The name of the destination bucket.
    from_bucket_region: str
        The region of the source bucket.
    from_bucket_name: str
        The name of the source bucket.
    """
    from_s3 = session.resource(service_name="s3", region_name=from_bucket_region)
    to_s3 = session.resource(service_name="s3", region_name=to_bucket_region)

    for from_element in from_s3.Bucket(from_bucket_name).objects.all():
        from_object = from_s3.Object(from_bucket_name, from_element.key)

        to_key = from_element.key.replace("accountId=", "account_id=").replace("eventHour=", "event_hour=")

        try:
            from_data = from_object.get()["Body"].read()

            to_s3.Object(to_bucket_name, to_key).put(Body=from_data)
            logging.info(f"Object s3://{from_bucket_name}/{from_element.key} copied to s3://{to_bucket_name}/{to_key}.")

            from_object.delete()
            logging.info(f"Object s3://{from_bucket_name}/{from_element.key} deleted.")
        except Exception as e:
            logging.error(f"Error while handling object s3://{from_bucket_name}/{from_element.key}: {e}")
            continue


# noinspection PyUnusedLocal
def main(event, context):
    """
    Tool to extract JSON logs from AWS Security Lake and store them in an S3 bucket.

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
        description="Tool to extract JSON logs from AWS Security Lake and store them in an S3 bucket.\n",
        formatter_class=argparse.RawTextHelpFormatter)
    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)

    aws_region = os.environ.get("AWS_REGION", "")

    if not aws_region:
        logging.critical("You need to specify an AWS region (AWS_REGION).")
        return 1

    bucket_name = os.environ.get("BUCKET_NAME", "")

    if not bucket_name:
        if not bucket_name:
            logging.critical("You need to specify the bucket name (BUCKET_NAME).")
        return 1

    session = boto3.session.Session()

    client = session.client(service_name="s3", region_name=aws_region)

    threads = []

    r = client.list_buckets()
    for bucket in r["Buckets"]:
        if bucket["Name"].startswith("aws-security-data-lake-"):
            region = client.get_bucket_location(Bucket=bucket["Name"])["LocationConstraint"]
            thread = threading.Thread(target=bucket_processing,
                                      args=(session, bucket["Name"], region, bucket_name, aws_region))
            thread.start()
            threads += [thread]
            logging.info(f"Thread started for bucket {bucket['Name']} in region {region}.")

    for thread in threads:
        thread.join()
        logging.info(f"Thread {thread.name} finished processing.")

    logging.info("All threads finished processing.")

    return 0


if __name__ == '__main__':
    exit(main({}, None))
