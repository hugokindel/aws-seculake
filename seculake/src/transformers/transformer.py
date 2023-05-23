#!/usr/bin/env python3
# coding: utf-8

import json
import base64
import logging


# noinspection PyUnusedLocal
def transform(event, context, time_formating_function, data_transformation_function):
    logging.getLogger().setLevel(logging.INFO)

    logging.info(f"Event: {event}")
    logging.info(f"{len(event['records'])} records received.")

    transformed_records = []

    for original_record in event["records"]:
        original_data = json.loads(base64.b64decode(original_record["data"]).decode("utf8"))

        logging.info(f"Data before transformation: {original_data}")

        transformed_data = data_transformation_function(original_data)

        logging.info(f"Data after transformation: {transformed_data}")

        partition_keys = {
            "event_hour": time_formating_function(original_data).strftime("%Y%m%d%H")
        }

        logging.info(f"Partition keys: {partition_keys}")

        transformed_record = {
            "recordId": original_record["recordId"],
            "result": "Ok",
            "data": base64.b64encode(
                json.dumps(transformed_data, separators=(",", ":")).encode("utf-8") + b"\n").decode("utf-8"),
            "metadata": {"partitionKeys": partition_keys}
        }

        transformed_records.append(transformed_record)

    result = {
        "records": transformed_records
    }

    logging.info(f"Result: {result}")
    logging.info("All records treated.")

    return result
