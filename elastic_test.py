import json
from elasticsearch import Elasticsearch
from datetime import datetime
import argparse
import time
import sys

# Parse Arguments
parser = argparse.ArgumentParser()
parser.add_argument("elastic_ip", help = "The IP of the Elasticsearch")
parser.add_argument("elastic_port", help = "Port of the Elasticsearch")
parser.add_argument("--debug", help = "Enable debug information", type=bool)
args = parser.parse_args()

debug = args.debug
elastic_ip = args.elastic_ip
elastic_port = args.elastic_port

if debug is True:
    print("Elastic IP: " + elastic_ip)
    print("Elastic port: " + elastic_port)

try:
    if debug is True:
        print("Sending query...")

    # Connect to the elastic cluster
    es=Elasticsearch([{"https://localhost:9200"}])
    if debug is True:
        print(es)

    res = es.search(index="packetbeat-*",
        body={'query':{"range": {"@timestamp": {"gt": "now-1w/w", "lt": "now"}}},
        "fields": ["@timestamp","destination.ip"],
        "sort": [{"@timestamp": {"order": "desc"}}]},
        size=5
    )

    if debug is True:
        print(es)

    for i in range (0, res['hits']['total']['value']-1):
        if debug is True:
            print("Timestamp -> " + res['hits']['hits'][i]['_source']['@timestamp'])
            print("Destination IP -> " + res['hits']['hits'][i]['_source']['destination']['ip'])

except Exception as e:
    print(e)
