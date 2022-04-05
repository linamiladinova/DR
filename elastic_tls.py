import json
from elasticsearch import Elasticsearch
from datetime import datetime
import argparse
import csv
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
    es = Elasticsearch(f"http://{elastic_ip}:{elastic_port}")
    if debug is True:
        print(es)

    res = es.search(
        index='packetbeat-*',
        body = {
            "aggs": {
                "2": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "12h",
                    "time_zone": "Europe/Sofia",
                    "min_doc_count": 1
                },
                "aggs": {
                    "3": {
                    "terms": {
                        "field": "tls.established",
                        "order": {
                        "_count": "desc"
                        },
                        "size": 5
                    }
                    }
                }
                }
            },
            "size": 0,
            "fields": [
                {
                "field": "@timestamp",
                "format": "date_time"
                },
                {
                "field": "code_signature.timestamp",
                "format": "date_time"
                },
                {
                "field": "dll.code_signature.timestamp",
                "format": "date_time"
                },
                {
                "field": "elf.creation_date",
                "format": "date_time"
                },
                {
                "field": "event.created",
                "format": "date_time"
                },
                {
                "field": "event.end",
                "format": "date_time"
                },
                {
                "field": "event.ingested",
                "format": "date_time"
                },
                {
                "field": "event.start",
                "format": "date_time"
                },
                {
                "field": "file.accessed",
                "format": "date_time"
                },
                {
                "field": "file.code_signature.timestamp",
                "format": "date_time"
                },
                {
                "field": "file.created",
                "format": "date_time"
                },
                {
                "field": "file.ctime",
                "format": "date_time"
                },
                {
                "field": "file.elf.creation_date",
                "format": "date_time"
                },
                {
                "field": "file.mtime",
                "format": "date_time"
                },
                {
                "field": "file.x509.not_after",
                "format": "date_time"
                },
                {
                "field": "file.x509.not_before",
                "format": "date_time"
                },
                {
                "field": "package.installed",
                "format": "date_time"
                },
                {
                "field": "process.code_signature.timestamp",
                "format": "date_time"
                },
                {
                "field": "process.elf.creation_date",
                "format": "date_time"
                },
                {
                "field": "process.end",
                "format": "date_time"
                },
                {
                "field": "process.parent.code_signature.timestamp",
                "format": "date_time"
                },
                {
                "field": "process.parent.elf.creation_date",
                "format": "date_time"
                },
                {
                "field": "process.parent.end",
                "format": "date_time"
                },
                {
                "field": "process.parent.start",
                "format": "date_time"
                },
                {
                "field": "process.start",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.file.accessed",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.file.code_signature.timestamp",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.file.created",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.file.ctime",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.file.elf.creation_date",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.file.mtime",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.first_seen",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.last_seen",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.modified_at",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.x509.not_after",
                "format": "date_time"
                },
                {
                "field": "threat.enrichments.indicator.x509.not_before",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.file.accessed",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.file.code_signature.timestamp",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.file.created",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.file.ctime",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.file.elf.creation_date",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.file.mtime",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.first_seen",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.last_seen",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.modified_at",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.x509.not_after",
                "format": "date_time"
                },
                {
                "field": "threat.indicator.x509.not_before",
                "format": "date_time"
                },
                {
                "field": "tls.client.not_after",
                "format": "date_time"
                },
                {
                "field": "tls.client.not_before",
                "format": "date_time"
                },
                {
                "field": "tls.client.x509.not_after",
                "format": "date_time"
                },
                {
                "field": "tls.client.x509.not_before",
                "format": "date_time"
                },
                {
                "field": "tls.client_certificate.not_after",
                "format": "date_time"
                },
                {
                "field": "tls.client_certificate.not_before",
                "format": "date_time"
                },
                {
                "field": "tls.detailed.client_certificate.not_after",
                "format": "date_time"
                },
                {
                "field": "tls.detailed.client_certificate.not_before",
                "format": "date_time"
                },
                {
                "field": "tls.detailed.server_certificate.not_after",
                "format": "date_time"
                },
                {
                "field": "tls.detailed.server_certificate.not_before",
                "format": "date_time"
                },
                {
                "field": "tls.server.not_after",
                "format": "date_time"
                },
                {
                "field": "tls.server.not_before",
                "format": "date_time"
                },
                {
                "field": "tls.server.x509.not_after",
                "format": "date_time"
                },
                {
                "field": "tls.server.x509.not_before",
                "format": "date_time"
                },
                {
                "field": "tls.server_certificate.not_after",
                "format": "date_time"
                },
                {
                "field": "tls.server_certificate.not_before",
                "format": "date_time"
                },
                {
                "field": "x509.not_after",
                "format": "date_time"
                },
                {
                "field": "x509.not_before",
                "format": "date_time"
                }
            ],
            "script_fields": {},
            "stored_fields": [
                "*"
            ],
            "runtime_mappings": {},
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                "must": [],
                "filter": [
                    {
                    "exists": {
                        "field": "tls.established"
                    }
                    },
                    {
                    "range": {
                        "@timestamp": {
                        "format": "strict_date_optional_time",
                        "gte": "now-15d",
                        "lte": "now"
                        }
                    }
                    }
                ],
                "should": [],
                "must_not": []
                }
            }
        }
    )

    if debug is True:
        print(es)

    # print(res["aggregations"]["2"]["buckets"])
    buckets = []
    for bucket in res["aggregations"]["2"]["buckets"]:
        buckets.append({'time':bucket["key_as_string"], 'count':bucket["doc_count"]})

    sum_counts = 0
    for bucket in buckets:
        sum_counts += bucket['count']
        print(f"time: {bucket['time']} count {bucket['count']}")

    header = ["time", "count", "baseline"]

    f = open('tls.csv', 'w')
    writer = csv.writer(f)
    writer.writerow(header)

    baseline = sum_counts / len(buckets)
    print(f"baseline: {baseline}")

    for bucket in buckets:
        writer.writerow([bucket["time"], bucket["count"], baseline])

    allowed_deviation = baseline / 5 # 20% of baseline
    last_val = buckets[-1]["count"] 
    if (last_val > baseline + allowed_deviation or last_val < baseline - allowed_deviation):
        print("Losha shema")


    # for i in range (0, res['hits']['total']['value']-1):
    #     if debug is True:
    #         print("Timestamp -> " + res['hits']['hits'][i]['_source']['@timestamp'])
    #         print("Destination IP -> " + res['hits']['hits'][i]['_source']['destination']['ip'])

except Exception as e:
    print(e)