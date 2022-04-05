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


if debug is True:
    print("Sending query...")

# Connect to the elastic cluster
es = Elasticsearch(f"http://{elastic_ip}:{elastic_port}")
if debug is True:
    print(es)

res = es.search(
    index='filebeat-*',
    body = {
    "aggs": {
        "2": {
        "date_histogram": {
            "field": "event.end",
            "fixed_interval": "5m",
            "time_zone": "Europe/Sofia",
            "min_doc_count": 1
        },
        "aggs": {
            "3": {
            "terms": {
                "field": "netflow.exporter.version",
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
        "field": "aws.cloudtrail.digest.end_time",
        "format": "date_time"
        },
        {
        "field": "aws.cloudtrail.digest.newest_event_time",
        "format": "date_time"
        },
        {
        "field": "aws.cloudtrail.digest.oldest_event_time",
        "format": "date_time"
        },
        {
        "field": "aws.cloudtrail.digest.start_time",
        "format": "date_time"
        },
        {
        "field": "aws.cloudtrail.user_identity.session_context.creation_date",
        "format": "date_time"
        },
        {
        "field": "azure.auditlogs.properties.activity_datetime",
        "format": "date_time"
        },
        {
        "field": "azure.enqueued_time",
        "format": "date_time"
        },
        {
        "field": "azure.signinlogs.properties.created_at",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.agentReceiptTime",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.deviceCustomDate1",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.deviceCustomDate2",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.deviceReceiptTime",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.endTime",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.fileCreateTime",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.fileModificationTime",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.flexDate1",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.managerReceiptTime",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.oldFileCreateTime",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.oldFileModificationTime",
        "format": "date_time"
        },
        {
        "field": "cef.extensions.startTime",
        "format": "date_time"
        },
        {
        "field": "checkpoint.subs_exp",
        "format": "date_time"
        },
        {
        "field": "cisco.amp.threat_hunting.incident_end_time",
        "format": "date_time"
        },
        {
        "field": "cisco.amp.threat_hunting.incident_start_time",
        "format": "date_time"
        },
        {
        "field": "cisco.amp.timestamp_nanoseconds",
        "format": "date_time"
        },
        {
        "field": "code_signature.timestamp",
        "format": "date_time"
        },
        {
        "field": "crowdstrike.event.EndTimestamp",
        "format": "date_time"
        },
        {
        "field": "crowdstrike.event.IncidentEndTime",
        "format": "date_time"
        },
        {
        "field": "crowdstrike.event.IncidentStartTime",
        "format": "date_time"
        },
        {
        "field": "crowdstrike.event.ProcessEndTime",
        "format": "date_time"
        },
        {
        "field": "crowdstrike.event.ProcessStartTime",
        "format": "date_time"
        },
        {
        "field": "crowdstrike.event.StartTimestamp",
        "format": "date_time"
        },
        {
        "field": "crowdstrike.event.Timestamp",
        "format": "date_time"
        },
        {
        "field": "crowdstrike.event.UTCTimestamp",
        "format": "date_time"
        },
        {
        "field": "crowdstrike.metadata.eventCreationTime",
        "format": "date_time"
        },
        {
        "field": "cyberarkpas.audit.iso_timestamp",
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
        "field": "google_workspace.admin.email.log_search_filter.end_date",
        "format": "date_time"
        },
        {
        "field": "google_workspace.admin.email.log_search_filter.start_date",
        "format": "date_time"
        },
        {
        "field": "google_workspace.admin.user.birthdate",
        "format": "date_time"
        },
        {
        "field": "gsuite.admin.email.log_search_filter.end_date",
        "format": "date_time"
        },
        {
        "field": "gsuite.admin.email.log_search_filter.start_date",
        "format": "date_time"
        },
        {
        "field": "gsuite.admin.user.birthdate",
        "format": "date_time"
        },
        {
        "field": "juniper.srx.elapsed_time",
        "format": "date_time"
        },
        {
        "field": "juniper.srx.epoch_time",
        "format": "date_time"
        },
        {
        "field": "juniper.srx.timestamp",
        "format": "date_time"
        },
        {
        "field": "kafka.block_timestamp",
        "format": "date_time"
        },
        {
        "field": "microsoft.defender_atp.lastUpdateTime",
        "format": "date_time"
        },
        {
        "field": "microsoft.defender_atp.resolvedTime",
        "format": "date_time"
        },
        {
        "field": "microsoft.m365_defender.alerts.creationTime",
        "format": "date_time"
        },
        {
        "field": "microsoft.m365_defender.alerts.lastUpdatedTime",
        "format": "date_time"
        },
        {
        "field": "microsoft.m365_defender.alerts.resolvedTime",
        "format": "date_time"
        },
        {
        "field": "misp.campaign.first_seen",
        "format": "date_time"
        },
        {
        "field": "misp.campaign.last_seen",
        "format": "date_time"
        },
        {
        "field": "misp.intrusion_set.first_seen",
        "format": "date_time"
        },
        {
        "field": "misp.intrusion_set.last_seen",
        "format": "date_time"
        },
        {
        "field": "misp.observed_data.first_observed",
        "format": "date_time"
        },
        {
        "field": "misp.observed_data.last_observed",
        "format": "date_time"
        },
        {
        "field": "misp.report.published",
        "format": "date_time"
        },
        {
        "field": "misp.threat_indicator.valid_from",
        "format": "date_time"
        },
        {
        "field": "misp.threat_indicator.valid_until",
        "format": "date_time"
        },
        {
        "field": "netflow.collection_time_milliseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.exporter.timestamp",
        "format": "date_time"
        },
        {
        "field": "netflow.flow_end_microseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.flow_end_milliseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.flow_end_nanoseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.flow_end_seconds",
        "format": "date_time"
        },
        {
        "field": "netflow.flow_start_microseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.flow_start_milliseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.flow_start_nanoseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.flow_start_seconds",
        "format": "date_time"
        },
        {
        "field": "netflow.max_export_seconds",
        "format": "date_time"
        },
        {
        "field": "netflow.max_flow_end_microseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.max_flow_end_milliseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.max_flow_end_nanoseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.max_flow_end_seconds",
        "format": "date_time"
        },
        {
        "field": "netflow.min_export_seconds",
        "format": "date_time"
        },
        {
        "field": "netflow.min_flow_start_microseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.min_flow_start_milliseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.min_flow_start_nanoseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.min_flow_start_seconds",
        "format": "date_time"
        },
        {
        "field": "netflow.monitoring_interval_end_milli_seconds",
        "format": "date_time"
        },
        {
        "field": "netflow.monitoring_interval_start_milli_seconds",
        "format": "date_time"
        },
        {
        "field": "netflow.observation_time_microseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.observation_time_milliseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.observation_time_nanoseconds",
        "format": "date_time"
        },
        {
        "field": "netflow.observation_time_seconds",
        "format": "date_time"
        },
        {
        "field": "netflow.system_init_time_milliseconds",
        "format": "date_time"
        },
        {
        "field": "okta.debug_context.debug_data.suspicious_activity.timestamp",
        "format": "date_time"
        },
        {
        "field": "package.installed",
        "format": "date_time"
        },
        {
        "field": "panw.panos.factorcompletiontime",
        "format": "date_time"
        },
        {
        "field": "pensando.dfw.timestamp",
        "format": "date_time"
        },
        {
        "field": "postgresql.log.session_start_time",
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
        "field": "rsa.internal.lc_ctime",
        "format": "date_time"
        },
        {
        "field": "rsa.internal.time",
        "format": "date_time"
        },
        {
        "field": "rsa.time.effective_time",
        "format": "date_time"
        },
        {
        "field": "rsa.time.endtime",
        "format": "date_time"
        },
        {
        "field": "rsa.time.event_queue_time",
        "format": "date_time"
        },
        {
        "field": "rsa.time.event_time",
        "format": "date_time"
        },
        {
        "field": "rsa.time.expire_time",
        "format": "date_time"
        },
        {
        "field": "rsa.time.recorded_time",
        "format": "date_time"
        },
        {
        "field": "rsa.time.stamp",
        "format": "date_time"
        },
        {
        "field": "rsa.time.starttime",
        "format": "date_time"
        },
        {
        "field": "snyk.vulnerabilities.disclosure_time",
        "format": "date_time"
        },
        {
        "field": "snyk.vulnerabilities.introduced_date",
        "format": "date_time"
        },
        {
        "field": "snyk.vulnerabilities.publication_time",
        "format": "date_time"
        },
        {
        "field": "sophos.xg.date",
        "format": "date_time"
        },
        {
        "field": "sophos.xg.eventtime",
        "format": "date_time"
        },
        {
        "field": "sophos.xg.start_time",
        "format": "date_time"
        },
        {
        "field": "sophos.xg.starttime",
        "format": "date_time"
        },
        {
        "field": "sophos.xg.timestamp",
        "format": "date_time"
        },
        {
        "field": "suricata.eve.alert.created_at",
        "format": "date_time"
        },
        {
        "field": "suricata.eve.alert.updated_at",
        "format": "date_time"
        },
        {
        "field": "suricata.eve.tls.notafter",
        "format": "date_time"
        },
        {
        "field": "suricata.eve.tls.notbefore",
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
        "field": "threatintel.anomali.modified",
        "format": "date_time"
        },
        {
        "field": "threatintel.anomali.valid_from",
        "format": "date_time"
        },
        {
        "field": "threatintel.indicator.first_seen",
        "format": "date_time"
        },
        {
        "field": "threatintel.indicator.last_seen",
        "format": "date_time"
        },
        {
        "field": "threatintel.misp.attribute.timestamp",
        "format": "date_time"
        },
        {
        "field": "threatintel.misp.context.attribute.timestamp",
        "format": "date_time"
        },
        {
        "field": "threatintel.misp.date",
        "format": "date_time"
        },
        {
        "field": "threatintel.misp.publish_timestamp",
        "format": "date_time"
        },
        {
        "field": "threatintel.misp.timestamp",
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
        "field": "x509.not_after",
        "format": "date_time"
        },
        {
        "field": "x509.not_before",
        "format": "date_time"
        },
        {
        "field": "zeek.kerberos.valid.from",
        "format": "date_time"
        },
        {
        "field": "zeek.kerberos.valid.until",
        "format": "date_time"
        },
        {
        "field": "zeek.ntp.org_time",
        "format": "date_time"
        },
        {
        "field": "zeek.ntp.rec_time",
        "format": "date_time"
        },
        {
        "field": "zeek.ntp.ref_time",
        "format": "date_time"
        },
        {
        "field": "zeek.ntp.xmt_time",
        "format": "date_time"
        },
        {
        "field": "zeek.ocsp.revoke.time",
        "format": "date_time"
        },
        {
        "field": "zeek.ocsp.update.next",
        "format": "date_time"
        },
        {
        "field": "zeek.ocsp.update.this",
        "format": "date_time"
        },
        {
        "field": "zeek.pe.compile_time",
        "format": "date_time"
        },
        {
        "field": "zeek.smb_files.times.accessed",
        "format": "date_time"
        },
        {
        "field": "zeek.smb_files.times.changed",
        "format": "date_time"
        },
        {
        "field": "zeek.smb_files.times.created",
        "format": "date_time"
        },
        {
        "field": "zeek.smb_files.times.modified",
        "format": "date_time"
        },
        {
        "field": "zeek.smtp.date",
        "format": "date_time"
        },
        {
        "field": "zeek.snmp.up_since",
        "format": "date_time"
        },
        {
        "field": "zeek.x509.certificate.valid.from",
        "format": "date_time"
        },
        {
        "field": "zeek.x509.certificate.valid.until",
        "format": "date_time"
        },
        {
        "field": "zoom.meeting.start_time",
        "format": "date_time"
        },
        {
        "field": "zoom.participant.join_time",
        "format": "date_time"
        },
        {
        "field": "zoom.participant.leave_time",
        "format": "date_time"
        },
        {
        "field": "zoom.phone.answer_start_time",
        "format": "date_time"
        },
        {
        "field": "zoom.phone.call_end_time",
        "format": "date_time"
        },
        {
        "field": "zoom.phone.connected_start_time",
        "format": "date_time"
        },
        {
        "field": "zoom.phone.date_time",
        "format": "date_time"
        },
        {
        "field": "zoom.phone.ringing_start_time",
        "format": "date_time"
        },
        {
        "field": "zoom.recording.recording_file.recording_end",
        "format": "date_time"
        },
        {
        "field": "zoom.recording.recording_file.recording_start",
        "format": "date_time"
        },
        {
        "field": "zoom.recording.start_time",
        "format": "date_time"
        },
        {
        "field": "zoom.timestamp",
        "format": "date_time"
        },
        {
        "field": "zoom.webinar.start_time",
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
        "must": [
            {
            "query_string": {
                "analyze_wildcard": True,
                "query": "*",
                "time_zone": "Europe/Sofia"
            }
            }
        ],
        "filter": [
            {
            "match_phrase": {
                "input.type": {
                "query": "netflow"
                }
            }
            },
            {
            "range": {
                "@timestamp": {
                "format": "strict_date_optional_time",
                "gte": "now-2h",
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
    print(res["aggregations"]["2"]["buckets"])

buckets = []
for bucket in res["aggregations"]["2"]["buckets"]:
    buckets.append({'time':bucket["key_as_string"], 'count':bucket["doc_count"]})

sum_counts = 0
for bucket in buckets:
    sum_counts += bucket['count']
    print(f"time: {bucket['time']} count {bucket['count']}")

header = ["time", "count", "baseline"]

f = open('fr.csv', 'w')
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