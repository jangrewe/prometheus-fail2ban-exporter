#!/usr/bin/env python3
import re, subprocess, argparse
from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest

## Filename
EXPORT_FILE_NAME="fail2ban.prom"

## File output location for node_exporter
EXPORT_LOCATION='/var/lib/prometheus/node-exporter'

## Modifying may break it!
parseKeys = {
    'Currently failed:': ('fail2ban_failed_current', 'Number of currently failed connections.'),
    'Total failed:':('fail2ban_failed_total', 'Total number of failed connections.'),
    'Currently banned:':('fail2ban_banned_current', 'Number of currently banned IP addresses.'),
    'Total banned:':('fail2ban_banned_total', 'Total number of banned IP addresses.')
}

## Commandline args
parser = argparse.ArgumentParser(description="Export fail2ban-client metrics for Prometheus Node Exporter.")
parser.add_argument('-j', '--jail', help="Jail name to be exported (all jails if omitted).")
parser.add_argument('-f', '--file', help="File to write metrics to.")
args = parser.parse_args()

## Regex
pattern = re.compile(r'('+ '|'.join(parseKeys.keys()) + r')\s*(\d*)')
metrics = {}
output = ''

for k in parseKeys.keys():
    metrics[k] = {}

if args.jail:
    jails = [args.jail]
else:
    process = subprocess.Popen(['fail2ban-client', 'status'], stdout=subprocess.PIPE)
    response = process.communicate()[0].decode('utf-8')
    match = re.search(r'.+Jail list:\s+(.+)$', response)
    jails = match.group(1).split(", ")

for jail in jails:
    process = subprocess.Popen(['fail2ban-client', 'status', jail], stdout=subprocess.PIPE)
    response = process.communicate()[0].decode('utf-8')
    match = re.findall(pattern, response)
    for m in match:
        metrics[m[0]].update( [(jail, float(m[1]))] )

registry = CollectorRegistry()
for (metric, jails) in metrics.items():
    gauge = Gauge(parseKeys[metric][0], parseKeys[metric][1], ['jail'], registry=registry)
    for (jail,value) in jails.items():
        gauge.labels(jail).set(float(value))

with open((args.file or (EXPORT_LOCATION + '/' + EXPORT_FILE_NAME)), "wb") as file:
  file.write(generate_latest(registry))
  file.close()
