#!/usr/local/bin/python3.11

import os
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import boto3
import logging
from logging.handlers import RotatingFileHandler
import argparse
import configparser
import ipaddress
import subprocess

APP_NAME = "ddr53-client"
APP_VERSION = "0.0.2"
CONFIG_FILES = ['/etc/ddr53-client.conf', os.path.expanduser('~/.ddr53-client.conf')]
LOG_ROTATION = {
    "maxBytes": 500000,
    "backupCount": 7
}
CMD_BLACKLIST = [
    "systemctl",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "init"
]


""" Argument Parsing """
parser = argparse.ArgumentParser(description="Route53 Dynamic DNS")
parser.add_argument(
    '-c','--config', required=False,
    help=f'Configuration file: INI format. Defaults: {CONFIG_FILES}',
    default=None
)
parser.add_argument(
    '-l','--log', required=False,
    help='Log file: Defaults to /var/log/ddr53-client.log',
    default='/var/log/ddr53-client.log'
)
parser.add_argument(
    '-v','--verbose', required=False,
    help='Verbose logging',
    action='store_true'
)
parser.add_argument(
    '-s','--silent', required=False,
    help='No console logging',
    action='store_true'
)
args = parser.parse_args()
config = configparser.ConfigParser()
DdnsConfigs = {}

""" Configure Application Logging """
if not os.path.isdir(os.path.dirname(args.log)):
    os.mkdir(os.path.dirname(args.log))

logging.basicConfig(
    handlers=[RotatingFileHandler(args.log, maxBytes=LOG_ROTATION["maxBytes"], backupCount=LOG_ROTATION["backupCount"])],
    format='%(asctime)s [%(levelname)-1s]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_format = logging.Formatter(
    f'[%(levelname)-1s]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger()
if not args.silent:
    console = logging.StreamHandler()
    console.setFormatter(console_format)
    logger.addHandler(console)

logger.setLevel(logging.DEBUG) if args.verbose else logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class DdnsConfig():
    def __init__(self, hostname:str, config_entry, config_defaults):
        self.enabled = True
        self.hostname = hostname
        self.zoneid = None
        self.use = 'http'
        self.http = 'http://ipinfo.io/ip'
        self.cmd = None
        self.http_accept = 'text/plain'
        self.profile = None
        self.region = 'us-east-1'
        self.access_key = None
        self.secret_key = None
        self.ttl = 60
        self.json_key = None
        self.public_ip = None
        self.dns_public_ip = None
        self.logger = logging.getLogger(__name__)

        # Set default values
        for key, val in config_defaults.items():
            if hasattr(self, key):
                setattr(self, key, self.__str_to_bool__(val))

        # Set config values (overwrites defaults)
        for key, val in config_entry.items():
            if hasattr(self, key):
                setattr(self, key, self.__str_to_bool__(val))

        # Fetch the public IP address
        if self.enabled and self.use in ['http', 'cmd']:
            self.logger.debug(f"Configuring {self.hostname}")
            if self.use == 'http' and self.http:
                self.public_ip = self.__http_public_ip__()
            elif self.use == 'cmd' and self.cmd:
                self.public_ip = self.__cmd_public_ip__()

            if self.public_ip:
                self.logger.info(f"Found IP Address: {self.public_ip} for '{self.hostname}' from source: '{self.use}'")

        self.route53 = self.__aws_client__()
        if not self.route53:
            self.logger.error(f"Unable to connect to AWS Route53 API")
            self.enabled = False

        if self.route53 and self.zoneid and self.hostname:
            self.logger.info(f"Connected to AWS Route53 API")
            self.dns_public_ip = self.__get_route53_ip__(self.zoneid, self.hostname)
        if self.dns_public_ip:
            self.logger.info(f"Found Existing Route53 DNS IP Address: {self.dns_public_ip} for '{self.hostname}'")

    @property
    def in_sync(self):
        return self.public_ip == self.dns_public_ip

    @property
    def ready(self):
        if self.enabled and self.public_ip:
            return True
        else:
            return False


    def __str_to_bool__(self, value):
        if value.lower() in ('yes', 'true'):
            return True
        elif value.lower() in ('no', 'false'):
            return False
        else:
            return value

    def __aws_client__(self):
        # Create a session object
        credentials = {
            "aws_access_key_id": self.access_key,
            "aws_secret_access_key": self.secret_key,
            "profile_name": self.profile
        }
        session = boto3.session.Session(region_name=self.region, **credentials)
        sts = session.client('sts')
        try:
            sts.get_caller_identity()
        except:
            self.logger.error(f"Unable to authenticate AWS session. Check your credentials.")
            return None
        return session.client('route53')

    def __http_public_ip__(self):
        """ Get the public IP address from a web service """
        self.logger.info(f"Getting public IP from HTTP for '{self.hostname}'")
        try:
            response = requests.get(self.http, headers={"Accept": f"{self.http_accept}"}, verify=True)
            if response.status_code == 200:
                if self.http_accept.endswith('json') and self.json_key:
                    self.logger.debug("Parsing HTTP JSON response")
                    return str(ipaddress.ip_address(response.json()[self.json_key]))
                else:
                    self.logger.debug("Parsing HTTP text response")
                    return str(ipaddress.ip_address(response.text))

            self.logger.debug(f"Public IP: {self.public_ip}")
        except ValueError as err:
            self.logger.error(f"Error getting public IP: {err}")
            return None

    def __cmd_public_ip__(self):
        """ Get the public IP address from a command """
        self.logger.info(f"Getting public IP from CMD for '{self.hostname}'")

        # Verify that the cmd is not blacklisted
        if self.cmd and any([cmd in self.cmd for cmd in CMD_BLACKLIST]):
            self.logger.error(f"Command '{self.cmd}' is blacklisted. Exiting.")
            self.enabled = False
            return None

        try:
            response = subprocess.run(self.cmd, shell=True, capture_output=True)
            if response.returncode == 0:
                return str(ipaddress.ip_address(response.stdout.decode('utf-8').strip()))
            else:
                self.logger.debug(f"Public IP: {self.public_ip}")
        except ValueError as err:
            self.logger.error(f"Error getting public IP: {err}")
            return None

    def __get_route53_ip__(self, zone_id:str, hostname:str):
        """ Get the public IP address from Route53 """
        self.logger.info(f"Getting DNS IP from Route53 for {self.hostname}")
        dns_public_ip = None

        response = self.route53.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordName=hostname,
            StartRecordType='A',
            MaxItems='1'
        )
        # Check if the response contains the hostname
        if "ResourceRecordSets" in response and len(response["ResourceRecordSets"]) > 0:
            for recordset in response["ResourceRecordSets"]:
                if recordset["Name"] in [hostname, f"{hostname}."]:
                    dns_public_ip = recordset["ResourceRecords"][0]["Value"]
                    break
        return dns_public_ip

    def update(self):
        try:
            response = self.route53.change_resource_record_sets(
                HostedZoneId=self.zoneid,
                ChangeBatch={
                    'Comment': 'string',
                    'Changes': [
                        {
                            'Action': 'UPSERT',
                            'ResourceRecordSet': {
                                'Name': self.hostname,
                                'Type': 'A',
                                'TTL': int(self.ttl),
                                'ResourceRecords': [
                                    {
                                        'Value': self.public_ip
                                    },
                                ]
                            }
                        },
                    ]
                }
            )
        except Exception as err:
            self.logger.error(f"Error updating Route53: {err}")
            return False


logger.info(f"** Starting {APP_NAME} version {APP_VERSION} **")

""" Load the configuration file """
if args.config:
    CONFIG_FILES.insert(0, args.config)
for config_file in CONFIG_FILES:
    logger.debug(f"Checking for configuration file: {config_file}")
    if os.path.isfile(config_file):
        logger.info(f"Loading configuration from {config_file}")
        config.read(config_file)
        for hostname in config.sections():
            DdnsConfigs[f"{hostname}"] = DdnsConfig(hostname=hostname, config_entry=config[hostname], config_defaults=config['DEFAULT'])
        break
if len(DdnsConfigs) == 0:
    logger.error(f"No configuration found. Exiting.")
    exit(1)


""" Run each config entry and update DNS if needed """
for hostname, ddns_config in DdnsConfigs.items():
    # skip disabled configs
    if not ddns_config.enabled:
        continue

    # Use the public IP from another hostname if specified and found
    if ddns_config.use in DdnsConfigs.keys() and DdnsConfigs[ddns_config.use].public_ip:
        ddns_config.public_ip = DdnsConfigs[ddns_config.use].public_ip

    # print(ddns_config.__dict__)
    if ddns_config.ready and not ddns_config.in_sync:
        logger.info(f"Updating DNS for {ddns_config.hostname} to {ddns_config.public_ip}")
        ddns_config.update()
    elif ddns_config.ready and ddns_config.in_sync:
        logger.info(f"Public IP for {ddns_config.hostname} is in sync with DNS. No update needed.")
    else:
        logger.error(f"One or more operations for {ddns_config.hostname} failed. Unable to update DNS.")
        continue
