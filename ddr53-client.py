#!/usr/local/bin/python3.11

import os
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import boto3
import botocore
import logging
from logging.handlers import RotatingFileHandler
import argparse
import configparser
import ipaddress
import subprocess

APP_NAME = "ddr53-client"
APP_VERSION = "1.0.1"
CONFIG_FILES = [f"{os.path.dirname(os.path.realpath(__file__))}/ddr53-client.conf", '/etc/ddr53-client.conf', os.path.expanduser('~/.ddr53-client.conf')]
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
    "init",
    "service"
]
CMD_WHITE_LIST = [
    "curl",
    "wget",
    "fetch",
    "cat",
    "dig",
    "nslookup",
    "host",
    "ip",
    "ifconfig"
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
parser.add_argument(
    '-d','--dry-run', required=False,
    help='Report only, do not update DNS',
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
    '[%(levelname)-1s]: %(message)s',
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

class SgRule():
    def __init__(self, hostname:str, **kwargs):
        self.SecurityGroupRuleId = None
        self.IpProtocol = None
        self.FromPort = None
        self.ToPort = None
        self.CidrIpv4 = None
        self.CidrIpv6 = None

        for key, val in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, val)

        self.Description = f"{APP_NAME} - {hostname}"

    @property
    def ip(self):
        if self.CidrIpv4:
            return str(ipaddress.ip_network(self.CidrIpv4).network_address)
        elif self.CidrIpv6:
            return str(ipaddress.ip_network(self.CidrIpv6).network_address)
    @ip.setter
    def ip(self, value):
        if self.CidrIpv4:
            self.CidrIpv4 = f"{value}/32"
        elif self.CidrIpv6:
            self.CidrIpv6 = f"{value}/128"

    def update_payload(self):
        out_dict = {
            'SecurityGroupRuleId': self.SecurityGroupRuleId,
            'SecurityGroupRule': {
                'IpProtocol': self.IpProtocol,
                'FromPort': self.FromPort,
                'ToPort': self.ToPort,
                'Description': self.Description
            }
        }
        if self.CidrIpv4:
            out_dict['SecurityGroupRule']['CidrIpv4'] = self.CidrIpv4
        if self.CidrIpv6:
            out_dict['SecurityGroupRule']['CidrIpv6'] = self.CidrIpv6
        return out_dict

class DdnsConfig():
    def __init__(self, hostname:str, config_entry, config_defaults):
        self.enabled = True
        self.hostname = hostname
        self.zoneid = None
        self.sgroupid = None
        self.sgruleid = None
        self.sgrule = None
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
            self.logger.error("Unable to connect to AWS Route53 API")
            self.enabled = False

        if self.route53 and self.zoneid and self.hostname:
            self.dns_public_ip = self.__get_route53_ip__(self.zoneid, self.hostname)
        if self.dns_public_ip:
            self.logger.info(f"Found Existing Route53 DNS IP Address: {self.dns_public_ip} for '{self.hostname}'")

        if self.sgroupid and self.sgruleid:
            self.ec2 = self.__aws_client__('ec2')
            if not self.ec2:
                self.logger.error("Unable to connect to AWS EC2 API")
                self.enabled = False
            if self.ec2 and self.sgroupid and self.sgruleid:
                self.sgrule = self.__get_sg_rule__(self.sgroupid, self.sgruleid)
            if self.sgrule:
                self.logger.info(f"Found Existing Security Group IP Address: {self.sgrule.ip} for '{self.hostname}'")


    @property
    def dns_in_sync(self):
        return self.public_ip == self.dns_public_ip

    @property
    def sg_in_sync(self):
        if self.sgrule:
            return self.public_ip == self.sgrule.ip
        else:
            return None

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

    def __aws_client__(self, client:str='route53'):
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
        except exception as err:
            self.logger.error(f"Unable to authenticate AWS session. Check your credentials. {err}")
            return None

        self.logger.debug(f"Connected to AWS API using client: {client}")
        return session.client(client)

    def __http_public_ip__(self, metadata_token=None):
        """ Get the public IP address from a web service """
        self.logger.info(f"Getting public IP from HTTP for '{self.hostname}'")
        try:
            headers = {"Accept": f"{self.http_accept}"}
            if metadata_token:
                self.logger.debug("Using ec2 metadata token")
                headers["X-aws-ec2-metadata-token"] = metadata_token
            response = requests.get(self.http, headers=headers, verify=True)

            if response.status_code == 401 and self.http.startswith('http://169.254.169.254') and not metadata_token:
                self.logger.debug("Requesting ec2 metadata token")
                metadata_token = requests.put("http://169.254.169.254/latest/api/token", headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, verify=True)
                return self.__http_public_ip__(metadata_token=metadata_token.text)
            elif response.status_code == 200:
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

    def __validate_cmd__(self, command:str):
        """ Validate a command string """
        # Verify that the cmd is whitelisted
        if command and not any([cmd in command for cmd in CMD_WHITE_LIST]):
            self.logger.error(f"Command '{command}' is not whitelisted. Exiting.")
            return None

        # Verify that the cmd is not blacklisted
        if command and any([cmd in command for cmd in CMD_BLACKLIST]):
            self.logger.error(f"Command '{command}' is blacklisted. Exiting.")
            return None

        return command

    def __cmd_public_ip__(self):
        """ Get the public IP address from a command """
        self.logger.info(f"Getting public IP from CMD for '{self.hostname}'")
        # Verify that the command is safe to run
        run_cmd = self.__validate_cmd__(self.cmd)
        if not run_cmd:
            return None

        try:
            response = subprocess.run(run_cmd, shell=True, capture_output=True)
            if response.returncode == 0:
                return str(ipaddress.ip_address(response.stdout.decode('utf-8').strip()))
            else:
                self.logger.debug(f"Public IP: {self.public_ip}")
        except ValueError as err:
            self.logger.error(f"Error getting public IP: {err}")
            return None

    def __get_sg_rule__(self, group_id:str, rule_id:str):
        """ Get the public IP address from a security group rule """
        self.logger.info(f"Getting public IP from Security Group for '{self.hostname}'")
        try:
            response = self.ec2.describe_security_group_rules(
                Filters=[{'Name': 'group-id', 'Values': [group_id]}],
                SecurityGroupRuleIds=[rule_id]
            )
            if response["SecurityGroupRules"] and len(response["SecurityGroupRules"]) > 0:
                return SgRule(hostname=self.hostname, **response["SecurityGroupRules"][0])
        except botocore.exceptions.ClientError as err:
            self.logger.error(f"Error getting public IP from Security Group: {err}")
            return None
        except ValueError as err:
            self.logger.error(f"Error getting public IP from Security Group: {err}")
            return None

    def __set_sg_rule_ip__(self, group_id:str, rule_id:str, public_ip:str, dry_run:bool=False):
        """ Set the public IP address in a security group rule """
        if dry_run:
            self.logger.info(f"DRY RUN: Updating Security Group for {self.hostname} to {self.public_ip}")
            return True

        self.logger.info(f"Setting public IP in Security Group for '{self.hostname}'")
        self.sgrule.ip = public_ip

        try:
            self.ec2.modify_security_group_rules(
                DryRun=dry_run,
                GroupId=group_id,
                SecurityGroupRules=[self.sgrule.update_payload()]
            )
            return True
        except botocore.exceptions.ClientError as err:
            self.logger.error(f"Error updating Security Group: {err}")
            return False


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

    def __set_route53_ip__(self, zone_id:str, hostname:str, public_ip:str, dry_run:bool=False):
        """ Set the public IP address in Route53 """
        if dry_run:
            self.logger.info(f"DRY RUN: Updating DNS for {self.hostname} to {self.public_ip}")
            return True

        try:
            response = self.route53.change_resource_record_sets(
                HostedZoneId=self.zoneid,
                ChangeBatch={
                    'Comment': f"{APP_NAME} Updating {self.hostname} to {self.public_ip}",
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
            return True if response.status_code == 200 else False

        except Exception as err:
            self.logger.error(f"Error updating Route53: {err}")
            return False

    def update(self, dry_run:bool=False):
        # Update the DNS record if needed
        if self.ready and not self.dns_in_sync:
            self.logger.info(f"Updating DNS for {self.hostname} to {self.public_ip}")
            if ddns_config.__set_route53_ip__(self.zoneid, self.hostname, self.public_ip, dry_run=dry_run):
                self.logger.info(f"DNS for {self.hostname} successfully updated to {self.public_ip}")
        else:
            self.logger.info(f"Public IP for {self.hostname} is in sync with DNS. No update needed.")

        # Update the Security Group rule if needed
        if ddns_config.sg_in_sync == None:
            self.logger.debug(f"No security group rule configured to update for {self.hostname}")

        elif ddns_config.ready and not ddns_config.sg_in_sync:
            self.logger.info(f"Updating Security Group for {self.hostname} to {self.public_ip}")
            if ddns_config.__set_sg_rule_ip__(self.sgroupid, self.sgruleid, f"{self.public_ip}", dry_run=dry_run):
                self.logger.info(f"Security Group for {self.hostname} successfully updated to {self.public_ip}")
        else:
            self.logger.info(f"Public IP for {self.hostname} is in sync with {self.sgroupid}. No update needed.")






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
    logger.error("No configuration found. Exiting.")
    exit(1)


""" Run each config entry and update DNS if needed """
for hostname, ddns_config in DdnsConfigs.items():
    # skip disabled configs
    if not ddns_config.enabled:
        continue

    # Use the public IP from another hostname if specified and found
    if ddns_config.use in DdnsConfigs.keys() and DdnsConfigs[ddns_config.use].public_ip:
        ddns_config.public_ip = DdnsConfigs[ddns_config.use].public_ip

    ddns_config.update(dry_run=args.dry_run)

