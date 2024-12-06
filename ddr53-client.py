#!/usr/local/bin/python3.11

import os
import sys
import signal
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import boto3
import botocore
import logging
import time
import argparse
import configparser
import ipaddress
import subprocess

APP_NAME = "ddr53-client"
APP_DESCRIPTION = "Route53 Dynamic DNS Client"
APP_VERSION = "1.1.0"
CONFIG_FILES = [
    '/etc/ddr53-client.conf',
    os.path.expanduser('~/.ddr53-client.conf'),
    f"{os.path.dirname(os.path.realpath(__file__))}/ddr53-client.conf"
]
# Set the log format options
LOG_FORMAT = {
"std_format": logging.Formatter(
    f'%(asctime)s %(levelname)-8s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'),
"debug_format": logging.Formatter(
    f'%(asctime)s %(levelname)-8s:%(message)s (%(filename)s: %(lineno)d)',
    datefmt='%Y-%m-%d %H:%M:%S')
}
LOG_LEVEL = {
    "none": {"level": None},
    "critical": {"level": logging.CRITICAL, "format": LOG_FORMAT["std_format"]},
    "error": {"level": logging.ERROR, "format": LOG_FORMAT["std_format"]},
    "warning": {"level": logging.WARNING, "format": LOG_FORMAT["std_format"]},
    "info": {"level": logging.INFO, "format": LOG_FORMAT["std_format"]},
    "debug": {"level": logging.DEBUG, "format": LOG_FORMAT["debug_format"]},
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

# Signal handler for graceful exit
def signal_handler(sig, frame):
    print('Exiting...')
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

""" Argument Parsing """
class EnvDefault(argparse.Action):
    """ Argparse Action that uses ENV Vars for default values """

    def boolify(self, s):
        if isinstance(s, bool):
            return s
        if s.lower() in ['true', 't', 'yes', 'y', '1']:
            return True
        if s.lower() in ['false', 'f', 'no', 'n', '0']:
            return False
        return s

    def __init__(self, envvar, required=False, default=None, **kwargs):
        if envvar and envvar in os.environ:
            default = self.boolify(os.environ[envvar])
            required = False

        super().__init__(default=default,
                         required=required,
                         **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)

parser = argparse.ArgumentParser(description=APP_DESCRIPTION, prog=APP_NAME)
parser.add_argument(
    '-c', '--config', required=False,
    help=f'Configuration file: INI format. Default: {CONFIG_FILES[0]}. ENV Var: CONFIG_FILE',
    metavar=f'{CONFIG_FILES[0]}', default=f'{CONFIG_FILES[0]}', action=EnvDefault, envvar="CONFIG_FILE"
)
parser.add_argument(
    '--log-file', required=False,
    help='Log file: Defaults to stdout. ENV Var: LOG_FILE',
    metavar=f'/var/log/{APP_NAME}.log', default=None, action=EnvDefault, envvar="LOG_FILE"
)
parser.add_argument( '--log-level', required=False,
    help=f'Log level: {", ".join(LOG_LEVEL.keys())}. ENV Var: LOG_LEVEL',
    metavar='info', default='info', action=EnvDefault, envvar="LOG_LEVEL"
)
parser.add_argument(
    '--dry-run', required=False,
    help='Report only, do not update DNS',
    action='store_true'
)
parser.add_argument(
    '-d', '--daemon', required=False,
    help='Run as a daemon/continuous loop',
    action='store_true'
)
parser.add_argument(
    '-i', '--interval', required=False,
    help='Daemon loop interval in seconds. ENV Var: DAEMON_INTERVAL', metavar='360',
    type=int, default=360, action=EnvDefault, envvar="DAEMON_INTERVAL"
)


def init_logger():
    """ Configure Application Logging """
    if args.log_level == 'none':
        return None
    if args.log_level not in LOG_LEVEL.keys():
        args.log_level = 'info'

    # create the logger
    app_logger = logging.getLogger()
    app_logger.setLevel(LOG_LEVEL[args.log_level]["level"])

    # initialize the file logger
    if args.log_file and not os.path.isdir(os.path.dirname(args.log_file)):
        os.mkdir(os.path.dirname(args.log_file))
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(LOG_LEVEL[args.log_level]["format"])
        app_logger.addHandler(file_handler)

    # initialize the console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(LOG_LEVEL[args.log_level]["format"])
    app_logger.addHandler(console_handler)

    # Set log level for boto3 and requests
    logging.getLogger('botocore').setLevel(logging.CRITICAL)
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    return app_logger

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

    def __aws_client__(self, client: str='route53'):
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
        self.logger.debug(f"Getting public IP from HTTP for '{self.hostname}'")
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
        self.logger.debug(f"Getting public IP from CMD for '{self.hostname}'")
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
        self.logger.debug(f"Getting public IP from Security Group for '{self.hostname}'")
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
        self.logger.debug(f"Getting DNS IP from Route53 for {self.hostname}")
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

    def get_public_ip(self):
        """ Get the public IP address """
        if self.enabled and self.use in ['http', 'cmd']:
            self.logger.debug(f"Configuring {self.hostname}")
            if self.use == 'http' and self.http:
                self.public_ip = self.__http_public_ip__()
            elif self.use == 'cmd' and self.cmd:
                self.public_ip = self.__cmd_public_ip__()

            if self.public_ip:
                self.logger.debug(f"Found IP Address: {self.public_ip} for '{self.hostname}' from source: '{self.use}'")

    def get_dns_ip(self):
        """ Get the public IP address from Route53 """
        if self.route53 and self.zoneid and self.hostname:
            self.dns_public_ip = self.__get_route53_ip__(self.zoneid, self.hostname)
        if self.dns_public_ip:
            self.logger.debug(f"Found Existing Route53 DNS IP Address: {self.dns_public_ip} for '{self.hostname}'")

    def get_sg_rule(self):
        """ Get the public IP address from a security group rule """
        self.ec2 = self.__aws_client__('ec2')
        if not self.ec2:
            self.logger.error("Unable to connect to AWS EC2 API")
            self.enabled = False

        if self.ec2 and self.sgroupid and self.sgruleid:
            self.sgrule = self.__get_sg_rule__(self.sgroupid, self.sgruleid)
        if self.sgrule:
            self.logger.debug(f"Found Existing Security Group IP Address: {self.sgrule.ip} for '{self.hostname}'")
    @property
    def update_needed(self):
        self.route53 = self.__aws_client__()
        if not self.route53:
            self.logger.error("Unable to connect to AWS Route53 API")
            self.enabled = False

        self.get_public_ip()
        self.get_dns_ip()
        self.get_sg_rule()

        if not self.enabled:
            return False

        if self.public_ip != self.dns_public_ip:
            self.logger.debug(f"Public IP for {self.hostname} is out of sync with DNS. Update needed.")
            return True
        elif self.sgrule and self.public_ip != self.sgrule.ip:
            self.logger.debug(f"Public IP for {self.hostname} is out of sync with {self.sgroupid}. Update needed.")
            return True
        else:
            return False

    def update(self, dry_run: bool=False):
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

def run():
    """ Main execution function """
    # Load the configuration file
    if args.config:
        CONFIG_FILES.insert(0, args.config)
    for config_file in CONFIG_FILES:
        logger.debug(f"Checking for configuration file: {config_file}")
        if os.path.isfile(config_file):
            logger.debug(f"Loading configuration from {config_file}")
            config.read(config_file)
            for hostname in config.sections():
                DdnsConfigs[f"{hostname}"] = DdnsConfig(hostname=hostname, config_entry=config[hostname],
                                                        config_defaults=config['DEFAULT'])
            break
    if len(DdnsConfigs) == 0:
        logger.error("No configuration found. Exiting.")
        sys.exit(1)

    """ Run each config entry and update DNS if needed """
    for hostname, ddns_config in DdnsConfigs.items():
        # Use the public IP from another hostname if specified and found
        if ddns_config.use in DdnsConfigs.keys() and DdnsConfigs[ddns_config.use].public_ip:
            ddns_config.public_ip = DdnsConfigs[ddns_config.use].public_ip

        if not ddns_config.enabled:
            continue
        if not ddns_config.update_needed:
            logger.info(f"DNS for {hostname} ({ddns_config.public_ip}) is in sync. No update needed.")
            continue

        ddns_config.update(dry_run=args.dry_run)

""" Main Application Loop """
if __name__ == "__main__":
    args = parser.parse_args()
    config = configparser.ConfigParser()
    DdnsConfigs = {}
    logger = init_logger()

    logger.info(f"** Starting {APP_NAME} version {APP_VERSION} **")
    if not args.daemon:
        run()
        sys.exit(0)

    logger.info(f"Running as a daemon with interval of {args.interval} seconds")
    while True:
        run()
        logger.debug(f"Sleeping for {args.interval} seconds")
        time.sleep(args.interval)


