# ddr53-client
Dynamic DNS client for Route53

## Usage
ddr53-client is a simple client for updating Route53 DNS records. It can be used to update a single record or multiple records at once.

### Arguments
  - `-c|--config`: The path to the configuration file. Defaults to `/etc/ddr53/ddr53.conf`.
  - `-l|--log`: The path to the log file. Defaults to `/var/log/ddr53/ddr53.log`.
  - `-v|--verbose`: Enable verbose output.
  - `-q|--quiet`: Disable all output. Logging will still be enabled.
  - `-h|--help`: Show the help message and exit.

## Configuration
The configuration file is located at `/etc/ddr53/ddr53.conf` and is a simple INI file with the following sections:
 - `[DEFAULT]`: Default values for all DDNS records
 - `[<hostanme>]`: Configuration for a specific hostname. Specify as many sections as you need.

### Configuration options
All configuration options can be set in the `[DEFAULT]` section and overridden in the hostname-specific sections.
  - `enabled`: Enable or disable the DDNS record. Defaults to `True`.
  - `hostname`: The hostname to update. This is the only required option.
  - `ttl`: The TTL for the record. Defaults to 60.
  - `zoneid`: The Route53 zone ID. Defaults to the zone ID of the hostname.
  - `access_key`: The AWS access key ID. Default: `None`.
  - `secret_key`: The AWS secret access key. Default: `None`.
  - `profile`: The AWS CLI prodile. Defaults to the value of the environment variable `AWS_PROFILE`.
  - `region`: The AWS region. Defaults to the value of the environment variable `AWS_REGION`.
  - `http_accept`: The HTTP Accept header. Defaults to `text/plain`.
  - `json_key`: The JSON key to use for the IP address. Default: `None`. Only used if the HTTP Accept header is `application/json`.
  - `use`: Specify the source to use for the IP address. Defaults to `http`. Valid values are `http` and `cmd` or another hostname specified in the config.
  - `http`: The URL to use for the HTTP source. Defaults to `http://ipinfo.io/ip`. Only used if `use` is set to `http`. Specify `http://169.254.169.254/latest/meta-data/public-ipv4` for EC2 instance metadata.
  - `cmd`: The command to use for the command source. Default: `None`. Only used if `use` is set to `cmd`.
