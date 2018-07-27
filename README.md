# dnsbl-checker
Asynchronous script for monitoring dns blacklists

## Installation
`pip install dnsbl-checker`

## Usage

#### Shell commands
Get list of dns blacklists in which IP_ADDR was found ('all' for listing all ips)
```bash
dnsbl get IP_ADDR
```

Perform check for dns blacklists:
```bash
dnsbl check CONF_FILE
```
##### Configuration
```yaml
ips: /path/to/file/with/ip_list.txt
banned_providers: /path/to/file/with/banned_providers.txt # optional
telegram_token: token123 # token of tg bot (optional)
telegram_ids: # ids of telegram users to whish send msgs about check (optional)
  - 11111111
  - 22222222 
```