# arpsnitch

This tool is similar to arpwatch, but much simpler. It purpose is to
monitor the network and log and keep track of discovered machines using
arp pings.

## Installation

TODO

## Usage

To start simply run it with the network to discover and the config file
to write as arguments:

```bash
$ arpsnitch.py -n 192.168.0.1/24 -c /tmp/arpsnitch.yml
```

It will discover the network and write the found hosts to the given
file:

```yaml
192.168.0.1/24:
  00:12:34:12:34:56
    alias: []
    comment: ''
    first_seen: '2017-12-04T10:48:55'
    hostname: router.local
    ip: 192.168.0.1
    last_seen: '2017-12-04T15:48:55'
    status: alive
  98:76:54:32:1f:aa
    alias: []
    comment: ''
    first_seen: '2017-12-04T10:48:55'
    hostname: router.local
    ip: 192.168.0.1
    last_seen: '2017-12-04T15:48:55'
    status: alive
```

My suggestion is to set this up as cronjob e.g.
```bash
# /etc/cron.d/arpsnitch
*/5 * * * * root [ -x /usr/local/bin/arpsnitch.py ] && /usr/local/bin/arpsnitch.py -c /tmp/arpsnitch.yml
```
