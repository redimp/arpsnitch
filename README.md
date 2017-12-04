# arpsnitch

This tool is similar to arpwatch, but much simpler. It purpose is to
monitor the network and log and keep track of discovered machines using
arp pings.

## Installation

arpsnitch is not yet on pypi, so you have to install it manually.
```bash
$ git clone git@github.com:redimp/arpsnitch.git
$ cd arpsnitch
$ python setup.py install
```

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
  00:12:34:12:34:56:
    alias: []
    comment: ''
    first_seen: '2017-12-04T15:48:55'
    hostname: router.local
    ignore: false
    ip: 192.168.0.1
    last_seen: '2017-12-04T15:48:55'
    status: alive
  98:76:54:32:1f:aa:
    alias: []
    comment: ''
    first_seen: '2017-12-04T15:48:55'
    hostname: workstation.local
    ignore: false
    ip: 192.168.0.2
    last_seen: '2017-12-04T15:48:55'
    status: alive
```

If a new mac address appears, the output looks like:
```bash
$ arpsnitch.py -n 192.168.0.1/24 -c /tmp/arpsnitch.yml
aa:bb:cc:dd:ee:ff (notebook.vmdgrid): new
```

If a machine is not discoverable the output looks like:
```bash
$ arpsnitch.py -n 192.168.0.1/24 -c /tmp/arpsnitch.yml
aa:bb:cc:dd:ee:ff (notebook.vmdgrid): missing. last seen: 2017-12-04T16:30:02
```

To prevent to get flooded with notifications you can ignore hosts, by setting `ignore: true` in the
config file:
```yaml
192.168.0.1/24:
# [...]
  00:12:34:12:34:56:
    alias: []
    comment: ''
    first_seen: '2017-12-04T15:48:55'
    hostname: notebook.local
    ignore: true
    ip: 192.168.0.3
    last_seen: '2017-12-04T16:30:02'
    status: alive
```

## Setup

My suggestion is to set this up as cron job e.g.

```bash
# /etc/cron.d/arpsnitch
*/5 * * * * root [ -x /usr/local/bin/arpsnitch.py ] && /usr/local/bin/arpsnitch.py -c /tmp/arpsnitch.yml
```
