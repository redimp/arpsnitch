#!/usr/bin/env python

"""
    arpsnitch.py - a tool for checking hosts on the network via arp
"""

import os
import sys
import argparse
import re
from datetime import datetime
import socket

from scapy.layers.l2 import arping
from scapy.all import conf as scapyconf
# disable scapy promiscuous mode
scapyconf.sniff_promisc = 0

import yaml
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

def error(msg):
    print >>sys.stderr, "Error:", msg
    sys.exit(1)

def is_cidr(s):
    m = re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$', s)
    return m is not None

def arp_ping(network, verbose=0, timeout=2):
    alive, dead = arping(net=network, timeout=timeout, verbose=verbose)
    hosts = [(x[1].hwsrc,x[1].psrc) for x in alive]
    return hosts

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description='arpsnitch.py is a tool for checking hosts on the network via arp',
            epilog='Note that arpsnitch needs to be run as root.',
            )
    parser.add_argument("--debug", "-d", help="Debug mode", action="store_true")
    parser.add_argument("--verbose", "-v", help="Verbose mode", action="store_true")
    parser.add_argument("--config", "-c", help="configuration file, e.g. /tmp/arpsnitch.yml", type=str, required=True)
    parser.add_argument("--network", "-n", help="network to monitor, e.g. 192.168.0.1/24", type=str, required=False)
    parser.add_argument("--timeout", "-t", help="time to wait for a response (for the arp ping)",
            type=int,
            default=2,
            required=False)

    args = parser.parse_args()

    if not os.geteuid() == 0:
        error("{} must be run as root.".format(sys.argv[0]))

    if args.network is not None:
        # test if this looks valid
        if not is_cidr(args.network):
            error("--network {} is not a valid IPv4 CIDR range.".format(args.network))

    # read config file
    try:
        with open(args.config) as f:
            configstr = f.read()
    except IOError:
        configstr = ""

    # parse yaml config
    config = yaml.load(configstr, Loader=Loader)
    if config is None:
        config = {}

    # handle --network
    if args.network is not None:
        if args.network not in config:
            config[args.network] = {}

    if len(config) == 0:
        error("No networks configured. For the first run add --network.")

    # TODO check config

    now = datetime.now().replace(microsecond=0).isoformat()

    notifications = {}

    for network in config.iterkeys():
        # ping network
        hosts = arp_ping(network, timeout=args.timeout, verbose=args.debug)
        # update hosts
        for hwaddr, ip in hosts:
            notifications[hwaddr] = []
            if args.debug:
                print "hwaddr: {} ip: {}".format(hwaddr,ip)
            # get hostname via socket
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = ip
            if hwaddr in config[network]:
                # check status
                if config[network][hwaddr]['status'] != 'alive':
                    # add notification
                    notifications[hwaddr].append("status {} -> {} (missing since {})".format(config[network][hwaddr]['status'],'alive', config[network][hwaddr]['last_seen']))
                    config[network][hwaddr]['status'] = 'alive'
                # update date
                config[network][hwaddr]['last_seen'] = now
                # check hostname
                if hostname != config[network][hwaddr]['hostname']:
                    # track old hostname as alias
                    if config[network][hwaddr]['hostname'] not in config[network][hwaddr]['alias']:
                        config[network][hwaddr]['alias'].append(config[network][hwaddr]['hostname'])
                    # add notification
                    notifications[hwaddr].append(
                        "hostname {} -> {}".format(config[network][hwaddr]['hostname'],hostname)
                        )
                    # update hostname
                    config[network][hwaddr]['hostname'] = hostname
                if ip != config[network][hwaddr]['ip']:
                    if config[network][hwaddr]['ip'] not in config[network][hwaddr]['alias']:
                        config[network][hwaddr]['alias'].append(config[network][hwaddr]['ip'])
                    # add notification
                    notifications[hwaddr].append(
                        "ip {} -> {}".format(config[network][hwaddr]['ip'],ip)
                        )
                    # update ip
                    config[network][hwaddr]['ip'] = ip
                if len(notifications[hwaddr])>0:
                    # print notifications
                    if not config[network][hwaddr]['ignore'] and not args.verbose:
                        print "{} ({}): {}".format(hwaddr,hostname,", ".join(notifications[hwaddr]))
                elif args.verbose:
                    print "{} ({}): ok".format(hwaddr,hostname)
            else:
                # add new host
                config[network][hwaddr] = \
                    {
                        'ip' : ip,
                        'hostname' : hostname,
                        'first_seen' : now,
                        'last_seen' : now,
                        'alias': [],
                        'comment': '',
                        'status':'alive',
                        'ignore':False,
                    }
                print "{} ({}): new".format(hwaddr,hostname)
        # check every hosts we know, if the host was updated
        for host in config[network]:
            if config[network][host]['last_seen'] != now and \
                    config[network][host]['status'] == 'alive':
                # the host is missing
                config[network][host]['status'] = 'missing'
                print "{} ({}): missing. last seen: {}".format(
                        host,
                        config[network][host]['hostname'],
                        config[network][host]['last_seen'],
                        )

    if len(config)>0:
        configstr = yaml.dump(config, Dumper=Dumper)
        # update the config file
        try:
            with open(args.config, 'w') as f:
                f.write(configstr)
        except IOError:
            error("Can not open {} for writing.".format(args.config))

    sys.exit(0)
