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
import time

from scapy.layers.l2 import arping
from scapy.all import conf as scapyconf
# disable scapy promiscuous mode
scapyconf.sniff_promisc = 0

import fasteners
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

def arp_ping(network, verbose=0, timeout=2, count=3):
    """ping network and return a list of tuples (mac-address,ip-address)"""
    hosts = []
    for _ in xrange(count):
        alive, dead = arping(net=network, timeout=timeout, verbose=verbose)
        hosts += [(x[1].hwsrc,x[1].psrc) for x in alive]
    return list(set(hosts))

def get_hostname(ipaddr):
    # get hostname via socket
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = ip
    return hostname

def check_host(hwaddr, ipaddr, config, args, timestr):
    """
        check host infos against the config

        returns changes, updated_config
    """
    changes = []
    # get hostname
    hostname = get_hostname(ipaddr)
    if hwaddr in config:
        # shortcut
        c = config[hwaddr]
        # check status
        if c['status'] != 'online':
            changes    += ['offline -> online','offline since {}'.format(c['last_seen'])]
            c['status'] = 'online'
        if c['ip']  != ipaddr:
            changes += ["{} -> {}".format(c['ip'], ipaddr)]
            if c['ip'] not in c['alias']:
                c['alias'] += [c['ip']]
            c['ip']  = ipaddr
        if c['hostname']  != hostname:
            changes += ["{} -> {}".format(c['hostname'], hostname)]
            if c['hostname'] not in c['alias']:
                c['alias'] += [c['hostname']]
            c['hostname']  = hostname
        # update config
        c['last_seen'] = timestr
        config[hwaddr] = c
    else:
        # add host to config
        config[hwaddr] = \
            {
                'ip' : ipaddr,
                'hostname' : hostname,
                'first_seen' : timestr,
                'last_seen' : timestr,
                'alias': [],
                'comment': '',
                'status':'online',
                'ignore':False,
            }
        changes += ['NEW']
    return changes, config

def format_changes(hwaddr, notifications, config):
    if len(notifications)<1 or config['ignore']:
        return ""
    fmt = "{:17.17}  {:16.16} {:15.15}  {:47.47}\n"
    s = fmt.format(hwaddr, config['hostname'], config['ip'], notifications[0])
    for msg in notifications[1:]:
        s+=fmt.format('', '', '', msg)
    return s

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description='arpsnitch.py is a tool for checking hosts on the network via arp',
            epilog='Note that arpsnitch needs to be run as root.',
            )
    parser.add_argument("--debug", "-D", help="Debug mode", action="store_true")
    parser.add_argument("--verbose", "-v", help="Verbose mode", action="store_true")
    parser.add_argument("--daemon", "-d", help="Run in deamon mode", action="store_true")
    parser.add_argument("--interval", "-i", help="Time to sleep after each check (in daemon mode).",
        type=int, default=60)
    parser.add_argument("--config", "-c", help="configuration file, e.g. /tmp/arpsnitch.yml", type=str, required=True)
    parser.add_argument("--network", "-n", help="network to monitor, e.g. 192.168.0.1/24", type=str, required=False)
    parser.add_argument("--timeout", "-t", help="time to wait for a response (for the arp ping)",
            type=int,
            default=10,
            required=False)

    args = parser.parse_args()

    if not os.geteuid() == 0:
        error("{} must be run as root.".format(sys.argv[0]))

    if args.network is not None:
        # test if this looks valid
        if not is_cidr(args.network):
            error("--network {} is not a valid IPv4 CIDR range.".format(args.network))

    # lock process
    lockfile = args.config+'.lock'
    lock= fasteners.InterProcessLock(lockfile)
    if not lock.acquire(blocking=False):
        error("Lockfile '{}' exists.".format(lockfile))

    # read config file
    try:
        with open(args.config) as f:
            configstr = f.read()
    except IOError:
        configstr = ""

    while True:
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

        output = ""

        for network in config.iterkeys():
            # ping network
            if args.debug: print >>sys.stderr, "debug: arpping", network
            hosts = arp_ping(network, timeout=args.timeout, verbose=args.debug)
            # update hosts
            for hwaddr, ip in hosts:
                if args.debug:
                    print "debug: checking hwaddr={} ip={}".format(hwaddr,ip)
                changes, config[network] = check_host(hwaddr, ip, config[network], args, timestr=now) 
                notifications[hwaddr] = changes
            # check every hosts we know, if the host was updated
            for host in config[network]:
                if config[network][host]['last_seen'] != now and \
                        config[network][host]['status'] == 'online':
                    # the host is missing
                    config[network][host]['status'] = 'offline'
                    if host not in notifications:
                        notifications[host] = []
                    notifications[host] += ['online -> offline',
                                            'last seen {}'.format(config[network][host]['last_seen'])]
                elif args.verbose and len(notifications[host])<1:
                    notifications[host] += ['ok']

            for c in notifications.iterkeys():
                #print c
                #print notifications[c]
                #print config[network][c]
                output += format_changes(c, notifications[c], config[network][c])

        output = output.strip()
        if len(output)>0:
            # add header to output
            output = "# {}\n# {}\n{}".format(" ".join(sys.argv), now, output)
            print output

        if len(config)>0:
            configstr = yaml.dump(config, Dumper=Dumper)
            # update the config file
            try:
                with open(args.config, 'w') as f:
                    f.write(configstr)
            except IOError:
                error("Can not open {} for writing.".format(args.config))
        if not args.daemon:
            break
        else:
            if args.debug:
                print >>sys.stderr, "debug: daemon is sleeping for {} seconds.".format(args.interval)
            time.sleep(args.interval)

    sys.exit(0)
