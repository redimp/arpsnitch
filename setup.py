#!/usr/bin/env python

from setuptools import setup

setup(name='arpsnitch',
      version='0.1',
      description='a tool for checking hosts on the network via arp',
      url='http://github.com/redimp/arpsnitch',
      author='Ralph Thesen',
      author_email='mail@redimp.de',
      license='MIT',
      install_requires=['scapy','pyyaml'],
      scripts=['arpsnitch.py'],
      zip_safe=False)
