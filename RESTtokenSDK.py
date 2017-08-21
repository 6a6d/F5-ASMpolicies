#! /usr/bin/python

import requests
from f5.bigip.tm import asm

requests.packages.urllib3.disable_warnings()

from f5.bigip import ManagementRoot

# Basic Authentication
# b = ManagementRoot('192.168.10.41', 'admin', 'admin')
# Token Authentication
b = ManagementRoot('192.168.10.41', 'admin', 'admin', token=True)
b.tmos_version
u'12.1.2'

# The LTM Organizing Collection
for x in b.tm.asm.tasks.get_collection():
    print x

asmP = b.tm.asm.policies_s.get_collection()
for policy in asmP:
#    asmD = b.tm.asm.policies_s.Policy()
    print "(+) Info: Exporting XML for policy '" + policy.name + "'"
    try:
        b.tm.asm.tasks.export-policy?(policy, '/var/tmp/' + asm.replace("/", "_") + '.xml')

    except Exception, e:
        print "(-) Error: Exporting XML for policy '" + policy.name + "' failed"

# The Net/Vlan Collection:
#vlans = b.tm.net.vlans.get_collection()
#for vlan in vlans:
#   print vlan.name

