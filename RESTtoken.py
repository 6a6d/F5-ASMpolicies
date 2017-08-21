#! /usr/bin/python
import os
import requests
import json
import argparse
import getpass


def create_pool(bigip, url, pool):
    payload = {}
    payload['name'] = pool

    pool_config = bigip.post(url, json.dumps(payload)).json()
    return pool_config

def export_asm(bigip, url, policy):
    payload = {}
    payload['name'] = policy
    bigip.post(url, json.dumps(payload)).json()


def get_token(bigip, url, creds):
    payload = {}
    payload['username'] = creds[0]
    payload['password'] = creds[1]
    payload['loginProviderName'] = 'tmos'

    token = bigip.post(url, json.dumps(payload)).json()['token']['token']
    return token


if __name__ == "__main__":

    requests.packages.urllib3.disable_warnings()

    parser = argparse.ArgumentParser(description='Remote Authentication Test - Create Pool')

    parser.add_argument("host", help='BIG-IP IP or Hostname', )
    parser.add_argument("username", help='BIG-IP Username')
    parser.add_argument("poolname", help='Key/Cert file names (include the path.)')
    parser.add_argument("asmpname", help='ASM Policy Name')
    args = vars(parser.parse_args())

    hostname = args['host']
    username = args['username']
    poolname = args['poolname']
    asmpname = args['asmpname']

    print "%s, enter your password: " % args['username'],
    password = getpass.getpass()

    url_base = 'https://%s/mgmt' % hostname
    url_auth = '%s/shared/authn/login' % url_base
    url_pool = '%s/tm/ltm/pool' % url_base
    url_asm = '%s/tm/asm' % url_base
    url_export = '%s/tasks/export-policy' % url_asm
    url_download = '%s/file-transfer/downloads' % url_asm

    b = requests.session()
    b.headers.update({'Content-Type': 'application/json'})
    b.auth = (username, password)
    b.verify = False

    token = get_token(b, url_auth, (username, password))
    print '\nToken: %s\n' % token

    b.auth = None
    b.headers.update({'X-F5-Auth-Token': token})

    response = create_pool(b, url_pool, poolname)
#    print '\nNew Pool: %s\n' % response
    export_asm(b, url_asm, asmpname)
