#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

import argparse
import base64
import json
import logging
import requests
import signal
import sys
import time
import urllib2
from Crypto.Hash import HMAC
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

logging.basicConfig(level=logging.INFO)


class InterNIMSClient(object):

    def __init__(self, internimsurl='https://internims.appspot.com/', hostname, uid, pubkey, privkey, sleep_time):
        self.uid = uid
        self.internimsurl = internimsurl
        self.hostname = hostname
        self.pubkey = open(pubkey).read()
        self.privkey = open(privkey).read()
        # figure a few things out...
        self.userlist = self._collect_users()
        self.payload = {'uid': self.uid, 'host': self.hostname, 'users': self.userlist, 'pubkey': base64.urlsafe_b64encode(self.pubkey)}
        # daemon stuffs
        self.alive = True
        self.sleeptime = sleep_time

    def cram_client(self):
        """cram authentication"""
        # 1. client hello, without an 'authorization' header
        r = requests.post(url=self.internimsurl, data=self.payload)
        # 2. server sends 401, along with a challenge in the www-authenticate header
        if r.status_code == 401:
            challenge = base64.b64decode(r.headers['www-authenticate'])
            logging.info('Authorization requested; challenge: %s' % challenge)
            # 3. create response, by encrypting the challenge with pubkey
            h = HMAC.new(self.pubkey, challenge)
            # full response contains uid for identification and hex digest of challenge
            response = base64.b64encode('%s %s' % (self.uid, h.hexdigest()))
            logging.info('sending: %s' % response)
            headers = {'authorization': response}
            # this request should be approved, now give the FULL payloads
            r = requests.post(url=self.internimsurl, data=self.payload, headers=headers)
            logging.info(r.text)

    def _collect_users(self):
        # placeholder for pymongo code. as a reminder.
        userlist = ['user1', 'user2', 'batman', 'robin']
        return json.dumps(userlist)

    def halt(self):
        self.alive = False

    def run(self):
        while self.alive:
            self.cram_client()
            time.sleep(self.sleeptime)


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('interNIMS_URL', help='https://internims.example.com/')
    arg_parser.add_argument('hostname', help='fqdn, e.g. host.example.com')
    # arg_parser.add_argument('uri', help='DB URI')
    # arg_parser.add_argument('stage_path', help='path to staging area')
    # arg_parser.add_argument('nims_path', help='data destination')
    arg_parser.add_argument('-u', '--uid', help='unique id string')
    arg_parser.add_argument('-c', '--commonname', help='common name')
    arg_parser.add_argument('--pubkey', help='path to rsa openssl public key')
    arg_parser.add_argument('--privkey', help='path to rsa openssl private key')
    # arg_parser.add_argument('-p', '--preserve', help='preserve incompatible files here')
    # arg_parser.add_argument('-j', '--json', help='JSON file containing users and groups')
    arg_parser.add_argument('-s', '--sleeptime', default=60, type=int, help='time to sleep between sending "is alive".')
    # arg_parser.add_argument('-t', '--tempdir', help='directory to use for temporary storage')
    # arg_parser.add_argument('-n', '--logname', help='process name for log')
    # arg_parser.add_argument('-f', '--logfile', help='path to logfile')
    # arg_parser.add_argument('-l', '--loglevel', default='info', help='log level (default: info)')
    arg_parser.add_argument('-q', '--quiet', action='store_true', default=False, help='disable console logging')
    args = arg_parser.parse_args()

    hb = InterNIMSClient(internimsurl=args.interNIMS_URL, hostname=args.hostname, uid=args.uid, pubkey=args.pubkey, privkey=args.privkey, sleep_time=args.sleeptime)

    def term_handler(signum, stack):
        hb.halt()
        logging.info('Recieved SIGTERM - shutting down...')
        # add clean-up behaviors here

    signal.signal(signal.SIGTERM, term_handler)

    hb.run()
    logging.warning('Process Halted')