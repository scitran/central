#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

import argparse
import base64
import json
import logging
import pymongo
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

    def __init__(self, db, hostname, _id, pubkey, privkey, sleep_time, internimsurl='https://internims.appspot.com/'):
        self.db = db
        self._id = _id
        self.internimsurl = internimsurl
        self.hostname = hostname
        self.pubkey = open(pubkey).read()
        self.privkey = open(privkey).read()
        self.userlist = self._collect_users()
        self.payload = {'_id': self._id, 'host': self.hostname, 'users': self.userlist, 'pubkey': base64.urlsafe_b64encode(self.pubkey)}
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
            response = base64.b64encode('%s %s' % (self._id, h.hexdigest()))
            logging.info('sending: %s' % response)
            headers = {'authorization': response}
            # this request should be approved, now give the FULL payloads
            r = requests.post(url=self.internimsurl, data=self.payload, headers=headers)

            # if repsonse OK, expect json object
            if r.status_code == 200:
                sites = list(json.loads(r.content))
                # add sites, or modify existing
                for site in sites:
                    spam = self.db.remotes.find_and_modify(query={'_id': site['_id']}, update=site, upsert=True, new=True)
                    logging.info(spam)
            else:
                # if r.status_code != 200; show plain content
                logging.info(r.content)


            # if a site is no longer being reported. i.e. goes offline
            # remove it from the local 'remotes' list.

            # TODO
            # self.db.remotes.distinct() gives list of docs in DB
            # if item in DB is not one of the sites listed
            # remove it from the DB (it's not an "active" and should not be pinged


    def _collect_users(self):
        # placeholder for pymongo code. as a reminder.
        # generator, can yield individual items to an unlimited sequence length
        # userlist = (item['_id'] for item in list(db.users.find({}, {'_id': True})))
        # list comprehension, good for create true list object, good for iterating multiple times
        # loads entire list into memory.
        userlist = [item['_id'] for item in list(db.users.find({}, {'_id': True}))]
        return json.dumps(userlist)

    def halt(self):
        self.alive = False

    def run(self):
        while self.alive:
            self.cram_client()
            time.sleep(self.sleeptime)


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('uri', help='DB URI')
    arg_parser.add_argument('interNIMS_URL', help='https://internims.appspot.com/')
    arg_parser.add_argument('hostname', help='fqdn, without protocol (http:// or https://), e.g. host.example.com')
    arg_parser.add_argument('-u', '--uid', help='unique id string')
    arg_parser.add_argument('-c', '--commonname', help='common name')
    arg_parser.add_argument('--pubkey', help='path to rsa openssl public key')
    arg_parser.add_argument('--privkey', help='path to rsa openssl private key')
    arg_parser.add_argument('-s', '--sleeptime', default=60, type=int, help='time to sleep between sending "is alive".')
    # arg_parser.add_argument('-t', '--tempdir', help='directory to use for temporary storage')
    # arg_parser.add_argument('-n', '--logname', help='process name for log')
    # arg_parser.add_argument('-f', '--logfile', help='path to logfile')
    # arg_parser.add_argument('-l', '--loglevel', default='info', help='log level (default: info)')
    arg_parser.add_argument('-q', '--quiet', action='store_true', default=False, help='disable console logging')
    args = arg_parser.parse_args()

    kwargs = dict(tz_aware=True)
    db = pymongo.MongoReplicaSetClient(args.uri, **kwargs) if 'replicaSet' in args.uri else pymongo.MongoClient(args.uri, **kwargs).get_default_database()

    hb = InterNIMSClient(db=db, internimsurl=args.interNIMS_URL, hostname=args.hostname, _id=args.uid, pubkey=args.pubkey, privkey=args.privkey, sleep_time=args.sleeptime)

    def term_handler(signum, stack):
        hb.halt()
        logging.info('Recieved SIGTERM - shutting down...')
        # add clean-up behaviors here

    signal.signal(signal.SIGTERM, term_handler)

    hb.run()
    logging.warning('Process Halted')
