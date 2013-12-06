#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

import sys
import json
import time
import base64
import signal
import logging
import pymongo
import urllib2
import argparse
import datetime
import requests
import Crypto.Hash.HMAC

import nimsutil

log = logging.getLogger('internims')
requests_log = logging.getLogger('requests')            # configure Requests logging
requests_log.setLevel(logging.WARNING)                  # set level to WARNING (default is INFO)

class InterNIMSClient(object):

    """Sends 'is-alive' to internims central."""

    def __init__(self, db, hostname, _id, pubkey, sleep_time, internimsurl='https://internims.appspot.com/'):
        self.db = db
        self._id = _id
        self.internimsurl = internimsurl
        self.hostname = hostname
        self.pubkey = open(pubkey).read()
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
            log.debug('Authorization requested - challenge: %s' % challenge)
            # 3. create response, by encrypting the challenge with pubkey
            h = Crypto.Hash.HMAC.new(self.pubkey, challenge)
            # full response contains uid for identification and hex digest of challenge
            response = base64.b64encode('%s %s' % (self._id, h.hexdigest()))
            log.debug('response:  %s %s' % (self._id, h.hexdigest()))
            log.debug('b64encode: %s' % response)
            headers = {'authorization': response}
            # this request should be approved, now give the FULL payloads
            r = requests.post(url=self.internimsurl, data=self.payload, headers=headers)

            # if repsonse OK, expect json object
            if r.status_code == 200:
                sites = list(json.loads(r.content))             # response is peer list, as JSON
                # parse response and update db.remotes
                # can parse out own instance here
                for site in sites:
                    # does a remote entry NEED to have a human readable timestamp??
                    # or can the timestamp be a UTC datetime object?
                    site['UTC'] = datetime.datetime.strptime(site['timestamp'], '%Y-%m-%dT%H:%M:%S.%f')
                    self.db.remotes.find_and_modify(query={'_id': site['_id']}, update=site, upsert=True, new=True)
                    log.debug('upserting remote site %s' % site['_id'])
            else:
                # if r.status_code != 200; show plain content
                log.info(r.content)

    def _collect_users(self):
        """return list of usernames"""
        userlist = [item['_id'] for item in list(db.users.find({}, {'_id': True}))]
        return json.dumps(userlist)

    def halt(self):
        """"halt listener."""
        self.alive = False

    def run(self):
        """run listener."""
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
    arg_parser.add_argument('-s', '--sleeptime', default=60, type=int, help='time to sleep between sending "is alive".')
    arg_parser.add_argument('-n', '--logname', help='process name for log')
    arg_parser.add_argument('-f', '--logfile', help='path to logfile')
    arg_parser.add_argument('-l', '--loglevel', default='info', help='log level (default: info)')
    arg_parser.add_argument('-q', '--quiet', action='store_true', default=False, help='disable console logging')
    args = arg_parser.parse_args()

    nimsutil.configure_log(args.logfile, not args.quiet, args.loglevel)

    kwargs = dict(tz_aware=True)
    db = pymongo.MongoReplicaSetClient(args.uri, **kwargs) if 'replicaSet' in args.uri else pymongo.MongoClient(args.uri, **kwargs).get_default_database()

    #remotes auto expire 120s after timestamp. timestamp must be kept updated.
    db.remotes.ensure_index('UTC', expireAfterSeconds=120)

    #each heartbeat, response from GAE resets TTL by updating timestamp
    hb = InterNIMSClient(db=db, internimsurl=args.interNIMS_URL, hostname=args.hostname, _id=args.uid, pubkey=args.pubkey, sleep_time=args.sleeptime)

    def term_handler(signum, stack):
        hb.halt()
        log('Recieved SIGTERM - shutting down...')
        # add clean-up behaviors here

    signal.signal(signal.SIGTERM, term_handler)

    hb.run()
    logging.warning('Process Halted')
