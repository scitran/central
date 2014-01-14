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
import Crypto.Hash.SHA
import Crypto.PublicKey.RSA
import Crypto.Signature.PKCS1_v1_5

import nimsutil

log = logging.getLogger('internims')
requests_log = logging.getLogger('requests')            # configure Requests logging
requests_log.setLevel(logging.WARNING)                  # set level to WARNING (default is INFO)


class InterNIMSClient(object):

    """Sends 'is-alive' to internims central."""

    def __init__(self, db, hostname, iid, privkey, sleep_time, internimsurl='https://internims.appspot.com/'):
        self.db = db
        self.internimsurl = internimsurl
        self.privkey = open(privkey).read()
        userlist = self._collect_users()
        self.payload = json.dumps({'iid': iid, 'hostname': hostname, 'users': userlist})
        self.alive = True
        self.sleeptime = sleep_time

    def is_alive(self):
        """POST request that submits NIMS instance details"""
        key = Crypto.PublicKey.RSA.importKey(self.privkey)
        h = Crypto.Hash.SHA.new(self.payload)
        signature = Crypto.Signature.PKCS1_v1_5.new(key).sign(h)

        # LINUX: sending of unencoded signature results in 'HTTP 400: INFO HTTP requires CRLF terminators'
        # b64 encoding signature works, for now.
        headers = {'Authorization': base64.b64encode(signature)}

        r = requests.post(url=self.internimsurl, data=self.payload, headers=headers, verify=True)
        if r.status_code == 200:
            sites = json.loads(r.content)
            for site in sites:
                site['UTC'] = datetime.datetime.strptime(site['timestamp'], '%Y-%m-%dT%H:%M:%S.%f')
                self.db.remotes.find_and_modify(query={'_id': site['_id']}, update=site, upsert=True, new=True)
                log.debug('upserting remote site %s' % site['_id'])
        else:
            log.info((r.status_code, r.reason))

    def _collect_users(self):
        """collect NON-LOCAL users, who have access to experiments"""
        # todo: create test no local users
        # get a list of all users who's names contain '@'
        # tease apart username, and instance ID
        # for each non-local user, find if they have permissions to access any experiments
        # return list of users who are permitted to access experiments on this local instance
        users = [user['_id'] for user in list(db.users.find({}, {'_id': True}))]
        return users

    def halt(self):
        """"halt listener."""
        self.alive = False

    def run(self):
        """run listener."""
        while self.alive:
            self.is_alive()
            time.sleep(self.sleeptime)


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('uri', help='DB URI')
    arg_parser.add_argument('interNIMS_URL', help='https://internims.appspot.com/')
    arg_parser.add_argument('hostname', help='fqdn, without protocol (http:// or https://), e.g. host.example.com')
    arg_parser.add_argument('-i', '--iid', help='instance ID')
    arg_parser.add_argument('--privkey', help='path to openssl private key')
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
    hb = InterNIMSClient(db=db, internimsurl=args.interNIMS_URL, hostname=args.hostname, iid=args.iid, privkey=args.privkey, sleep_time=args.sleeptime)

    def term_handler(signum, stack):
        hb.halt()
        log('Recieved SIGTERM - shutting down...')
        # add clean-up behaviors here

    signal.signal(signal.SIGTERM, term_handler)

    hb.run()
    logging.warning('Process Halted')
