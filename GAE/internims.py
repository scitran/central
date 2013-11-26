#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

import base64
import datetime
import httplib
import json
import logging
import webapp2
import time
from Crypto.Hash import HMAC
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Signature import PKCS1_v1_5
from google.appengine.ext import db

from internimsutil import AuthorizedHost, NIMSServer, CRAMChallenge, key_AuthorizedHosts, key_NIMSServers, key_Challenges

logging.basicConfig(level=logging.INFO)


class InterNIMS(webapp2.RequestHandler):

    def __init__(self, request=None, response=None):
        webapp2.RequestHandler.__init__(self, request, response)

    def get(self):
        # self.response.write('internims cram')
        if self.CRAM():
            self.response.write('AUTHORIZED')

    def post(self):
        # get some info from the request
        try:
            self._id = self.request.get('_id')
            self.commonname = self._id
            self.hostname = self.request.get('host')
            self.ipv4 = '0.0.0.0'
            self.userlist = json.loads(self.request.get('users'))
            self.pubkey = base64.urlsafe_b64decode(str(self.request.get('pubkey')))
        except KeyError:
            self.abort(400)

        if self.CRAM() and self._host_reachable():
            self.update_datastore()
            self.return_NIMSServers()

    def CRAM(self):
        """challenge response auth mechanism."""
        try:
            authinfo = self.request.headers['authorization']
            _id, digest = base64.b64decode(authinfo).split()
            authd = AuthorizedHost.all().ancestor(key_AuthorizedHosts).filter('_id =', _id).filter('active =', True).get()
            if not authd: self.abort(403, 'host is not authorized, OR authorization for host has been disabled')
            if authd.pubkey.endswith('\r\n'):
                logging.info('repairing pubkey line endings; \\r\\n -> \\n')
                authd.pubkey = authd.pubkey.replace('\r','')
                authd.put()
            # challenge go "stale" at 30seconds
            challenge = CRAMChallenge.all().ancestor(key_Challenges).filter('_id =', _id).filter('timestamp >', datetime.datetime.now() - datetime.timedelta(seconds=30)).get()
            if not challenge: self.abort(403, 'no fresh challenge for {0}'.format(_id))
            # verify response
            h = HMAC.new(authd.pubkey, challenge.challenge)
            # challenges are one-time-use
            challenge.delete()
            self.expected = base64.b64encode('%s %s' % (_id, h.hexdigest()))
            if self.expected == authinfo:
                logging.info('CRAM response accepted')
                return True

        except KeyError, e:
            # send a 401 with a fresh challenge
            _id = self.request.get('_id')
            if not _id: self.abort(403, '_id required')
            authd = AuthorizedHost.all().ancestor(key_AuthorizedHosts).filter('_id =', _id).filter('active =', True).get()
            if not authd: self.abort(403, 'host is not authorized')
            challenge = str(random.getrandbits(128))
            CRAMChallenge(key_name=_id, parent=key_Challenges, _id=_id, challenge=challenge).put()
            self.response.headers['www-authenticate'] = base64.b64encode(challenge)
            self.response.set_status(401)
            logging.info('issued challenge to %s; %s' % (_id, base64.b64encode(challenge)))


    def _host_reachable(self):
        """Returns True if host is reachable."""
        conn = httplib.HTTPConnection('nims.stanford.edu')              # for testing w/o OAUTH
        conn.request('HEAD', '', headers={'User-Agent': 'InterNIMS'})   # for testing w/o OAUTH
        # conn = httplib.HTTPConnection(self.hostname)
        # conn.request('HEAD', '/nimsapi', headers={'User-Agent': 'InterNIMS'})
        resp = conn.getresponse()
        code = resp.status
        if code == 200:
            logging.info('host %s is reachable' % self.hostname)
            return True
        else:
            logging.info('host %s is not reachable' % self.hostname)
            return False

    def update_datastore(self):
        """updates datastore NIMSServer entity for entity with matching _id."""
        server = NIMSServer.all().ancestor(key_NIMSServers).filter('_id =', self._id).get() or NIMSServer(key_name=self._id, parent=key_NIMSServers, _id=self._id, commonname=self.commonname)
        server.hostname = self.hostname
        server.ipv4 = self.ipv4
        server.userlist = self.userlist
        server.timestamp = datetime.datetime.now()
        server.pubkey = self.pubkey
        server.put()

    def return_NIMSServers(self):
        # cannot do more than one filter with inequality operators.  how to exclude requesting site from report
        servers = NIMSServer.all().ancestor(key_NIMSServers).filter('timestamp >', datetime.datetime.now() - datetime.timedelta(minutes=2))
        self.response.write(json.dumps([server.as_dict() for server in servers], sort_keys=True, indent=4, separators=(',', ': ')))


app = webapp2.WSGIApplication([('/', InterNIMS),
                              ], debug=True)