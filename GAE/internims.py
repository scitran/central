#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

import base64
import datetime
import httplib
import json
import logging
import urllib2
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
            self.uid = self.request.get('uid')
            self.commonname = self.uid
            self.hostname = self.request.get('host')
            self.ipv4 = '0.0.0.0'
            self.userlist = json.loads(self.request.get('users'))
            self.pubkey = base64.urlsafe_b64decode(str(self.request.get('pubkey')))
        except KeyError:
            self.abort(400)

        if self.CRAM():
            self.update_datastore()
            self.return_NIMSServers()

    def CRAM(self):
        """challenge response auth mechanism."""
        try:
            authinfo = self.request.headers['authorization']
            # lack of authorization header leads to KeyError. see exception below.
            uid, digest = base64.b64decode(authinfo).split()
            authd = AuthorizedHost.all().ancestor(key_AuthorizedHosts).filter('uid =', uid).filter('active =', True).get()
            if not authd: self.abort(403, 'host is not authorized, OR authorization for host has been disabled')

            # if the pubkey ends with '\r\n' then the entity has been modified from the GAE interface
            if authd.pubkey.endswith('\r\n'):
                logging.info('converting crlf (\\r\\n) to lf (\\n)')
                authd.pubkey = authd.pubkey.replace('\r','')
                authd.put()
            else:
                logging.info('pubkey line endings OK')

            # look up the challenge information. must be less than 30 seconds old
            challenge = CRAMChallenge.all().ancestor(key_Challenges).filter('uid =', uid).filter('timestamp >', datetime.datetime.now() - datetime.timedelta(seconds=30)).get()
            # if no fresh challenge
            if not challenge: self.abort(403, 'no fresh challenge')

            logging.info('%s challenge \'%s\'' % (uid, challenge.challenge))

            # now use the information from the uid specific challenge entity and authd entity
            h = HMAC.new(authd.pubkey, challenge.challenge)
            self.expected = base64.b64encode('%s %s' % (uid, h.hexdigest()))
            logging.info('expected: %s' % self.expected)
            logging.info('recieved: %s' % authinfo)
            if self.expected == authinfo:
                # once the challenge/response has been used up, should remove the challenge (no replay attacks)
                # challenge.delete()
                return True

        except KeyError, e:
            # send a 401 with a fresh challenge
            uid = self.request.get('uid')
            if not uid: self.abort(403, 'additional message')

            ### TODO: PUT IS AUTH check here. why even issue a challenge if the uid is not authd

            challenge = str(random.getrandbits(128))
            # enter the challenge into datastore, time-stamp is 'auto-now'
            CRAMChallenge(key_name=uid, parent=key_Challenges, uid=uid, challenge=challenge).put()
            # www-authenticate needs more details to be RFC complaint
            logging.info('issuing challenge to %s; %s' % (uid, base64.b64encode(challenge)))
            # send the challenge in 'www-authenticate' header, with a 401 status code
            self.response.headers['www-authenticate'] = base64.b64encode(challenge)
            self.response.set_status(401)

    def _host_reachable(self):
        """used in both self.keypairauth() and self.cramauth() to ensure host
        is reachable from teh interwebs"""
        try:
            req = urllib2.Request('http://%s' % self.hostname)
            code = urllib2.urlopen(req).getcode()
            if code == 200:
                logging.info('host %s is reachable' % self.hostname)
                return True
            else:
                logging.info('host %s is not reachable' % self.hostname)
                return False
        except (httplib.InvalidURL, urllib2.HTTPError, httplib.error), e:
            logging.error(e)
            return False

    def update_datastore(self):
        # UID and Commonname should stay the same
        server = NIMSServer.all().ancestor(key_NIMSServers).filter('uid =', self.uid).get() or NIMSServer(key_name=self.uid, parent=key_NIMSServers, uid=self.uid, commonname=self.commonname)
        server.hostname = self.hostname
        server.ipv4 = self.ipv4
        server.userlist = self.userlist
        server.timestamp = datetime.datetime.now()
        server.pubkey = self.pubkey
        server.put()

    def return_NIMSServers(self):
        # don't return the requesting server on the list. how to filter this...
        servers = NIMSServer.all().ancestor(key_NIMSServers).filter('timestamp >', datetime.datetime.now() - datetime.timedelta(minutes=2))
        self.response.write(json.dumps([server.as_dict() for server in servers], sort_keys=True, indent=4, separators=(',', ': ')))


app = webapp2.WSGIApplication([('/', InterNIMS),
                              ], debug=True)