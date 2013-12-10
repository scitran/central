#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

import json
import time
import base64
import httplib
import logging
import webapp2
import datetime
import Crypto.Hash.HMAC
import Crypto.Random.random
from google.appengine.ext import db

from internimsutil import AuthorizedHost, NIMSServer, NIMSServerHistory, CRAMChallenge, key_AuthorizedHosts, key_NIMSServers, key_NIMSServerHistory, key_Challenges

log = logging.getLogger('internims')


class InterNIMS(webapp2.RequestHandler):

    """internims instance registry"""

    def __init__(self, request=None, response=None):
        webapp2.RequestHandler.__init__(self, request, response)

    def get(self):
        if self.CRAM():
            self.response.write('AUTHORIZED')

    def post(self):
        """'is-alive' POST request handler listener"""
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
        # expire all challenges older than 30sec
        expired_challenges = CRAMChallenge.all().ancestor(key_Challenges).filter('timestamp <', datetime.datetime.now() - datetime.timedelta(seconds=30))
        # clean out expired
        for expired in expired_challenges:
            log.debug('expiring challenge %s at %s' % (str(expired), datetime.datetime.utcnow().isoformat()))
            expired.delete()
        try:
            authinfo = self.request.headers['authorization']
            _id, digest = base64.b64decode(authinfo).split()
            authd = AuthorizedHost.all().ancestor(key_AuthorizedHosts).filter('_id =', _id).filter('active =', True).get()
            if not authd: self.abort(403, 'host is not authorized, OR authorization for host has been disabled')
            if authd.pubkey.endswith('\r\n'):
                log.debug('repairing pubkey line endings; \\r\\n -> \\n')
                authd.pubkey = authd.pubkey.replace('\r','')
                authd.put()
            # lookup challenge by _id, and creation within last 30 sec
            challenge = CRAMChallenge.all().ancestor(key_Challenges).filter('_id =', _id).filter('timestamp >', datetime.datetime.now() - datetime.timedelta(seconds=30)).get()
            if not challenge: self.abort(403, 'no fresh challenge for {0}'.format(_id))
            # verify response
            h = Crypto.Hash.HMAC.new(authd.pubkey, challenge.challenge)
            self.expected = base64.b64encode('%s %s' % (_id, h.hexdigest()))
            challenge.delete()
            log.debug('recieved: %s' % authinfo)
            log.debug('expected: %s' % self.expected)
            if self.expected == authinfo:
                log.debug('CRAM response accepted - %s authenticated' % _id)
                return True

        except KeyError, e:
            # send a 401 with a fresh challenge
            _id = self.request.get('_id')
            if not _id: self.abort(403, '_id required')
            authd = AuthorizedHost.all().ancestor(key_AuthorizedHosts).filter('_id =', _id).filter('active =', True).get()
            if not authd: self.abort(403, 'host is not authorized')
            challenge = str(Crypto.Random.random.getrandbits(128))
            CRAMChallenge(key_name=_id, parent=key_Challenges, _id=_id, challenge=challenge).put()
            self.response.headers['www-authenticate'] = base64.b64encode(challenge)
            self.response.set_status(401)
            log.debug('issued challenge to %s; %s' % (_id, challenge))

    def _host_reachable(self):
        """Returns True if host is reachable."""
        conn = httplib.HTTPConnection('nims.stanford.edu')              # for testing w/o OAUTH
        conn.request('HEAD', '', headers={'User-Agent': 'InterNIMS'})   # for testing w/o OAUTH
        # conn = httplib.HTTPConnection(self.hostname)
        # conn.request('HEAD', '/nimsapi', headers={'User-Agent': 'InterNIMS'})
        if conn.getresponse().status == 200:
            log.debug('host %s is reachable' % self.hostname)
            return True
        else:
            log.debug('host %s is not reachable' % self.hostname)
            return False

    def update_datastore(self):
        """updates datastore NIMSServer entity for entity with matching _id."""
        # update NIMSServer entity
        server = NIMSServer.all().ancestor(key_NIMSServers).filter('_id =', self._id).get() or NIMSServer(key_name=self._id, parent=key_NIMSServers, _id=self._id, commonname=self.commonname)
        server.hostname = self.hostname
        server.ipv4 = self.ipv4
        server.userlist = self.userlist
        server.timestamp = datetime.datetime.utcnow()
        server.pubkey = self.pubkey
        server.put()
        # locate an existing history entry, OR create a new NIMSServerHistory with automatic unique keyname
        # unique keyname should prevent overwriting of host histories...
        nsh = NIMSServerHistory.all().ancestor(key_NIMSServerHistory).filter('_id =', self._id).filter('expired =', False).get() or NIMSServerHistory(parent=key_NIMSServerHistory, _id=self._id)
        nsh.expired = False
        nsh.modified = datetime.datetime.utcnow()
        nsh.expiration = None
        nsh.put()
        log.debug('%s modified at %s' % (nsh._id, nsh.modified))
        # expire NIMSservers that have not sent is_alive for 2+ minutes
        expired_servers = NIMSServer.all().ancestor(key_NIMSServers).filter('timestamp <', datetime.datetime.utcnow() - datetime.timedelta(minutes=2))
        for expired in expired_servers:
            # delete expired NIMSServer entity
            expired.delete()
            log.debug('%s had no is_alive for >2 minutes. removed from NIMSServer.' % expired._id)
            # update NIMSServerHistory log. set expiration time, but leave expired=False
            # expiration time, expired=False, indicates NIMSServerHistory entity is marked for expiration/lock
            nsh = NIMSServerHistory.all().ancestor(key_NIMSServerHistory).filter('_id =', expired._id).filter('expired =', False).get()
            if nsh:
                nsh.expiration = datetime.datetime.utcnow()
                nsh.put()
                log.debug('%s will expire if no is_alive within 24 hours' % nsh._id)

        # are there any NIMSServerHistory that have not been modified in over 1 day
        expired_history = NIMSServerHistory.all().ancestor(key_NIMSServerHistory).filter('modified <', datetime.datetime.utcnow() - datetime.timedelta(days=1)).filter('expired =', False)
        for expired in expired_history:
            expired.expired = True
            expired.expiration = datetime.datetime.utcnow()
            expired.put()
            log.debug('%s had no is_alive for >1 day, expired on %s' % (expired._id, expired.expiration.isoformat()))

    def return_NIMSServers(self):
        """writes list of registered NIMS Instances."""
        # servers = NIMSServer.all().ancestor(key_NIMSServers).filter('_id !=', self.hostname).filter('timestamp >', datetime.datetime.now() - datetime.timedelta(minutes=2))
        servers = NIMSServer.all().ancestor(key_NIMSServers).filter('timestamp >', datetime.datetime.now() - datetime.timedelta(minutes=2))
        # exclude requesting NIMS instance from response
        self.response.write(json.dumps([server.as_dict() for server in servers if server._id != self._id], sort_keys=True, indent=4, separators=(',', ': ')))


app = webapp2.WSGIApplication([('/', InterNIMS),
                              ], debug=True)