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
import Crypto.Hash.SHA
import Crypto.PublicKey.RSA
import Crypto.Signature.PKCS1_v1_5

from google.appengine.ext import ndb

from internimsutil import AuthorizedHost, NIMSServer, NIMSServerHistory, key_AuthorizedHosts, key_NIMSServers, key_NIMSServerHistory

log = logging.getLogger('internims')
logging.basicConfig(level=logging.DEBUG)


class InterNIMS(webapp2.RequestHandler):

    """internims instance registry"""

    def __init__(self, request=None, response=None):
        webapp2.RequestHandler.__init__(self, request, response)

    def post(self):
        """'is-alive' POST request handler listener"""
        try:
            # message and signature to verify
            self.message = self.request.body
            self.signature = base64.b64decode(self.request.headers.get('Authorization'))
            # parse request body as json
            self.payload = json.loads(self.message)
            self.iid = self.payload.get('iid')
            self.hostname = self.payload.get('hostname')
            self.userlist = self.payload.get('users')
        except KeyError as e:
            self.abort(400, e)

        # is iid authorized
        authd = AuthorizedHost.query(ancestor=key_AuthorizedHosts).filter(AuthorizedHost.id == self.iid).filter(AuthorizedHost.active == True).get()
        if not authd: self.abort(403, 'host is not authorized')

        # clean up pubkey line endings
        if authd.pubkey.endswith('\r\n'):
            auth.pubkey = authd.pubkey.replace('\n', '')
            authd.put()

        # verify message/signature
        key = Crypto.PublicKey.RSA.importKey(authd.pubkey)
        h = Crypto.Hash.SHA.new(self.message)
        verifier = Crypto.Signature.PKCS1_v1_5.new(key)
        if verifier.verify(h, self.signature):
            log.debug('message/signature is authentic')
        else:
            log.debug('message/signature is not authentic')
            self.abort(403)

        # is hostname api reachable
        # TODO: use only HTTPS, set to real hostname
        conn = httplib.HTTPSConnection('nims.stanford.edu')             # DEBUG
        conn.request('HEAD', '', headers={'User-Agent': 'InterNIMS'})   # DEBUG
        # conn = httplib.HTTPSConnection(self.hostname)
        # conn.request('HEAD', '/nimsapi', headers={'User-Agent': 'InterNIMS'})
        if conn.getresponse().status == 200:
            log.debug('host is reachable')
        else:
            log.debug('host is not reachable')
            self.abort(403, 'host is not reachable')

        # create/update NIMSServer entity
        server = NIMSServer.query(ancestor=key_NIMSServers).filter(NIMSServer.id == self.iid).get() or NIMSServer(id=self.iid, parent=key_NIMSServers)
        server.commonname = authd.commonname            # NIMSServer inherits commonname from AuthiorizedHost
        server.pubkey = authd.pubkey                    # NIMSServer inherits pubkey from AuthorizedHost
        server.hostname = self.hostname
        server.userlist = self.userlist
        server.timestamp = datetime.datetime.utcnow()
        server.put()

        # expire NIMSServerHistory that haven't been modified for 1+ day
        expired_history = NIMSServerHistory.query(ancestor=key_NIMSServerHistory).filter(NIMSServerHistory.modified < datetime.datetime.utcnow() - datetime.timedelta(days=1)).filter(NIMSServerHistory.expired == False)
        for expired in expired_history:
            expired.expired = True
            expired.expiration = datetime.datetime.utcnow()
            expired.put()
            log.debug('%s had no is_alive for >1 day, expired on %s' % (expired.id, expired.expiration.isoformat()))

        # create/update HIMSServerHistory entity, do not update 'expired' history entities
        nsh = NIMSServerHistory.query(ancestor=key_NIMSServerHistory).filter(NIMSServerHistory.id == self.iid).filter(NIMSServerHistory.expired == False).get() or NIMSServerHistory(id=self.iid, parent=key_NIMSServerHistory)
        nsh.expired = False
        nsh.modified = datetime.datetime.utcnow()
        nsh.expiration = None
        nsh.put()
        log.info('%s modified at %s' % (nsh.id, nsh.modified))

        # remove NIMSservers that have not sent is_alive for 2+ minutes
        expired_servers = NIMSServer.query(ancestor=key_NIMSServers).filter(NIMSServer.timestamp < datetime.datetime.utcnow() - datetime.timedelta(minutes=2))
        for expired in expired_servers:
            log.debug('%s had no is_alive for >2 minutes. removed from NIMSServer.' % expired.id)
            expired.key.delete()

        # return NIMSServers, exclude requesting NIMS instance
        servers = NIMSServer.query(ancestor=key_NIMSServers).filter(NIMSServer.timestamp > datetime.datetime.now() - datetime.timedelta(minutes=2))
        self.response.write(json.dumps([server.as_dict() for server in servers if server.id != self.iid], sort_keys=True, indent=4, separators=(',', ': ')))


app = webapp2.WSGIApplication([('/', InterNIMS),
                              ], debug=True)
