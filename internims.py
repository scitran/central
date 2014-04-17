#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

import json
import time
import base64
import urllib
import webapp2
import datetime
import Crypto.Hash.SHA
import Crypto.PublicKey.RSA
import Crypto.Signature.PKCS1_v1_5

from google.appengine.ext import ndb
from google.appengine.api import urlfetch

import logging
log = logging.getLogger('internims')
logging.basicConfig(level=logging.DEBUG)

import internimsutil as inu


# lazy load config db.
if inu.Config.query(inu.Config.name == 'skip_reachable_check', ancestor=inu.k_Configs).get() == None:
    log.warning('configuration "reachable_check" not found. lazy-loading default datastore item')
    item = inu.Config(id='skip_reachable_check',
               name='skip_reachable_check',
               value='false',
               default='false',
               description='disables checking if reported api_uri is reachable',
               parent=inu.k_Configs)
    item.put()


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
            self.site = self.payload.get('site')
            self.name = self.payload.get('name')
            self.api_uri = self.payload.get('api_uri')
            self.userlist = self.payload.get('users')
        except KeyError as e:
            self.abort(400, e)

        # is site authorized
        authd = inu.AuthHost.query(inu.AuthHost.id == self.site, inu.AuthHost.active == True, ancestor=inu.k_AuthHosts).get()
        if not authd: self.abort(403, 'host is not authorized')

        # is reported api_uri reachable
        skip_reachable_check = inu.Config.query(inu.Config.name == 'skip_reachable_check', ancestor=inu.k_Configs).get()
        if skip_reachable_check.value in ['True', 'true', '1']:
            log.warning('skipping "is_host_reachable" check of reported api_uri')
        else:
            if not self.api_uri.startswith('https'):
                self.abort(400, 'api_uri ' + self.api_uri + ' is not https://')
            try:
                result = urlfetch.fetch(url=self.api_uri, method=urlfetch.HEAD, headers={'User-Agent': 'InterNIMS'}, deadline=5)
            except AttributeError:
                log.warning('api_uri ' + self.api_uri + ' not set')
                self.abort(400, 'api_uri ' + self.api_uri + 'not set')
            except urlfetch.InvalidURLError:
                log.warning('api_uri ' + self.api_uri + ' is invalid')
                self.abort(400, 'api_uri ' + self.api_uri + ' is invalid')
            except urlfetch.DeadlineExceededError:
                log.warning('api_uri ' + self.api_uri + ' timed out')
                self.abort(400, 'api_uri ' + self.api_uri + ' timed out')
            except urlfetch.DownloadError:
                log.warning('api_uri ' + self.api_uri + ' had a download error')
                self.abort(400, 'api_uri ' + self.api_uri + ' had a download error')

            if result.status_code == 200:
                log.info('api_uri ' + self.api_uri + ' is reachable')
            else:
                log.warning('api_uri is ' + self.api_uri + ' not reachable')
                self.abort(403, 'api_uri ' + self.api_uri + ' is not reachable')

        # clean up authd.pubkey line endings
        if authd.pubkey.endswith('\r\n'):
            auth.pubkey = authd.pubkey.replace('\n', '')
            authd.put()

        # verify message/signature
        key = Crypto.PublicKey.RSA.importKey(authd.pubkey)
        h = Crypto.Hash.SHA.new(self.message)
        verifier = Crypto.Signature.PKCS1_v1_5.new(key)
        if verifier.verify(h, self.signature):
            log.info('message/signature is authentic')
        else:
            log.warning('message/signature is not authentic')
            self.abort(403, 'message/signature is not authentic')

        # create/update NIMSServer entity
        server = inu.Server.query(inu.Server.id == self.site, ancestor=inu.k_Servers).get() or inu.Server(id=self.site, parent=inu.k_Servers)
        server.pubkey = authd.pubkey                    # NIMSServer inherits pubkey from AuthorizedHost
        server.name = self.name
        server.api_uri = self.api_uri
        server.userlist = self.userlist
        server.timestamp = datetime.datetime.utcnow()
        server.put()

        # expire NIMSServerHistory that haven't been modified for 1+ day
        expired_history = inu.ServerHistory.query(inu.ServerHistory.modified < datetime.datetime.utcnow() - datetime.timedelta(days=1), inu.ServerHistory.expired == False, ancestor=inu.k_ServerHistory)
        for expired in expired_history:
            expired.expired = True
            expired.expiration = datetime.datetime.utcnow()
            expired.put()
            log.debug('%s had no is_alive for >1 day, expired on %s' % (expired.id, expired.expiration.isoformat()))

        # create/update NIMSServerHistory entity, do not update 'expired' history entities
        nsh = inu.ServerHistory.query(inu.ServerHistory.id == self.site, inu.ServerHistory.expired == False, ancestor=inu.k_ServerHistory).get() or inu.ServerHistory(id=self.site, parent=inu.k_ServerHistory)
        nsh.expired = False
        nsh.modified = datetime.datetime.utcnow()
        nsh.expiration = None
        nsh.put()
        log.info('%s modified at %s' % (nsh.id, nsh.modified))

        # remove NIMSservers that have not sent is_alive for 2+ minutes
        expired_servers = inu.Server.query(inu.Server.timestamp < datetime.datetime.utcnow() - datetime.timedelta(minutes=2), ancestor=inu.k_Servers)
        for expired in expired_servers:
            log.debug('%s had no is_alive for >2 minutes. removed from NIMSServer.' % expired.id)
            expired.key.delete()

        # return NIMSServers, exclude requesting NIMS instance
        servers = inu.Server.query(inu.Server.timestamp > datetime.datetime.now() - datetime.timedelta(minutes=2), ancestor=inu.k_Servers)
        # hack to side-steps GAE ndb limitation of not being able to use inequality filters on two different attributes
        remotes = [server for server in servers if server.id != self.site]
        # all unique users from all remotes
        user_set = set([user for site in [remote.userlist for remote in remotes] for user in site])
        # create dict. keys are usernames, values are list of remote sites
        # new_remotes is a dictionary, specific to the requesting host, keys = userid, value = list of sites where they have permissions
        new_remotes = {user.split('#')[0]: [remote.id for remote in remotes if user in remote.userlist] for user in user_set}
        self.response.write(json.dumps({'sites': [remote.as_dict() for remote in remotes], 'users': new_remotes}))


app = webapp2.WSGIApplication([('/', InterNIMS),
                              ], debug=True)
