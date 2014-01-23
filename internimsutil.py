#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

from google.appengine.ext import ndb


key_AuthorizedHosts = ndb.Key('InterNIMS', 'AuthorizedHosts')
key_NIMSServers = ndb.Key('InterNIMS', 'NIMSServers')
key_NIMSServerHistory = ndb.Key('InterNIMS', 'NIMSServerHistory')


class AuthorizedHost(ndb.Model):

    id = ndb.StringProperty()
    commonname = ndb.StringProperty()                   # human readable
    pubkey = ndb.StringProperty()
    active = ndb.BooleanProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)

    def __str__(self):
        return self.id

    def as_dict(self):
        return {'_id': self.id, 'commonname': self.commonname, 'pubkey': self.pubkey}


class NIMSServer(ndb.Model):

    id = ndb.StringProperty()
    pubkey = ndb.StringProperty()
    api_uri = ndb.StringProperty()
    timestamp = ndb.DateTimeProperty()
    userlist = ndb.StringProperty(repeated=True)

    def __str__(self):
        return '%s: %s' % (str(self.timestamp), self.id)

    def as_dict(self):
        return {'_id': self.id,
                'pubkey': self.pubkey,
                'userlist': self.userlist,
                'api_uri': self.api_uri,
                'timestamp': self.timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')}


class NIMSServerHistory(ndb.Model):

    id = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)
    modified = ndb.DateTimeProperty()                   # last mod
    expiration = ndb.DateTimeProperty()                 # expiration timer
    expired = ndb.BooleanProperty()                     # expired boolean
