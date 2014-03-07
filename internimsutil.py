#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

from google.appengine.ext import ndb


k_AuthHosts = ndb.Key('InterNIMS', 'AuthHosts')
k_Servers = ndb.Key('InterNIMS', 'Servers')
k_ServerHistory = ndb.Key('InterNIMS', 'ServerHistory')
k_Configs = ndb.Key('InterNIMS', 'Configuration')

class AuthHost(ndb.Model):

    id = ndb.StringProperty()
    commonname = ndb.StringProperty()                   # human readable
    pubkey = ndb.StringProperty()
    active = ndb.BooleanProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)

    def __str__(self):
        return self.id

    def as_dict(self):
        return {'_id': self.id, 'commonname': self.commonname, 'pubkey': self.pubkey}


class Server(ndb.Model):

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
                'timestamp': self.timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}


class ServerHistory(ndb.Model):

    id = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)
    modified = ndb.DateTimeProperty()                   # last mod
    expiration = ndb.DateTimeProperty()                 # expiration timer
    expired = ndb.BooleanProperty()                     # expired boolean


class Config(ndb.Model):

    name = ndb.StringProperty()
    value = ndb.StringProperty()
    default = ndb.StringProperty()
    description = ndb.StringProperty()
