#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

"""
SDMC central peer registry.

Provides one route that supports two HTTP GET and POST.
POST require SSL Client Certificate.

"""

import logging
log = logging.getLogger(__name__)
logging.getLogger('requests').setLevel(logging.WARNING) # silence Requests library logging

import copy
import json
import webapp2
import datetime
import requests
import bson.json_util


def _dict_merge(a, b):
    result = copy.deepcopy(a)
    for k, v in b.iteritems():
        if k in result and isinstance(result[k], dict):
            result[k] = _dict_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


class SDMC(webapp2.RequestHandler):

    """SDMC POST and GET request handler."""

    def get(self):
        """Return status information."""
        locals_at_remotes = self.app.db.instances.aggregate([  # local users that have access elsewhere
                {'$match': {'last_seen': {'$gt': datetime.datetime.now() - datetime.timedelta(minutes=2)}}},  # all instances
                {'$unwind': '$users'},  # one user/site per entry
                {'$group': {'_id': '$users.site', 'users': {'$addToSet': '$users.user'}}},  # group by users home site
                {'$project': {'remote_access': {'$size': '$users'}}},
        ])['result']
        access = {site['_id']: {'remote_access': site['remote_access']} for site in locals_at_remotes}
        users_from_remotes = self.app.db.instances.aggregate([  # remote users that have access to that site
                {'$match': {'last_seen': {'$gt': datetime.datetime.now() - datetime.timedelta(minutes=2)}}},  # all instances
                {'$project': {'name': 1, 'remote_users': {'$size': '$users'}}},
        ])['result']
        remotes = {site['_id']: {'remote_users': site['remote_users'], 'name': site['name']} for site in users_from_remotes}
        result = {'sites': [dict([('_id', k)] + v.items()) for  k, v in _dict_merge(access, remotes).iteritems()]}
        result['num_sites'] = len(result['sites'])
        self.response.write(json.dumps(result))

    def post(self):
        """Update peer registry using POST data from approved reachable hosts."""
        # payload = {'_id': domain.example.org,
        #            'name': nickname,
        #            'api_uri': domain.example.org/api,
        #            'users': [{'user': 'user1', 'site': 'domain.example.org'},
        #                      {'user': 'user2', 'site': 'other.demo.org'},
        #                      ]
        #            }
        remote_hostname, aliases, _ = requests.utils.socket.gethostbyaddr(self.request.environ.get('REMOTE_ADDR'))
        if self.request.environ['SSL_CLIENT_VERIFY'] != 'SUCCESS':
            log.debug('%s sent request without SSL client certificate' % remote_hostname)
            self.abort(401, 'No required SSL certificate was sent.')  # auth required

        try:
            payload = json.loads(self.request.body, object_hook=bson.json_util.object_hook)
            _id = payload['_id']
            api_uri = payload['api_uri']
        except (ValueError, KeyError) as e:
            log.debug(str(e))
            self.abort(400, str(e))  # bad request

        # does reverse lookup hostname match _id
        if not _id.endswith(remote_hostname.lower()):
            log.debug('reverse lookup does not match _id %s.' % _id)
            self.abort(403, 'reverse lookup does not match _id %s.' % _id)

        # is host reachable
        try:
            r = requests.head(api_uri, timeout=3)
        except requests.packages.urllib3.exceptions.ProtocolError:
            log.debug('could not connect to %s. Name or Service not known.' % api_uri)
            self.abort(500, 'could not connect to %s. Name or Service not known.' % api_uri)  # XXX error code?
        except requests.exceptions.Timeout:
            log.debug('connection to %s timed out.' % api_uri)
            self.abort(500, 'connection to %s timed out.' % api_uri)  # XXX error code
        else:
            if r.status_code != 200:
                log.debug('head request to %s failed.' % api_uri)
                self.abort(500, 'head request to %s failed.' % api_uri)  # XXX error code

        # is host authorized?
        payload['last_seen'] = datetime.datetime.now()
        if not self.app.db.instances.update({'_id': _id}, {'$set': payload}, multi=False)['updatedExisting']:
            log.debug('host %s is not authorized' % _id)
            self.abort(403, 'host %s is not authorized' % _id)

        # success
        log.debug('updated host %s (%s).' % (_id, api_uri))

        # prepare site-specific response
        users_with_remotes = {}
        sites_with_users = self.app.db.instances.aggregate([
                {'$match': {'users.site': payload['_id']}},
                {'$unwind': '$users'},
                {'$match': {'users.site': payload['_id']}},
        ])['result']
        for site in sites_with_users:
            users_with_remotes.setdefault(site['users']['user'], []).append({'_id': site['_id'], 'name': site['name']})

        active_sites = self.app.db.instances.find(
                {'_id': {'$ne': _id}, 'last_seen': {'$gt': datetime.datetime.now() - datetime.timedelta(minutes=2)}},
                {'users': 0, 'last_seen': 0, 'date_added': 0},
        )
        self.response.write(json.dumps({'sites': list(active_sites), 'users': users_with_remotes}, default=bson.json_util.default))


routes = [
    webapp2.Route(r'/', SDMC)
]

app = webapp2.WSGIApplication(routes)
app.config = dict(check_reachable=True)

if __name__ == '__main__':
    import os
    import pymongo
    import argparse
    import ConfigParser
    import paste.httpserver

    log = logging.getLogger('sdmc')

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('config_file', help='path to config file')
    arg_parser.add_argument('--db_uri', narg=1, help='internims DB URI')
    args = arg_parser.parse_args()

    config = ConfigParser.ConfigParser({'here': os.path.dirname(os.path.abspath(args.config_file))})
    config.read(args.config_file)
    logging.config.fileConfig(args.config_file, disable_existing_loggers=False)
    logging.getLogger('paste.httpserver').setLevel(logging.DEBUG)  # silence paste loggin

    kwargs = dict(tz_aware=True)
    db_uri = args.db_uri or config.get('internims', 'db_uri')
    db_client = pymongo.MongoReplicaSetClient(db_uri, **kwargs) if 'replicaSet' in db_uri else pymongo.MongoClient(db_uri, **kwargs)
    app.db = db_client.get_default_database()

    app.debug = True
    paste.httpserver.serve(app, port='8080')
