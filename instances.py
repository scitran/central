# @author:  Kevin S Hahn
#           Gunnar Schaefer

import logging
log = logging.getLogger('scitran.central')

import json
import webapp2
import datetime
import urlparse
import requests
import jsonschema
import bson.json_util


class Instances(webapp2.RequestHandler):

    """API route: /api/instances"""

    def get(self):
        """Return info about all instances."""
        sites = list(self.app.db.instances.find())
        result = {
            'sites': sites,
            'num_sites': len(sites),
        }
        self.response.write(json.dumps(result, default=bson.json_util.default))

    def post(self):
        """Create a new instance."""
        self.abort(500, 'POST /instances not implemented')

class Instance(webapp2.RequestHandler):

    """API route: /api/instances/<_id>"""

    # payload = {
    #     'name': nickname,
    #     'api_uri': domain.example.org/api,
    #     'users': [
    #         {'user': 'user1', 'site': 'domain.example.org'},
    #         {'user': 'user2', 'site': 'other.demo.org'},
    #     ],
    # }
    json_schema = {
        '$schema': 'http://json-schema.org/draft-04/schema#',
        'title': 'Instance',
        'type': 'object',
        'properties': {
            'name': {
                'title': 'Name',
                'type': 'string',
            },
            'api_uri': {
                'title': 'Api_uri',
                'type': 'string',
            },
            'users': {
                'title': 'Users',
                'type': 'array',
                'items': {
                    'title': 'Remote Users',
                    'type': 'object',
                    'properties': {
                        'user': {
                            'title': 'User Name',
                            'type': 'string',
                        },
                        'site': {
                            'title': 'User Site',
                            'type': 'string',
                        },
                    },
                    'required': ['user', 'site'],
                    'additionalProperties': False,
                },
            },
        },
        'required': ['name', 'api_uri', 'users'],
        'additionalProperties': False,
    }

    def get(self, _id):
        """Return info about one instance."""
        instance = self.app.db.instances.find_one({'_id': _id})
        if not instance:
            self.abort(404)
        self.response.write(json.dumps(instance, default=bson.json_util.default))

    def put(self, _id):
        """Update peer registry using PUT data from approved reachable hosts."""
        # does hostname match rep
        remote_hostname, aliases, addr = requests.utils.socket.gethostbyaddr(self.request.environ.get('REMOTE_ADDR'))
        if self.request.environ['SSL_CLIENT_VERIFY'] != 'SUCCESS':
            log.debug('%s sent request without SSL client certificate' % remote_hostname)
            self.abort(401, 'No required SSL certificate was sent.')  # auth required

        # is payload valid
        try:
            payload = json.loads(self.request.body, object_hook=bson.json_util.object_hook)
            jsonschema.validate(payload, self.json_schema)
        except (ValueError, jsonschema.ValidationError) as e:
            log.debug(str(e))
            self.abort(400, str(e))
        api_uri = payload.get('api_uri')

        # is host authorized?
        payload['last_seen'] = datetime.datetime.now()
        if not self.app.db.instances.update({'_id': _id}, {'$set': payload}, multi=False)['updatedExisting']:
            log.debug('host %s is not authorized' % _id)
            self.abort(403, 'host %s is not authorized' % _id)

        # does reverse lookup hostname match api_url
        if not urlparse.urlparse(api_uri).hostname.endswith(remote_hostname.lower()):
            # check if the reported api_uri and remote_addr hostname resolve to the same underlying IP
            if addr[0] != requests.utils.socket.gethostbyname(urlparse.urlparse(api_uri).hostname):
                log.debug('reverse lookup does not match api %s.' % api_uri)
                self.abort(403, 'reverse lookup does not match api %s.' % api_uri)

        # is host reachable
        try:
            r = requests.head(api_uri, timeout=3, cert=self.app.ssl_cert)
        except requests.packages.urllib3.exceptions.ProtocolError:
            log.debug('could not connect to %s. Name or Service not known.' % api_uri)
            self.abort(500, 'could not connect to %s. Name or Service not known.' % api_uri)  # XXX error code?
        except requests.exceptions.Timeout:
            log.debug('connection to %s timed out.' % api_uri)
            self.abort(500, 'connection to %s timed out.' % api_uri)  # XXX error code
        except requests.exceptions.ConnectionError:
            log.debug('connection error while connecting to %s' % api_uri)
            self.abort(500, 'connection error while connecting to %s' % api_uri)
        else:
            if r.status_code != 200:
                log.debug('head request to %s failed.' % api_uri)
                self.abort(500, 'head request to %s failed.' % api_uri)  # XXX error code

        # success
        log.info('updated host %s (%s).' % (_id, api_uri))

        # prepare site-specific response
        users_with_remotes = {}
        sites_with_users = self.app.db.instances.aggregate([
                {'$match': {'users.site': _id}},
                {'$unwind': '$users'},
                {'$match': {'users.site': _id}},
        ])['result']
        for site in sites_with_users:
            users_with_remotes.setdefault(site['users']['user'], []).append({'_id': site['_id'], 'name': site['name']})

        active_sites = self.app.db.instances.find(
                {'last_seen': {'$gt': datetime.datetime.now() - datetime.timedelta(minutes=2)}},
                {'users': 0, 'last_seen': 0, 'date_added': 0},
        )
        self.response.write(json.dumps({'sites': list(active_sites), 'users': users_with_remotes}, default=bson.json_util.default))

    def schema(self):
        self.response.write(json.dumps(self.json_schema, default=bson.json_util.default))
