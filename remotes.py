# @author:  Kevin S Hahn
#           Gunnar Schaefer

import copy
import json
import webapp2
import datetime
import bson.json_util


def _dict_merge(a, b):
    result = copy.deepcopy(a)
    for k, v in b.iteritems():
        if k in result and isinstance(result[k], dict):
            result[k] = _dict_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


class Remotes(webapp2.RequestHandler):

    """API route: /api/remotes"""

    # TODO: this currently only shows results that have remote users
    # probably want this to return EVERY host, as status overview.
    # not for checking if a host is permitted or not.
    def get(self):
        """Return info about all instances."""
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
        self.response.write(json.dumps(result, default=bson.json_util.default))
