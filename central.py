#!/usr/bin/env python
# @author:  Kevin S. Hahn
#           Gunnar Schaefer

"""Scitran Central peer registry."""

import logging
log = logging.getLogger(__name__)
logging.getLogger('requests').setLevel(logging.WARNING)  # silence Requests library logging
logging.getLogger('MARKDOWN').setLevel(logging.WARNING)  # silence Mardkwon library logging

import webapp2
import webapp2_extras.routes

import core
import remotes
import instances

routes = [
    webapp2.Route(r'/api',                                          core.Core),
    webapp2.Route(r'/api/instances',                                instances.Instances),
    webapp2_extras.routes.PathPrefixRoute(r'/api/instances', [
        webapp2.Route(r'/schema',                                   instances.Instance, handler_method='schema', methods=['GET']),
        webapp2.Route(r'/<_id>',                                    instances.Instance, methods=['GET', 'PUT']),
    ]),
    webapp2.Route(r'/api/remotes',                                  remotes.Remotes),
]

app = webapp2.WSGIApplication(routes)


if __name__ == '__main__':
    import pymongo
    import argparse
    import paste.httpserver

    logging.getLogger('paste.httpserver').setLevel(logging.INFO)  # silence paste loggin

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('ssl_cert', help-'scitran central ssl cert, containing key and certificate, in pem format')
    arg_parser.add_argument('--db_uri', help='internims DB URI [mongodb://127.0.0.1/central]', default='mongodb://127.0.0.1/central')
    arg_parser.add_argument('--log_level', help='logging level [info]', default='info')
    args = arg_parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper()))
    log = logging.getLogger('central')

    kwargs = dict(tz_aware=True)
    db_client = pymongo.MongoReplicaSetClient(args.db_uri, **kwargs) if 'replicaSet' in args.db_uri else pymongo.MongoClient(args.db_uri, **kwargs)
    app.db = db_client.get_default_database()
    app.ssl_cert = args.ssl_cert

    app.debug = True
    paste.httpserver.serve(app, port='8080')
