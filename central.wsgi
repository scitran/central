# @author:  Kevin S Hahn
#           Gunnar Schaefer

import os
import logging
import pymongo
import argparse

os.environ['PYTHON_EGG_CACHE'] = '/tmp/python_egg_cache'
os.umask(0o022)

ap = argparse.ArgumentParser()
ap.add_argument('ssl_cert', help='scitran central ssl cert, containing key and certificate, in pem format')  # provide as pyargv to uwsgi
ap.add_argument('--db_uri', help='mongodb uri [mongodb://127.0.0.1/central]', default='mongodb://127.0.0.1/central')
ap.add_argument('--log_level', help='logging level [info]', default='info')
args = ap.parse_args()

logging.basicConfig(level=getattr(logging, args.log_level.upper()))
log = logging.getLogger('central')

import central
application = central.app

kwargs = dict(tz_aware=True)
db_client = pymongo.MongoReplicaSetClient(args.db_uri, **kwargs) if 'replicaSet' in args.db_uri else pymongo.MongoClient(args.db_uri, **kwargs)
application.db = db_client.get_default_database()
application.ssl_cert = args.ssl_cert
