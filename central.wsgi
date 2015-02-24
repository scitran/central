
# @author: Kevin S Hahn

import os
import pymongo
import argparse

import logging
logging.basicConfig()
log = logging.getLogger('central')

os.environ['PYTHON_EGG_CACHE'] = '/tmp/python_egg_cache'
os.umask(0o022)

ap = argparse.ArgumentParser()
ap.add_argument('--db_uri', help='mongodb uri [mongodb://127.0.0.1/central]', default='mongodb://127.0.0.1/central')
ap.add_argument('--log_level', help='logging level [info]', default='info')
args = ap.parse_args()

log.setLevel(getattr(logging, args.log_level.upper()))

import central
application = central.app

kwargs = dict(tz_aware=True)
db_client = pymongo.MongoReplicaSetClient(args.db_uri, **kwargs) if 'replicaSet' in args.db_uri else pymongo.MongoClient(args.db_uri, **kwargs)
application.db = db_client.get_default_database()
