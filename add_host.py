#!/usr/bin/env python
"""Utility script to add a new authorized host."""


import logging
import pymongo
import argparse
import datetime
import ConfigParser
import logging.config

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('--configfile', help='path to configuration file', default='./production.ini')
arg_parser.add_argument('hostname', help='hostname to be added to authd instances')
arg_parser.add_argument('--db_uri', help='DB uri')
args = arg_parser.parse_args()

config = ConfigParser.ConfigParser()
config.read(args.configfile)
logging.config.fileConfig(args.configfile, disable_existing_loggers=False)

log = logging.getLogger('sdmc')

kwargs = dict(tz_aware=True)
db_uri = args.db_uri or config.get('sdmc', 'db_uri')
db_client = pymongo.MongoReplicaSetClient(db_uri, **kwargs) if 'replicaSet' in db_uri else pymongo.MongoClient(db_uri, **kwargs)
db = db_client.get_default_database()

# is there already a host entry for this hostname?
if not db.instances.find_one({'_id': args.hostname}):
    db.instances.insert({'_id': args.hostname, 'date_added': datetime.datetime.now()})
    log.info('entry created for host %s' % args.hostname)
else:
    log.info('entry already exists for host %s' % args.hostname)
