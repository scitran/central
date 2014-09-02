
# @author: Kevin S Hahn

import os
import sys
import site
import ConfigParser

configfile = './production.ini'
config = ConfigParser.ConfigParser()
config.read(configfile)

site.addsitedir(os.path.join(config.get('sdmc', 'virtualenv'), 'lib/python2.7/site-packages'))
sys.path.append(config.get('sdmc', 'here'))
os.environ['PYTHON_EGG_CACHE'] = config.get('sdmc', 'python_egg_cache')
os.umask(0o022)

import pymongo
import logging
import logging.config
logging.config.fileConfig(configfile, disable_existing_loggers=False)

import sdmc

application = sdmc.app

kwargs = dict(tz_aware=True)
db_uri = config.get('sdmc', 'db_uri')
db_client = pymongo.MongoReplicaSetClient(db_uri, **kwargs) if 'replicaSet' in db_uri else pymongo.MongoClient(db_uri, **kwargs)
application.db = db_client.get_default_database()
