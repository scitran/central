#!/usr/bin/env python
#
# @author:  Kevin S. Hahn
# BASICALLY DONE~ maybe add redirects so URLS don't require trailing slashes

import json
import logging
import re
import uuid
import webapp2
from google.appengine.ext import db
from internimsutil import AuthorizedHost, NIMSServer, key_AuthorizedHosts, key_NIMSServers


logging.basicConfig(level=logging.INFO)


class AdminSplash(webapp2.RequestHandler):

    """splash page to admin utilities - menu'ish"""

    def get(self):
        self.response.write("""\
                            <html>
                                <title>NIMS - Admin Tools</title>
                                <body>
                                    <div>
                                    <h3>ADMIN PAGE</h3>
                                    <a href='bootstrap'>bootstrap</a><br>
                                    <a href='new'>create new auth host entry</a><br>
                                    placeholder1<br>
                                    </div>
                                </body>
                            </html>
                            """)
    def post(self):
        self.response.write("""don't do that (no POST'ing)""")


class Bootstrap(webapp2.RequestHandler):

    """initially setup - should only need to be run once..."""

    def get(self):
        self.response.write("""\
                            <html>
                                <title>NIMS - Bootstrap</title>
                                <body>
                                    put bootstrapping setup stuff here.<br>
                                    nothing to see here.<br>
                                    move along.<br>
                                    <a href='../admin/'>done</a>
                                </body>
                            </html>
                            """)

    def _first_time_setup(self):
        pass


class NewAuthHost(webapp2.RequestHandler):

    """html form to submit information for AuthorizedHost entity creation"""

    def get(self):
        self.response.write("""\
                            <html>
                                <title>NIMS - Registration</title>
                                <body>
                                    <div>
                                        <form action="/admin/new/confirm" method="post">
                                            Site ID (common name)<br>
                                            <input type="text" name="commonname" size="60" required autofocus><br>
                                            SSL Public Key (RSA)<br>
                                            <textarea name="pubkey" rows="5" cols="43" required></textarea><br>
                                            <input type="submit" value="submit">
                                            <input type="reset" value="reset">
                                            <a href="../admin/"><button type="button">cancel</button></a>
                                        </form>
                                    </div>
                                </body>
                            </html>
                            """)
    def post(self):
        self.response.write("""stop it! (no POST'ing)""")


class NewAuthHostConfirm(webapp2.RequestHandler):

    """returns information to be sent to registrant, specifically 'uid'"""

    def post(self):
        commonname = self.request.get('commonname')
        pubkey = self.request.get('pubkey').replace('\r','')
        cn_clean = re.compile('[\W_]+').sub('_', commonname).strip().lower()  # '\W+' = not [a-zA-Z0-9_]
        uid = cn_clean
        counter = 1
        unique = False
        # if uid exists, increment uid until unique
        while not unique:
            exists = AuthorizedHost().all().ancestor(key_AuthorizedHosts).filter('uid =', uid).get()
            if exists:
                # if it does exist, add a suffix to the name
                uid = cn_clean + '_' + str(counter)
                counter += 1
            else:
                unique = True

        #query/create - if nothing matches key_name, then create new with keyname
        nah = AuthorizedHost(key_name=uid, parent=key_AuthorizedHosts, uid=uid, commonname=commonname, active=True)
        nah.pubkey = pubkey
        nah.put()
        ## provide feedback to email to NIMS site admin
        self.response.write("""\
                            <html>
                                <title>NIMS - Registration Confirmation</title>
                                <body>
                                    <div>
                                        <strong>Assigned UUID:</strong><br>
                                        {uid}<br><br>
                                        <strong>Submitted Info:</strong><br>
                                        commonname:  {cn}<br>
                                        pubkey:      {pubkey}<br><br>
                                        <strong>Registration Entry:</strong><br>
                                        {nah}<br><br>
                                        <a href='..'><button type="button">back to main</button></a>
                                    </div>
                                </body>
                            </html>
                            """.format(uid=uid, cn=commonname, pubkey=pubkey, nah=nah.as_dict()))


### NOT IMPLEMENTENTED - webform to edit existing AuthorizedHost Entities
### should have similar patterning as NewAuthHost and NewAuthHostConfirm
# class UpdateAuthHost(webapp2.RequestHandler):
#     def get(self):
#
#
# class UpdateAUthHostFeedback(webapp2.RequestHandler):
#     def post(self):

app = webapp2.WSGIApplication([(r'/admin/', AdminSplash),
                               (r'/admin/bootstrap', Bootstrap),
                               (r'/admin/new', NewAuthHost),
                               (r'/admin/new/confirm', NewAuthHostConfirm),
                               # (r'admin/status/', AdminSplash),
                               # (r'/admin/new/feedback', NewAuthHostFeedback)
                              ], debug=True)