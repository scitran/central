#!/usr/bin/env python
#
# @author:  Kevin S. Hahn

import re
import json
import uuid
import logging
import webapp2

from google.appengine.ext import ndb

import internimsutil as inu

logging.basicConfig(level=logging.INFO)


class Admin(webapp2.RequestHandler):

    """splash page to admin utilities"""

    def get(self):
        self.response.write("""\
                            <html>
                                <title>NIMS - Admin Tools</title>
                                <body>
                                    <div>
                                    <h3>ADMIN PAGE</h3>
                                    <a href='admin/bootstrap'>bootstrap</a><br>
                                    <a href='admin/new'>create new auth host entry</a><br>
                                    placeholder1<br>
                                    </div>
                                </body>
                            </html>
                            """)


class Bootstrap(webapp2.RequestHandler):

    """initial setup - should only need to be run once..."""

    def get(self):
        self.response.write("""\
                            <html>
                                <title>NIMS - Bootstrap</title>
                                <body>
                                    put bootstrapping setup stuff here.<br>
                                    nothing to see here.<br>
                                    move along.<br>
                                    <a href='../admin'>done</a>
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
                                            Preliminary Site ID (a string safe ID will be returned)<br>
                                            <input type="text" name="pre_site_id" size="60" required autofocus><br>
                                            SSL Public Key (RSA)<br>
                                            <textarea name="pubkey" rows="5" cols="43" required></textarea><br>
                                            <input type="submit" value="submit">
                                            <input type="reset" value="reset">
                                            <a href="../admin"><button type="button">cancel</button></a>
                                        </form>
                                    </div>
                                </body>
                            </html>
                            """)


class NewAuthHostConfirm(webapp2.RequestHandler):

    """returns information to be returned to registrant"""

    def post(self):
        pre_site_id = self.request.get('pre_site_id')
        pubkey = self.request.get('pubkey').replace('\r','')
        cleanname = re.sub('[\W_]+', '_', pre_site_id).strip().lower()  # '\W+' = not [a-zA-Z0-9_]
        site_id = cleanname
        counter = 1
        unique = False
        # if iid exists, increment iid until unique
        while not unique:
            exists = inu.AuthHost().query(inu.AuthHost.id == site_id, ancestor=inu.k_AuthHosts).get()
            if exists:
                # if it does exist, add a suffix to the name
                site_id = cleanname + '_' + str(counter)
                counter += 1
            else:
                unique = True

        # query/create - if nothing matches site, then create new
        nah = inu.AuthHost(id=site_id, parent=inu.k_AuthHosts, pubkey=pubkey, active=True)
        nah.put()
        # provide feedback to email to NIMS site admin
        self.response.write("""\
                            <html>
                                <title>NIMS - Registration Confirmation</title>
                                <body>
                                    <div>
                                        <strong>Assigned UUID:</strong><br>
                                        {site_id}<br><br>
                                        <strong>Submitted Info:</strong><br>
                                        pubkey:      {pubkey}<br><br>
                                        <strong>AuthHost Entry:</strong><br>
                                        {nah}<br><br>
                                        <a href='../../admin'><button type="button">back to main</button></a>
                                    </div>
                                </body>
                            </html>
                            """.format(site_id=nah.id, pubkey=nah.pubkey, nah=nah.as_dict()))


### NOT IMPLEMENTENTED - webform to edit existing AuthorizedHost Entities
### should have similar patterning as NewAuthHost and NewAuthHostConfirm
# class UpdateAuthHost(webapp2.RequestHandler):
#     def get(self):
#
#
# class UpdateAuthHostFeedback(webapp2.RequestHandler):
#     def post(self):

app = webapp2.WSGIApplication([(r'/admin', Admin),
                               (r'/admin/bootstrap', Bootstrap),
                               (r'/admin/new', NewAuthHost),
                               (r'/admin/new/confirm', NewAuthHostConfirm),
                              ], debug=True)
