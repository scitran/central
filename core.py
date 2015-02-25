# @author:  Kevin S Hahn
#           Gunnar Schaefer

import webapp2
import markdown

class Core(webapp2.RequestHandler):

    def get(self):
        """Return API documentation"""
        resources = """Resource                             | Description
            :-----------------------------------------------|:-----------
            api/registration                                | none
            api/registration/checkid                        | check if id is available
            api/instances                                   | list of instances
            api/instances/schema                            | schema
            api/instances/<site_id>                         | defailts for site *<site_id>*
            api/remotes                                     | details for sites that are sharing data
            """
        self.response.headers['Content-Type'] = 'text/html; charset=utf-8'
        self.response.write('<html>\n')
        self.response.write('<head>\n')
        self.response.write('<title>SciTran Central API</title>\n')
        self.response.write('<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">\n')
        self.response.write('<style type="text/css">\n')
        self.response.write('table {width:0%; border-width:1px; padding: 0;border-collapse: collapse;}\n')
        self.response.write('table tr {border-top: 1px solid #b8b8b8; background-color: white; margin: 0; padding: 0;}\n')
        self.response.write('table tr:nth-child(2n) {background-color: #f8f8f8;}\n')
        self.response.write('table thead tr :last-child {width:100%;}\n')
        self.response.write('table tr th {font-weight: bold; border: 1px solid #b8b8b8; background-color: #cdcdcd; margin: 0; padding: 6px 13px;}\n')
        self.response.write('table tr th {font-weight: bold; border: 1px solid #b8b8b8; background-color: #cdcdcd; margin: 0; padding: 6px 13px;}\n')
        self.response.write('table tr td {border: 1px solid #b8b8b8; margin: 0; padding: 6px 13px;}\n')
        self.response.write('table tr th :first-child, table tr td :first-child {margin-top: 0;}\n')
        self.response.write('table tr th :last-child, table tr td :last-child {margin-bottom: 0;}\n')
        self.response.write('</style>\n')
        self.response.write('</head>\n')
        self.response.write('<body style="min-width:900px">\n')
        self.response.write(markdown.markdown(resources, ['extra']))
        self.response.write('</body>\n')
        self.response.write('</html>\n')
