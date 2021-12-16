"""  
Copyright (c) 2021 Software AG, Darmstadt, Germany and/or its licensors

SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

'''


'''
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import logging
import cgi
from urllib.parse import urlparse
from c8ydm.framework.modulebase import Driver

class HTTPServerRequestHandler(BaseHTTPRequestHandler):
    logger = logging.getLogger(__name__)
    def set_agent(self, agent):
        self.agent=agent


    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        html = '''
                <!doctype html>
                <title>Upload Payload</title>
                <h1>Upload Payload</h1>
                <form method=post enctype=multipart/form-data>
                <input type=file name=file>
                </br>
                <p>payload</p>
                <input type=text name=payload>
                <input type=submit value=Upload>
                </form>
                '''
        
        self.wfile.write(html.encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        form = cgi.FieldStorage(fp=self.rfile,headers=self.headers,environ={
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': self.headers['Content-Type'],
        })
    #    logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
    #            str(self.path), str(self.headers), post_data.decode('utf-8'))
        self.logger.info(str(form.keys()))
        mo_id = self.agent.rest_client.get_internal_id(self.agent.serial)
        self.agent.rest_client.create_event( mo_id,'c8y_dac', 'DAC Event', post_data.decode('utf-8') )
        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

        

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def makehandlerclassfordb(agent):
    class CustomHandler(HTTPServerRequestHandler, object):
        def __init__(self, *args, **kwargs):
            self.agent = agent
            super(CustomHandler, self).__init__(*args, **kwargs)
    return CustomHandler



class HttpReceiver(Driver):

    logger = logging.getLogger(__name__)
    http_server = None

    def start(self):
        self.handler= makehandlerclassfordb(self.agent)
        self.port = int(self.agent.configuration.getValue('http_receiver', 'port'))
        self.ip = self.agent.configuration.getValue('http_receiver', 'ip')
        self.http_server = HTTPServer((self.ip, self.port), self.handler)
        self.logger.info('Starting http_server on: ' + self.ip+ ':' +str(self.port) )
        try:
            self.http_server.serve_forever()
        except Exception as e:
            self.logger.exception(e)

    def stop(self):
        self.http_server.server_close()
        self.logger.info('Stoping http_server'  )
