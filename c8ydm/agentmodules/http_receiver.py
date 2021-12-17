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
from cgi import parse_header, parse_multipart
from urllib.parse import parse_qs, urlparse
from c8ydm.framework.modulebase import Driver

class HTTPServerRequestHandler(BaseHTTPRequestHandler):
    logger = logging.getLogger(__name__)

    def set_agent(self,agent):
        self.agent= agent
        self.default_event_type= self.agent.configuration.getValue('http_receiver', 'default.event.type')
        self.default_event_text= self.agent.configuration.getValue('http_receiver', 'default.event.text')

    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        if self.path.startswith('/event'):

            self._set_response()
            html = '''
                    <!doctype html>
                    <title>Upload Payload</title>
                    <h1>Upload Json Payload</h1>
                    <form method=post enctype=multipart/form-data>
                    <input type=file name=file>
                    </br>
                    <p>Event Text</p>
                    <input type=text name=text>
                
                    </br>
                    <input type=submit value=Upload>
                    </form>
                    '''
        
            self.wfile.write(html.encode('utf-8'))

    def do_POST(self):

        if self.path.startswith('/event'):
            self.create_event()

           
        
    def create_event(self):
        try:
            text = self.default_event_text
            type = self.default_event_type
            mo_id = self.agent.rest_client.get_internal_id(self.agent.serial)
            content_length = int(self.headers['Content-Length']) 
            post_data=bytearray()
            url_last = self.path.rsplit('/', 1)[-1]
            if url_last != 'event' and url_last != '':
                type = url_last
            ctype, pdict = parse_header(self.headers['content-type'])
            if ctype == 'multipart/form-data':
                pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
                postvars = parse_multipart(self.rfile, pdict)
                text= postvars['text'][0]
                file = postvars['file'][0]
                self.agent.rest_client.create_event( mo_id,type, text, file.decode('utf-8') ,None)
            if ctype == 'application/json':
                post_data = self.rfile.read(content_length) # <--- Gets the data itself
                self.agent.rest_client.create_event( mo_id,type, text,post_data.decode('utf-8'),None)
            self._set_response()
            self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))
        except Exception as e:
           self.logger.exception(e)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def makehandlerclassfordb(agent):
    class CustomHandler(HTTPServerRequestHandler, object):
        def __init__(self, *args, **kwargs):
            self.set_agent( agent )
            super(CustomHandler, self).__init__(*args, **kwargs)
    return CustomHandler



class HttpReceiver(Driver):

    logger = logging.getLogger(__name__)
    http_server = None

    def start(self):
        self.handler= makehandlerclassfordb(self.agent)
        self.port = int(self.agent.configuration.getValue('http_receiver', 'port'))
        self.ip = self.agent.configuration.getValue('http_receiver', 'ip')
        self.http_server = ThreadedHTTPServer((self.ip, self.port), self.handler)
        self.logger.info('Starting http_server on: ' + self.ip+ ':' +str(self.port) )
        try:
            self.http_server.serve_forever()
        except Exception as e:
            self.logger.exception(e)

    def stop(self):
        self.http_server.server_close()
        self.logger.info('Stoping http_server'  )
