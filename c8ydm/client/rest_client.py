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

import requests
import logging
import json
import datetime
from base64 import b64encode


class RestClient():

    def __init__(self, agent):
        self.logger = logging.getLogger(__name__)
        self.serial = agent.serial
        self.configuration = agent.configuration
        self.base_url = agent.url
        if not self.base_url.startswith('http'):
            self.base_url = f'https://{self.base_url}'
        self.token = agent.token

    def get_auth_header(self):
        if self.token:
            return {'Authorization': 'Bearer '+self.token}
        else:
            credentials = self.configuration.getCredentials()
            self.tenant = credentials[0]
            self.user = credentials[1]
            self.password = credentials[2]
            auth_string = f'{self.tenant}/{self.user}:{self.password}'
            encoded_auth_string = b64encode(
                bytes(auth_string, 'utf-8')).decode('ascii')
            return {'Authorization': 'Basic '+encoded_auth_string, }

    def update_managed_object(self, internal_id, payload):
        #self.logger.info('Update of managed Object')
        try:
            url = f'{self.base_url}/inventory/managedObjects/{internal_id}'
            headers = self.get_auth_header()
            headers['Content-Type'] = 'application/json'
            self.logger.debug(f'Sending Request to url {url}')
            response = requests.request(
                "PUT", url, headers=headers, data=payload)
            self.logger.debug('Response from request: ' + str(response.text))
            self.logger.debug(
                'Response from request with code : ' + str(response.status_code))
            if response.status_code == 200 or response.status_code == 201:
                #self.logger.info('Managed object updated in C8Y')
                return True
            else:
                self.logger.warning('Managed object not updated in C8Y')
                return False
        except Exception as e:
            self.logger.error('The following error occured: %s' % (str(e)))

    def get_internal_id(self, external_id):
        try:
            #self.logger.info('Checking against indentity service what is internalID in C8Y')
            url = f'{self.base_url}/identity/externalIds/c8y_Serial/{external_id}'
            self.logger.debug(f'Sending Request to url {url}')
            headers = self.get_auth_header()
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
            response = requests.request("GET", url, headers=headers)
            self.logger.debug('Response from request: ' + str(response.text))
            self.logger.debug(
                'Response from request with code : ' + str(response.status_code))
            if response.status_code == 200:
                #self.logger.info('Managed object exists in C8Y')
                json_data = json.loads(response.text)
                internalID = json_data['managedObject']['id']
                #self.logger.info("The internalID for " + str(external_id) + " is " + str(internalID))
                self.logger.debug('Returning the internalID')
                return internalID
            else:
                self.logger.warning(
                    'Response from request: ' + str(response.text))
                self.logger.warning('Got response with status_code: ' +
                                    str(response.status_code))
                return None
        except Exception as e:
            self.logger.error('The following error occured: %s' % (str(e)))
            return None

    def upload_binary_logfile(self, internal_id, payload, file):
        #self.logger.info('Update of managed Object')
        try:
            url = f'{self.base_url}/inventory/binaries'
            headers = self.get_auth_header()
            headers['Content-Type'] = 'multipart/form-data'
            headers['Accept'] = 'application/json'
            self.logger.debug(f'Sending Request to url {url}')
            response = requests.request(
                "POST", url, headers=headers, data=payload, files=file)
            print("Responsestatuscode:" + str(response.status_code))
            print("RESPONSEMSG: "+str(response.text))
            self.logger.debug(
                'Response from request: ' + str(response.text))
            self.logger.debug(
                'Response from request with code : ' + str(response.status_code))
            if response.status_code == 200 or response.status_code == 201:
                json_data = json.loads(response.text)
                binaryurl = json_data["self"]
                # print(binaryurl)
                # return binaryurl
                return binaryurl
            else:
                self.logger.warning('Binary upload failed in C8Y')
                return False
        except Exception as e:
            self.logger.error('The following error occured: %s' % (str(e)))

            
    def create_logfile_event(self, mo_id):
        try:
            url = f'{self.base_url}/event/events'
            headers = self.get_auth_header()
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
            payload = {
                "time" : datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "type" : "c8y_LogfileRequest",
                "text" : "LogFile Request Event",
                "source": { "id" : mo_id}
            }
            self.logger.debug(f'Sending Request to url {url}')
            response = requests.request(
                "POST", url, headers=headers, data=json.dumps(payload))
            self.logger.debug(
                'Response from request: ' + str(response.text))
            self.logger.debug(
                'Response from request with code : ' + str(response.status_code))
            if response.status_code == 200 or response.status_code == 201:
                json_data = json.loads(response.text)
                event_id = json_data["id"]
                # print(binaryurl)
                # return binaryurl
                return event_id
            else:
                self.logger.warning('Creating LogFileEvent failed!')
                return None
        except Exception as ex:
            self.logger.error('The following error occured: %s' % (str(ex)))
            return None
  
    def create_event(self, mo_id,type,text, content , file):
        try:
            url = f'{self.base_url}/event/events'
            headers = self.get_auth_header()
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
            payload = {
                "time" : datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "type" : type,
                "text" : text,
                "source": { "id" : mo_id},
                type : json.loads(content)
            }
            self.logger.debug(f'Sending Request to url {url}')
            response = requests.request(
                "POST", url, headers=headers, data=json.dumps(payload), files=file)
            self.logger.debug(
                'Response from request: ' + str(response.text))
            self.logger.debug(
                'Response from request with code : ' + str(response.status_code))
            if response.status_code == 200 or response.status_code == 201:
                json_data = json.loads(response.text)
                event_id = json_data["id"]
                # print(binaryurl)
                # return binaryurl
                return event_id
            else:
                self.logger.warning('Creating LogFileEvent failed!')
                return None
        except Exception as ex:
            self.logger.error('The following error occured: %s' % (str(ex)))
            return None

    def create_alarm(self, mo_id,type,text, severity,  status, content,action  ):
        try:

            url = f'{self.base_url}/alarm/alarms'
            headers = self.get_auth_header()
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
            type_payload = ''
            try:
                type_payload : json.loads(content)
            except:
                self.logger.warning('Create alarm parsing additional payload failed')
                
            payload = {
                "time" : datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "type" : type,
                "text" : text,
                "severity" : severity,
                "status" : status,
                type: type_payload,
                "source": { "id" : mo_id}
                
            }
            self.logger.debug(f'Sending Request to url {url}')
            response = requests.request(
                action, url, headers=headers, data=json.dumps(payload))
            self.logger.debug(
                'Response from request: ' + str(response.text))
            self.logger.debug(
                'Response from request with code : ' + str(response.status_code))
            if response.status_code == 200 or response.status_code == 201:
                json_data = json.loads(response.text)
                event_id = json_data["id"]
                # print(binaryurl)
                # return binaryurl
                return event_id
            else:
                self.logger.warning('Creating Alarm failed!')
                return None
        except Exception as ex:
            self.logger.error('The following error occured: %s' % (str(ex)))
            return None

    def upload_event_logfile(self, mo_id, payload, file):
        #self.logger.info('Update of managed Object')
        try:
            event_id = self.create_logfile_event(mo_id)
            if not event_id:
                return None
            url = f'{self.base_url}/event/events/{event_id}/binaries'
            headers = self.get_auth_header()
            headers['Content-Type'] = 'multipart/form-data'
            headers['Accept'] = 'application/json'
            self.logger.debug(f'Sending Request to url {url}')
            response = requests.request(
                "POST", url, headers=headers, data=payload, files=file)
            self.logger.debug('Response from request: ' + str(response.text))
            self.logger.debug(
                'Response from request with code : ' + str(response.status_code))
            if response.status_code == 200 or response.status_code == 201:
                json_data = json.loads(response.text)
                binaryurl = json_data["self"]
                # print(binaryurl)
                # return binaryurl
                return binaryurl
            else:
                self.logger.warning('Binary upload failed in C8Y')
                return None
        except Exception as e:
            self.logger.error('The following error occured: %s' % (str(e)))

    def get_all_dangling_operations(self, internal_id):
        try:
            url = f'{self.base_url}/devicecontrol/operations?status=EXECUTING&deviceId={internal_id}'
            headers = self.get_auth_header()
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
            response = requests.request("GET", url, headers=headers)
            self.logger.debug('Response from request: ' + str(response.text))
            self.logger.debug(
                'Response from request with code : ' + str(response.status_code))
            if response.status_code == 200:
                json_data = json.loads(response.text)
                #operations = []
                operations = json_data['operations']
                #self.logger.info("The internalID for " + str(external_id) + " is " + str(internalID))
                self.logger.debug(
                    f'Returning Operations with status EXECUTING {operations}')
                return operations
            else:
                self.logger.warning(
                    'Response from request: ' + str(response.text))
                self.logger.warning('Got response with status_code: ' +
                                    str(response.status_code))
                return None
        except Exception as e:
            self.logger.error('The following error occured: %s' % (str(e)))

    def set_operations_to_failed(self, operations):
        if len(operations) > 0:
            try:
                for op in operations:
                    url = f'{self.base_url}/devicecontrol/operations/{op["id"]}'
                    headers = self.get_auth_header()
                    headers['Content-Type'] = 'application/json'
                    headers['Accept'] = 'application/json'
                    payload = {
                        "status": "FAILED",
                        "failureReason": "Operation unexpectedly interrupted. Check logs for details"
                    }
                    response = requests.request(
                        "PUT", url, headers=headers, data=json.dumps(payload))
                    self.logger.debug(
                        'Response from request: ' + str(response.text))
                    self.logger.debug(
                        'Response from request with code : ' + str(response.status_code))
                    if response.status_code == 200:
                        return True
                    else:
                        return False
            except Exception as e:
                self.logger.error('The following error occured: %s' % (str(e)))

    def create_SmartRest_template(self,template,template_id):
        try:
            url = f'{self.base_url}/inventory/managedObjects'
            self.logger.debug(f'Sending Request to url {url}')
            payload = json.loads(template)
            headers = self.get_auth_header()
            headers['Content-Type'] ='application/json'
            headers['Accept'] = 'application/json'
            response = requests.request("POST", url, headers=headers, data = json.dumps(payload))
            if response.status_code == 200 or response.status_code==201:
                json_data = json.loads(response.text)
                self.logger.info(f'Template created with id {json_data["id"]}')
                payload = json.loads(f'{{"externalId": "{template_id}","type": "c8y_SmartRest2DeviceIdentifier"}}')
                url = f'{self.base_url}/identity/globalIds/{json_data["id"]}/externalIds'
                self.logger.debug(f'Sending Request for idenenity of smart rest template to url {url}')
                response = requests.request("POST", url, headers=headers, data = json.dumps(payload))
                if response.status_code == 200 or response.status_code==201:
                    self.logger.debug('Response from request of identity API for smart rest template: ' + str(response.text))
                    return True
                else:
                    self.logger.warning('Response from request: ' + str(response.text))
                    self.logger.warning('Got response with status_code: ' +
                            str(response.status_code))
                    return False
            else:
                self.logger.warning('Response from request: ' + str(response.text))
                self.logger.warning('Got response with status_code: ' +
                            str(response.status_code))
                return False
        except Exception as e:
            self.logger.error('The following error occured while trying to create SmartRest template: %s' % (str(e)))    

    def check_SmartRest_template_exists(self,templateID):
        try:
            url = f'{self.base_url}/identity/externalIds/c8y_SmartRest2DeviceIdentifier/{templateID}'
            self.logger.debug(f'Sending Request to url {url}')
            headers = self.get_auth_header()
            headers['Content-Type'] ='application/json'
            headers['Accept'] = 'application/json'
            response = requests.request("GET", url, headers=headers)
            self.logger.info('Checking against indentity service')
            if response.status_code == 200:
                self.logger.info('Managed object exists in C8Y')
                self.logger.debug('Returning the internalID')
                json_data = json.loads(response.text)
                return True
            else:
                self.logger.warning('Response from request: ' + str(response.text))
                self.logger.warning('Got response with status_code: ' + str(response.status_code))
                return False
        except Exception as e:
            self.logger.error('The following error occured while trying to check for existing SmartRest templates: %s' % (str(e)))
            return False

    def create_child_device(self, parent_mo_id,external_id,name,type   ):

        try:
            child_id = None
            url = f'{self.base_url}/inventory/managedObjects'
            headers = self.get_auth_header()
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
                
            payload = {
                "time" : datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "c8y_IsDevice": {},
                "type": type,
                "name": name
            }

            self.logger.info(f'Sending Request to url {url}')
            response = requests.request(
                'POST', url, headers=headers, data=json.dumps(payload))
            self.logger.debug(
                'Response from request: ' + str(response.text))
            self.logger.debug(
                'Response from request with code : ' + str(response.status_code))

            if response.status_code == 200 or response.status_code == 201:
                json_data = json.loads(response.text)
                child_id = json_data["id"]
                payload_external_id = {
                        "externalId": external_id,
                        "type": "c8y_Serial"
                    }
                url = f'{self.base_url}/identity/globalIds/{child_id}/externalIds'
                self.logger.info(f'Sending Request to url {url}')
                response = requests.request(
                    'POST', url, headers=headers, data=json.dumps(payload_external_id))
                self.logger.info(
                    'Response from request with code : ' + str(response.status_code))
                    
                if response.status_code == 200 or response.status_code == 201:
                    payload_child = {
                        "managedObject": {
                        "id": child_id
                        }
                    }
                    url = f'{self.base_url}/inventory/managedObjects/{parent_mo_id}/childDevices'
                    self.logger.info(f'Sending Request to url {url}')
                    response = requests.request(
                        'POST', url, headers=headers, data=json.dumps(payload_child))
                    self.logger.info(
                        'Response from request with code : ' + str(response.status_code))
                    return child_id
                else:
                    self.logger.error('Creating Child Device failed!')
                    return None
            else:
                self.logger.error('Creating Child Device failed!')
                return None
        except Exception as ex:
            self.logger.error('Creating Child The following error occured: %s' % (str(ex)))
            return None
        
