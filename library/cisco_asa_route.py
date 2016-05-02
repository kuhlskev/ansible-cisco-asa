#!/usr/bin/python

# Copyright 2015 Patrick Ogenstad <patrick@ogenstad.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

DOCUMENTATION = '''
---

module: cisco_asa_network_objectgroup
author: Kevin Kuhls
version: 1.0
short_description: Creates deletes or edits routes.
description:
    - Configures static routes on ASA via ASA API
requirements:
options:
    category:
        description:
            - The type of object you are creating. Use slash notation for networks, i.e. 192.168.0.0/24. Use - for ranges, i.e. 192.168.0.1-192.168.0.10. 
        choices: [ 'ipv4_address', 'ipv6_address', 'ipv4_subnet', 'ipv6_subnet', 'ipv4_range', 'ipv6_range', 'ipv4_fqdn', 'ipv6_fqdn', 'object', 'object_group' ]
        required: false
    description:
        description:
            - Description of the object
        required: false
    entry_state:
        description:
            - State of the entire object-group
        choices: [ 'present', 'absent' ]
        required: false
    host:
        description:
            - Typically set to {{ inventory_hostname }}
        required: true
    name:
        description:
            - Name of the network object
        required: true
    password:
        description:
            - Password for the device
        required: true
    state:
        description:
            - State of the entire object-group
        choices: [ 'present', 'absent' ]
        required: true
    username:
        description:
            - Username for device
        required: true
    validate_certs:
        description:
            - If no, SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
        choices: [ 'no', 'yes']
        default: 'yes'
        required: false
    value:
        description:
            - The data to enter into the network object
        required: false

'''

EXAMPLES = '''

# Create a network object for a web server
- cisco_asa_network_object:
    host={{ inventory_hostname }}
    username=api_user
    password=APIpass123
    name=tsrv-web-1
    state=present
    category=IPv4Address
    description='Test web server'
    value='10.12.30.10'
    validate_certs=no

# Remove test webserver
- cisco_asa_network_object:
    host={{ inventory_hostname }}
    username=api_user
    password=APIpass123
    name=tsrv-web-2
    state=absent
    validate_certs=no
'''
import json

import sys
from ansible.module_utils.basic import *
from collections import defaultdict
import requests
from requests.auth import HTTPBasicAuth
requests.packages.urllib3.disable_warnings()

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
}

class ASA(object):

    def __init__(self, device=None, username=None, password=None, verify_cert=False, timeout=30):
        
        self.device = device
        self.username = username
        self.password = password
        self.verify_cert = verify_cert
        self.timeout = timeout
        self.cred = HTTPBasicAuth(self.username, self.password)

    ######################################################################
    # General Functions
    ######################################################################
    def _delete(self, request):
        url = 'https://' + self.device + '/api/' + request
        data = requests.delete(url,headers=HEADERS,auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        return data

    def _get(self, request):
        url = 'https://' + self.device + '/api/' + request
        data = requests.get(url,headers=HEADERS,auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        return data

    def _patch(self, request, data):
        url = 'https://' + self.device + '/api/' + request
        data = requests.patch(url, data=json.dumps(data), headers=HEADERS, auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        return data

    def _post(self, request, data=False):
        url = 'https://' + self.device + '/api/' + request
        if data != False:
            data = requests.post(url, data=json.dumps(data), headers=HEADERS, auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        else:
            data = requests.post(url, headers=HEADERS, auth=self.cred, verify=self.verify_cert, timeout=self.timeout)            
        return data

    def _put(self, request, data):
        url = 'https://' + self.device + '/api/' + request
        data = requests.put(url, data=json.dumps(data), headers=HEADERS, auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        return data

    ######################################################################
    # Functions related to network object-groups, or
    # "object-group network" in the ASA configuration
    ######################################################################

    def create_route(self, data):
        request = 'routing/static'
        return self._post(request, data)

    def delete_route(self, net_object):
        request = 'routing/static/' + net_object
        return self._delete(request)

    def get_routes(self):
        request = 'routing/static'
        return self._get(request)


def add_route(dev, module, member_data):
    try:
        result = dev.create_route(member_data)
    except:
        err = sys.exc_info()[0]
        module.fail_json(msg='Unable to connect to device: %s' % err)

    if result.status_code != 201:
        module.fail_json(msg='Unable to add object - %s' % result.status_code)

    return True


def delete_route(dev, module, current_data, desired_data):
    for member in current_data['items']:
        if member['interface']['name'] == desired_data['interface']['name'] and member['gateway'] == desired_data['gateway'] and member['network'] == desired_data['network']:
            objectId = member['objectId']
    try:
        result = dev.delete_route(objectId)
    except:
        err = sys.exc_info()[0]
        module.fail_json(msg='Unable to connect to device: %s' % err)

    if result.status_code == 204:
        return_status = True
    else:
        module.fail_json(msg='Unable to delete object - %s' % result.status_code)

    return return_status

def find_member(current_data, desired_data, module):

    member_exists = False
    for member in current_data['items']:
        if member['interface']['name'] == desired_data['interface']['name'] and member['gateway'] == desired_data['gateway'] and member['network'] == desired_data['network']:
            member_exists = True

    return member_exists

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            username=dict(required=True),
            password=dict(required=True),
            next_hop=dict(required=True),
            interface=dict(required=True),
            network=dict(required=True),  
            description=dict(required=False),
            state=dict(required=True, choices=['absent', 'present']),
            validate_certs=dict(required=False, type='bool', default=False),

            ),
        supports_check_mode=False)

    m_args = module.params
    value = m_args['network']
    dev = ASA(
        device=m_args['host'],
        username=m_args['username'],
        password=m_args['password'],
        verify_cert=m_args['validate_certs']
    )
    changed = False
    if '/32' in value:
        value = value.split('/')[0]  #API rejects /32 network objects, must convert to host
        network_kind = 'IPv4Address'
    else:
        network_kind = 'IPv4Network' 
    desired_data = {}
    desired_data = { 
      "kind": "object#IPv4Route",
      "distanceMetric": 1,
      "gateway": {
        "kind": "IPv4Address",
        "value": m_args['next_hop']
      },
      "network": {
        "kind": network_kind,
        "value": value
      },
      "interface": {
        "kind": "objectRef#Interface",
        "name": m_args['interface']
      } }
    try:
        data = dev.get_routes()
    except:
        err = sys.exc_info()[0]
        module.fail_json(msg='Unable to connect to device: %s' % err)
    #module.fail_json(msg='yo %s' % desired_data)
    if data.status_code == 200:
        found = find_member(data.json(), desired_data, module)
        #module.fail_json(msg="test %s %s %s" % (found, desired_data, data.json()))
        if found and m_args['state'] == 'present':
            changed_status = False
        elif found and m_args['state'] == 'absent':
            changed_status = delete_route(dev, module, data.json(), desired_data)    
        elif m_args['state'] == 'present':
            changed_status = add_route(dev, module, desired_data)    
        elif m_args['state'] == 'absent':
            changed_status = False                    
        else:
           #Remove after members are implemented
           module.fail_json(msg='Unknown error check arguments') 
    elif data.status_code == 401:
        module.fail_json(msg='Authentication error')    
    elif data.status_code == 404:
        if m_args['state'] == 'absent':
            changed_status = False
        elif m_args['state'] == 'present':
            changed_status = add_route(dev, module, desired_data)
    else:
        module.fail_json(msg="Unsupported return code %s" % data.status_code)
    if changed == False:
        changed = changed_status
    return_msg = {}
    return_msg['changed'] = changed

    module.exit_json(**return_msg)


main()

