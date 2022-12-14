#!/usr/bin/python
# -*- coding: utf-8 -*-


import json
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.urls import fetch_url, ConnectionError, SSLValidationError
from requests.packages import urllib3
from typing import Literal

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VCDA_LOGIN_TYPES = ['appliance', 'sso', 'vcd']


def vcda_argument_spec():
    """Set default module argument spec, needed for login to VCDA appliance
        and get access token, used in next API calls.
    """
    return dict(
        hostname=dict(type='str', required=True,
                      fallback=(env_fallback, ['VCDA_HOST'])),
        username=dict(type='str', required=True,
                      fallback=(env_fallback, ['VCDA_USER'])),
        password=dict(type='str', required=True, no_log=True,
                      fallback=(env_fallback, ['VCDA_PASSWORD'])),
        validate_certs=dict(type='bool', fallback=(
            env_fallback, ['VCDA_VERIFY_SSL']), default=False),
        login_type=dict(type='str', required=False,
                        choices=VCDA_LOGIN_TYPES, default='appliance')

    )


class VCDAAnsibleModule(AnsibleModule):
    HEADERS_TYPE = Literal['json', 'vendor']
    API_METHODS = Literal['GET', 'POST', 'PUT', 'DELETE']

    def __init__(self, *args, **kwargs):
        argument_spec = vcda_argument_spec()
        argument_spec.update(kwargs.get('argument_spec', dict()))
        kwargs['argument_spec'] = argument_spec

        super(VCDAAnsibleModule, self).__init__(*args, **kwargs)
        self.login()

        self.headers_vendor = {
            "Accept": self.hAccept,
            "Content-Type": "application/json",
            "X-VCAV-Auth": self.token
        }
        self.headers_json = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-VCAV-Auth": self.token
        }

    def login(self):
        hostname = self.params.get('hostname')
        username = self.params.get('username')
        password = self.params.get('password')
        login_type = self.params.get('login_type')

        url = f"https://{hostname}/sessions"
        if login_type == 'appliance':
            session_body = {
                "type": "localUser",
                "localUser": username,
                "localPassword": password
            }
        elif login_type == 'sso':
            session_body = {
                "type": "ssoCredentials",
                "username": username,
                "password": password
            }
        else:
            session_body = {
                "type": "vcdCredentials",
                "username": username,
                "password": password
            }
        headers = {
            "Accept": "application/json;charset=UTF-8",
            "Content-Type": "application/json"
        }
        #self.validate_certs = False
        response, info = fetch_url(module=self, url=url, method="POST",
                                   headers=headers, data=json.dumps(session_body))
        status_code = info['status']
        if status_code == 200:
            self.token = response.headers.get('X-VCAV-Auth')
            self.hAccept = response.headers.get('Content-Type')
            self.hostname = hostname
            self.password = password
        elif status_code == 401:
            self.fail_json(
                msg='Login failed for user {}'.format(username))
        else:
            self.fail_json(
                msg='{}'.format(info))

    def request_vcda_api(self, api_url: str, api_method: API_METHODS, headers_type: HEADERS_TYPE, headers_append: dict = {}, body: dict = {}):
        url = f"https://{self.hostname}{api_url}"
        match api_method:
            case 'GET':
                return fetch_url(module=self, method=api_method, url=url, headers=self.headers_json if headers_type == 'json' else self.headers_vendor)
            case 'POST':
                if headers_append:
                    headers = self.headers_json.copy(
                    ) if headers_type == 'json' else self.headers_vendor.copy()
                    headers.update(headers_append)
                else:
                    headers = self.headers_json if headers_type == 'json' else self.headers_vendor
                return fetch_url(module=self, method=api_method, url=url, headers=headers, data=json.dumps(body))
            case 'PUT':
                pass
            case 'DELETE':
                pass
