#!/usr/bin/python
# -*- coding: utf-8 -*-


import json
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.urls import fetch_url, ConnectionError, SSLValidationError
from requests.packages import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VCDA_LOGIN_TYPES = ['appliance', 'sso', 'vcd']


def vcda_argument_spec():
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
    def __init__(self, *args, **kwargs):
        argument_spec = vcda_argument_spec()
        argument_spec.update(kwargs.get('argument_spec', dict()))
        kwargs['argument_spec'] = argument_spec

        super(VCDAAnsibleModule, self).__init__(*args, **kwargs)
        self.login()

    def login(self):
        hostname = self.params.get('hostname')
        username = self.params.get('username')
        password = self.params.get('password')
        login_type = self.params.get('login_type')
        validate_certs = self.params.get('validate_certs')

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
            self.__token = response.headers.get('X-VCAV-Auth')
            self.__hAccept = response.headers.get('Content-Type')
            self.__hostname = hostname
        elif status_code == 401:
            self.fail_json(
                msg='Login failed for user {}'.format(username))
        else:
            self.fail_json(
                msg='{}'.format(info))

    def get_info(self):
        url = f"https://{self.__hostname}/diagnostics/about"
        headers = {
            "Accept": self.__hAccept,
            "Content-Type": "application/json",
            "X-VCAV-Auth": self.__token
        }
        response, info = fetch_url(module=self, url=url, method="GET",
                                   headers=headers)
        status_code = info['status']
        if status_code == 200:
            r = json.loads(response.read())
            self.exit_json(changed=False, vcda_info=r)
        else:
            self.fail_json(msg="{}".format(info['body']))
