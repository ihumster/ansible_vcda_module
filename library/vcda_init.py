#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.vcda_common import VCDAAnsibleModule
from ansible.module_utils.urls import fetch_url, ConnectionError, SSLValidationError
from requests.packages import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def vcda_argument_spec():
    return dict(
        new_password=dict(type='str', required=True, no_log=True),
        license_key=dict(type='str', required=True, no_log=True)
    )


class VCDAInit(VCDAAnsibleModule):
    def __init__(self, *args, **kwargs) -> None:
        super(VCDAInit, self).__init__(*args, **kwargs)

    def vcda_init(self) -> dict():
        result = dict()
        result['changed'] = False
        result['failed'] = False
        result['warnings'] = []
        # Check password expirations and changing password if his expiried
        pass_expiried = self.get_appliance_password_expiried(result=result)
        if pass_expiried is None:  # get_appliance_password_expiried request return 400+ status code, need exit
            return result
        elif pass_expiried:  # get_appliance_password_expiried return True - pass need change
            new_pass = self.params.get('new_password')
            change_pass = self.change_manager_appliance_password(
                new_password=new_pass, result=result)
            if not change_pass:  # change_manager_appliance_password request return 400+ status code, need exit
                return result
        # Push license
        license_key = self.params.get('license_key')
        self.push_license(license_key=license_key, result=result)

        return result

    def get_appliance_password_expiried(self, result: dict):
        url = f"https://{self.hostname}/appliance/root-password-expired"
        headers = {
            "Accept": self.hAccept,
            "Content-Type": "application/json",
            "X-VCAV-Auth": self.token
        }
        response, info = fetch_url(module=self, url=url, method="GET",
                                   headers=headers)
        status_code = info['status']

        if status_code == 200:
            r = json.loads(response.read())
            if r['rootPasswordExpired']:
                return True
            else:
                return False
        else:
            b = json.loads(info['body'].decode())
            result['msg'].append(b['msg'])
            result['failed'] = True

    def change_manager_appliance_password(self, new_password: str, result: dict):
        url = f"https://{self.hostname}/config/root-password"
        headers = {
            "Accept": self.hAccept,
            "Content-Type": "application/json",
            "Config-Secret": self.password,
            "X-VCAV-Auth": self.token
        }
        body = {
            "rootPassword": new_password
        }
        response, info = fetch_url(
            module=self, url=url, method="POST", headers=headers, data=json.dumps(body))

        status_code = info['status']
        if status_code == 204:
            result['changed'] = True
            result['warnings'].append(
                "VCDA Appliance password is changed. For new operations use new password.")
            return True
        elif status_code >= 400:
            b = json.loads(info['body'].decode())
            result['msg'].append(b['msg'])
            result['failed'] = True
            return False

    def push_license(self, license_key: str, result: dict):
        url = f"https://{self.hostname}/license"
        headers = {
            "Accept": self.hAccept,
            "Content-Type": "application/json",
            "X-VCAV-Auth": self.token
        }

        body = {
            "key": license_key
        }

        response, info = fetch_url(module=self, url=url, method="GET")
        status_code = info['status']
        if status_code == 200:
            r = json.loads(response.read())
            if r['isLicensed']:
                return
        response, info = fetch_url(
            module=self, url=url, method="POST", headers=headers, data=json.dumps(body))
        status_code = info['status']
        if status_code == 200:
            result['changed'] = True
        elif status_code >= 400:
            b = json.loads(info['body'].decode())
            result['msg'].append(b['msg'])
            result['failed'] = True


def main():
    argument_spec = vcda_argument_spec()
    result = dict(msg=dict(type='str'))
    module = VCDAInit(argument_spec=argument_spec, supports_check_mode=True)
    try:
        if module.check_mode:
            result = dict()
            result['changed'] = False
            result['msg'] = "skipped, running in check mode"
            result['skipped'] = True
        else:
            result = module.vcda_init()
    except Exception as error:
        result['msg'] = error
        module.fail_json(**result)
    else:
        if result["failed"]:
            module.fail_json(**result)
        else:
            module.exit_json(**result)


if __name__ == '__main__':
    main()
