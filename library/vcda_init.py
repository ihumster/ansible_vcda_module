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
        result['warnings'] = []
        # Check password expirations and changing password if his expiried
        pass_expiried = self.get_appliance_password_expiried()
        if type(pass_expiried) is bool and pass_expiried == True:
            new_pass = self.params.get('new_password')
            change_pass = self.change_manager_appliance_password(
                new_password=new_pass)
            if type(change_pass) is bool and change_pass == True:
                result['changed'] = True
                result['warnings'].append(
                    "VCDA Appliance password is changed. For new operations use new password.")
        elif type(pass_expiried) is bool and pass_expiried == False:
            result['changed'] = False
        else:
            result['warnings'].append(pass_expiried)
            result["failed"] = True
        # Push license
        license_key = self.params.get('license_key')
        license_push = self.push_license(license_key=license_key)
        if type(license_push) is bool and license_push == True:
            result['changed'] = True
        else:
            result['changed'] = result["changed"] or False
            result["warnings"].append(license_push)
        return result

    def get_appliance_password_expiried(self):
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
            return "{}".format(info)

    def change_manager_appliance_password(self, new_password: str):
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
            return True
        else:
            return "{}".format(info)

    def push_license(self, license_key: str):
        url = f"https://{self.hostname}/license"
        headers = {
            "Accept": self.hAccept,
            "Content-Type": "application/json",
            "X-VCAV-Auth": self.token
        }
        body = {
            "key": license_key
        }

        response, info = fetch_url(
            module=self, url=url, method="POST", headers=headers, data=json.dumps(body))

        status_code = info['status']
        if status_code == 200:
            return True
        else:
            return "{}".format(info)


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
