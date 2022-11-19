#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.vcda_common import VCDAAnsibleModule
from ansible.module_utils.urls import fetch_url, ConnectionError, SSLValidationError
from requests.packages import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VCDAInfo(VCDAAnsibleModule):
    def __init__(self, *args, **kwargs) -> None:
        super(VCDAInfo, self).__init__(*args, **kwargs)

    def get_info(self):
        """Get '/diagnostics/about' API call and return VCDA About info in vcda_info var."""
        url = f"https://{self.hostname}/diagnostics/about"
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
            self.exit_json(changed=False, vcda_info=r)
        else:
            self.fail_json(msg="{}".format(info))


def main():
    module = VCDAInfo(supports_check_mode=True)

    module.get_info()


if __name__ == '__main__':
    main()
