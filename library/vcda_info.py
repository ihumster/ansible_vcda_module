#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.vcda_common import VCDAAnsibleModule
from ansible.module_utils.urls import fetch_url, ConnectionError, SSLValidationError
import json
import time


class VCDAInfo(VCDAAnsibleModule):
    def __init__(self, *args, **kwargs) -> None:
        super(VCDAInfo, self).__init__(*args, **kwargs)

    def get_info(self):
        """Get '/diagnostics/health' API call and return VCDA About info in vcda_info var."""
        result = dict()
        error = dict()
        result['changed'] = False
        result['failed'] = False
        result['warnings'] = []

        # Get ID health task
        resp, info = self.request_vcda_api(
            api_url='/diagnostics/health',
            api_method='GET',
            headers_type='vendor')
        if info['status'] == 202:
            r = json.loads(resp.read())
            task_id = r['id']
            time.sleep(2)
            # Get full health info
            resp, info = self.request_vcda_api(
                api_url=f"/tasks/{task_id}",
                api_method='GET',
                headers_type='json')
            if info['status'] == 200:
                r = json.loads(resp.read())
                result['vcda_health'] = r['result']
            else:
                if info['status'] >= 400:
                    error = json.loads(info['body'].decode())
                else:
                    error['msg'] = info['msg']
                result['msg'] = "Failed on /diagnostics/health. Error: " + error['msg']
                result['failed'] = True
            return result
        else:
            if info['status'] >= 400:
                error = json.loads(info['body'].decode())
            else:
                error['msg'] = info['msg']
            result['msg'] = "Failed on /diagnostics/health. Error: " + error['msg']
            result['failed'] = True
        return result


def main():
    result = dict(msg=dict(type='str'))
    module = VCDAInfo(supports_check_mode=True)
    try:
        result = module.get_info()
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
