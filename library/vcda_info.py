#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.vcda_common import VCDAAnsibleModule

VCDA_LOGIN_TYPES = ['appliance', 'sso', 'vcd']


def vcda_argument_spec():
    return dict(
        hostname=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', default=False),
        login_type=dict(type='str', required=False,
                        choices=VCDA_LOGIN_TYPES, default='appliance')

    )


def main():
    argument_spec = vcda_argument_spec()
    module = VCDAAnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True)

    module.get_info()


if __name__ == '__main__':
    main()
