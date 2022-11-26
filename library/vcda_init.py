#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.vcda_common import VCDAAnsibleModule
from typing import Literal
import json
import epdb


def vcda_argument_spec():
    return dict(
        new_password=dict(type='str', required=True, no_log=True),
        license_key=dict(type='str', required=True, no_log=True),
        apiPublicAddress=dict(type='str', required=True),
        apiPublicPort=dict(type='int', required=False, default='443'),
        site=dict(type='str', required=True),
        vmc_data_engine=dict(type=bool, required=False, default=False),
        vcdUrl=dict(type='str', required=True),
        vcdUsername=dict(type='str', required=True),
        vcdPassword=dict(type='str', required=True, no_log=True),
        replicators=dict(type='list', elements='str', required=True),
        lookupServiceUrl=dict(type='str', required=True),
        ssoUser=dict(type='str', required=True),
        ssoPassword=dict(type='str', required=True, no_log=True),
        tunnel=dict(type='str', required=True)
    )


class VCDAInit(VCDAAnsibleModule):

    APPLIANCE_TYPES = Literal["manager", "replicator", "tunnel"]

    def __init__(self, *args, **kwargs) -> None:
        super(VCDAInit, self).__init__(*args, **kwargs)

    def get_certificate(self, url: str):
        cert_url = f"/config/remote-certificate?url={url}"
        resp, info = self.request_vcda_api(
            api_url=cert_url,
            api_method='GET',
            headers_type='json')
        if info['status'] == 200:
            r = json.loads(resp.read())
            return True, r['certificate']['thumbPrint'], r['encoded']
        else:
            return False, None, None

    def vcda_init(self) -> dict():
        result = dict()
        error = dict()
        result['changed'] = False
        result['failed'] = False
        result['warnings'] = []
        # get all params
        new_pass = self.params.get('new_password')
        license_key = self.params.get('license_key')
        apiPubAddr = self.params.get('apiPublicAddress')
        apiPubPort = int(self.params.get('apiPublicPort'))
        site = self.params.get('site')
        vmc_data_engine = self.params.get('vmc_data_engine')
        vcdUrl = self.params.get('vcdUrl')
        vcdUser = self.params.get('vcdUsername')
        vcdPass = self.params.get('vcdPassword')
        replicators = self.params.get('replicators')
        lookupServiceUrl = self.params.get('lookupServiceUrl')
        ssoUser = self.params.get('ssoUser')
        ssoPassword = self.params.get('ssoPassword')
        tunnel = self.params.get('tunnel')

        # check and save certificates and her thumbprints
        # if any certificate not getted - fail
        # check replicators certs
        repl_certs = dict()
        for replicator_address in replicators:
            cert_getted, cert_thumb, cert_encoded = self.get_certificate(
                url=replicator_address)
            if not cert_getted:
                result['failed'] = True
                result['msg'] = f"Can't get replicator '{replicator_address}' certificate"
                return result
            else:
                repl_certs[replicator_address] = tuple(
                    [cert_thumb, cert_encoded])
        # check tunnel certificate
        cert_getted, cert_thumb, cert_encoded = self.get_certificate(
            url=tunnel)
        if not cert_getted:
            result['failed'] = True
            result['msg'] = f"Can't get tunnel '{tunnel}' certificate"
            return result
        else:
            tunnel_cert = tuple([cert_thumb, cert_encoded])
        # check vcd certificate
        cert_getted, cert_thumb, cert_encoded = self.get_certificate(
            url=vcdUrl)
        if not cert_getted:
            result['failed'] = True
            result['msg'] = f"Can't get VCD '{vcdUrl}' certificate"
            return result
        else:
            vcd_cert = tuple([cert_thumb, cert_encoded])
        # check lookupService certificate
        cert_getted, cert_thumb, cert_encoded = self.get_certificate(
            url=lookupServiceUrl)
        if not cert_getted:
            result['failed'] = True
            result['msg'] = f"Can't get Lookup Service '{lookupServiceUrl}' certificate"
            return result
        else:
            lookupsrv_cert = tuple([cert_thumb, cert_encoded])

        # Check password expiration Cloud Manager Appliance and change password if expiried
        resp, info = self.request_vcda_api(
            api_url='/appliance/root-password-expired',
            api_method='GET',
            headers_type='vendor')
        if info['status'] == 200:
            response = json.loads(resp.read())
            if response['rootPasswordExpired']:
                # password is expiried, need change
                resp, info = self.request_vcda_api(
                    api_url='/config/root-password',
                    api_method='POST',
                    headers_type='vendor',
                    headers_append={'Config-Secret': self.password},
                    body={
                        "rootPassword": new_pass
                    }
                )
                # password changed
                if info['status'] == 204:
                    result['changed'] = True
                    result['warnings'].append(
                        "Cloud Manager Appliance password is changed. For new operations use new password.")
                else:  # get error
                    error = json.loads(info['body'].decode())
                    result['msg'] = "Failed on /config/root-password. Error: " + error['msg']
                    result['failed'] = True
                    return result
        else:
            error = json.loads(info['body'].decode())
            result['msg'] = "Failed on /appliance/root-password-expired. Error: " + error['msg']
            result['failed'] = True
            return result
        # Push license
        resp, info = self.request_vcda_api(
            api_url='/license',
            api_method='POST',
            headers_type='vendor',
            body={
                "key": license_key
            }
        )
        if info['status'] == 200:
            result['changed'] = True
        else:  # get error
            error = json.loads(info['body'].decode())
            result['msg'] = "Failed on /license. Error: " + error['msg']
            result['failed'] = True
            return result

        # Set Endpoints
        resp, info = self.request_vcda_api(
            api_url='/config/endpoints',
            api_method='POST',
            headers_type='json',
            body={
                "mgmtAddress": None,
                "mgmtPort": 8046,
                "mgmtPublicAddress": None,
                "mgmtPublicPort": None,
                "apiAddress": None,
                "apiPort": 8443,
                "apiPublicAddress": apiPubAddr,
                "apiPublicPort": apiPubPort
            }
        )
        if info['status'] == 200:
            result['changed'] = True
        else:  # get error
            error = json.loads(info['body'].decode())
            result['msg'] = "Failed on /config/endpoints. Error: " + error['msg']
            result['failed'] = True
            return result

        # Set Site
        resp, info = self.request_vcda_api(
            api_url='/config/site',
            api_method='POST',
            headers_type='json',
            body={
                "localSite": site,
                "localSiteDescription": ""
            }
        )
        if info['status'] == 200:
            result['changed'] = True
        else:  # get error
            error = json.loads(info['body'].decode())
            result['msg'] = "Failed on /config/site. Error: " + error['msg']
            result['failed'] = True
            return result

        # Set Data Engine
        body = {
            "hbrsrv": False if vmc_data_engine else True,
            "h4dm": True if vmc_data_engine else False
        }
        resp, info = self.request_vcda_api(
            api_url='/config/data-engine',
            api_method='POST',
            headers_type='vendor',
            body=body
        )
        if info['status'] == 204:
            result['changed'] = True
        else:  # get error
            if info['status'] >= 400:
                error = json.loads(info['body'].decode())
            else:
                error['msg'] = info['msg']
            result['msg'] = "Failed on /config/data-engine. Error: " + error['msg']
            result['failed'] = True
            return result

        # Check vcdUrl
        resp, info = self.request_vcda_api(
            api_url='/config/check-vcloud',
            api_method='POST',
            headers_type='json',
            body={
                "vcdPassword": vcdPass,
                "vcdThumbprint": vcd_cert[0],
                "vcdUrl": vcdUrl,
                "vcdUsername": vcdUser
            })
        if info['status'] == 204:  # Check sucessful
            # Save VCD to config
            resp, info = self.request_vcda_api(
                api_url='/config/vcloud',
                api_method='POST',
                headers_type='json',
                body={
                    "vcdPassword": vcdPass,
                    "vcdThumbprint": vcd_cert[0],
                    "vcdUrl": vcdUrl,
                    "vcdUsername": vcdUser
                })
            if info['status'] == 200:
                result['changed'] = True
            else:  # get error
                if info['status'] >= 400:
                    error = json.loads(info['body'].decode())
                else:
                    error['msg'] = info['msg']
                result['msg'] = "Failed on /config/vcloud. Error: " + error['msg']
                result['failed'] = True
                return result
        else:  # get error
            if info['status'] >= 400:
                error = json.loads(info['body'].decode())
            else:
                error['msg'] = info['msg']
            result['msg'] = "Failed on /config/check-vcloud. Error: " + error['msg']
            result['failed'] = True
            return result

        for replicator_address in replicators:
            resp, info = self.request_vcda_api(
                api_url='/config/replicators/root-password-expired',
                api_method='POST',
                headers_type='vendor',
                body={
                    "apiThumbprint": repl_certs[replicator_address][0],
                    "apiUrl": replicator_address,
                    "rootPassword": self.password
                })
            if info['status'] == 200:
                response = json.loads(resp.read())
                if response['rootPasswordExpired']:
                    # replicator password expiried
                    resp, info = self.request_vcda_api(
                        api_url='/config/replicators/root-password',
                        api_method='POST',
                        headers_type='json',
                        headers_append={'Config-Secret': self.password},
                        body={
                            "apiUrl": replicator_address,
                            "apiThumbprint": repl_certs[replicator_address][0],
                            "rootPassword": new_pass
                        })
                    # password changed
                    if info['status'] == 200:
                        result['changed'] = True
                        result['warnings'].append(
                            f"Cloud Replicator Appliance '{replicator_address}' password is changed. For new operations use new password.")
                    else:  # get error
                        error = json.loads(info['body'].decode())
                        result['msg'] = "Failed on /config/replicators/root-password. Error: " + error['msg']
                        result['failed'] = True
                        return result
            else:
                error = json.loads(info['body'].decode())
                result['msg'] = "Failed on /config/replicators/root-password-expired. Error: " + error['msg']
                result['failed'] = True
                return result
            # Set lookupservice
            resp, info = self.request_vcda_api(
                api_url='/config/replicators/lookup-service',
                api_method='POST',
                headers_type='vendor',
                body={
                    "apiThumbprint": repl_certs[replicator_address][0],
                    "apiUrl": replicator_address,
                    "lsThumbprint": lookupsrv_cert[0],
                    "lsUrl": lookupServiceUrl,
                    "rootPassword": new_pass
                })
            if info['status'] == 200:
                result['changed'] = True
            else:
                error = json.loads(info['body'].decode())
                result['msg'] = "Failed on /config/replicators/lookup-service. Error: " + error['msg']
                result['failed'] = True
                return result
            # Pair replicator to manager
            resp, info = self.request_vcda_api(
                api_url='/replicators',
                api_method='POST',
                headers_type='vendor',
                body={
                    "apiUrl": replicator_address,
                    "apiThumbprint": repl_certs[replicator_address][0],
                    "rootPassword": new_pass,
                    "ssoUser": ssoUser,
                    "ssoPassword": ssoPassword,
                    "description": ""
                })
            if info['status'] == 200:
                result['changed'] = True
            else:
                error = json.loads(info['body'].decode())
                result['msg'] = "Failed on /replicators. Error: " + error['msg']
                result['failed'] = True
                return result

        # Check lookup service
        resp, info = self.request_vcda_api(
            api_url='/config/check-lookup-service',
            api_method='POST',
            headers_type='json',
            body={
                "url": lookupServiceUrl,
                "thumbprint": lookupsrv_cert[0]
            })
        if info['status'] == 204:
            # Save lookup service
            resp, info = self.request_vcda_api(
                api_url='/config/lookup-service',
                api_method='POST',
                headers_type='json',
                body={
                    "url": lookupServiceUrl,
                    "thumbprint": lookupsrv_cert[0]
                })
            if info['status'] == 200:
                result['changed'] = True
            else:
                error = json.loads(info['body'].decode())
                result['msg'] = "Failed on /config/lookup-service. Error: " + error['msg']
                result['failed'] = True
                return result
        else:
            error = json.loads(info['body'].decode())
            result['msg'] = "Failed on /config/check-lookup-service. Error: " + error['msg']
            result['failed'] = True
            return result
        # Set lookup service for manger
        resp, info = self.request_vcda_api(
            api_url='/config/manager/lookup-service',
            api_method='POST',
            headers_type='vendor',
            body={
                "url": lookupServiceUrl,
                "thumbprint": lookupsrv_cert[0]
            })
        if info['status'] == 200:
            result['changed'] = True
        else:
            error = json.loads(info['body'].decode())
            result['msg'] = "Failed on /config/manager/lookup-service. Error: " + error['msg']
            result['failed'] = True
            return result

        # Prepare Tunnel Appliance
        resp, info = self.request_vcda_api(
            api_url='/config/tunnels/root-password-expired',
            api_method='POST',
            headers_type='vendor',
            body={
                    "apiThumbprint": tunnel_cert[0],
                    "apiUrl": tunnel,
                    "rootPassword": self.password
            })
        if info['status'] == 200:
            response = json.loads(resp.read())
            if response['rootPasswordExpired']:
                # replicator password expiried
                resp, info = self.request_vcda_api(
                    api_url='/config/tunnels/root-password',
                    api_method='POST',
                    headers_type='vendor',
                    headers_append={'Config-Secret': self.password},
                    body={
                        "apiUrl": tunnel,
                        "apiThumbprint": tunnel_cert[0],
                        "rootPassword": new_pass
                    }
                )
                # password changed
                if info['status'] == 200:
                    result['changed'] = True
                    result['warnings'].append(
                        f"Cloud Tunnel Appliance '{tunnel}' password is changed. For new operations use new password.")
                else:  # get error
                    error = json.loads(info['body'].decode())
                    result['msg'] = "Failed on /config/tunnels/root-password. Error: " + error['msg']
                    result['failed'] = True
                    return result
        else:
            error = json.loads(info['body'].decode())
            result['msg'] = "Failed on /config/tunnels/root-password-expired. Error: " + error['msg']
            result['failed'] = True
            return result

        # Add Tunnel service
        resp, info = self.request_vcda_api(
            api_url='/config/tunnel-service',
            api_method='POST',
            headers_type='json',
            body={
                "certificate": tunnel_cert[1],
                "rootPassword": new_pass,
                "url": tunnel
            })
        if info['status'] == 200:
            result['changed'] = True
        else:
            error = json.loads(info['body'].decode())
            result['msg'] = "Failed on /config/tunnel-service. Error: " + error['msg']
            result['failed'] = True
            return result

        # Set lookup service for tunnel
        resp, info = self.request_vcda_api(
            api_url='/config/tunnels/lookup-service',
            api_method='POST',
            headers_type='vendor',
            body={
                "apiThumbprint": tunnel_cert[0],
                "apiUrl": tunnel,
                "lsThumbprint": lookupsrv_cert[0],
                "lsUrl": lookupServiceUrl,
                "rootPassword": new_pass
            })
        if info['status'] == 200:
            result['changed'] = True
        else:
            error = json.loads(info['body'].decode())
            result['msg'] = "Failed on /config/tunnels/lookup-service. Error: " + error['msg']
            result['failed'] = True
            return result

        # Enable Telemetry
        resp, info = self.request_vcda_api(
            api_url='/config/telemetry',
            api_method='POST',
            headers_type='vendor',
            body={
                "enabled": True,
                "environment": None
            })
        if info['status'] == 200:
            result['changed'] = True
        else:
            error = json.loads(info['body'].decode())
            result['msg'] = "Failed on /config/telemetry. Error: " + error['msg']
            result['failed'] = True
            return result

        return result  # final result


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
