#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.vcda_common import VCDAAnsibleModule
from ansible.module_utils.urls import fetch_url, ConnectionError, SSLValidationError
from requests.packages import urllib3
from typing import Literal
import json
import epdb


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        lookupServiceUrl=dict(type='str', required=True)
    )


class VCDAInit(VCDAAnsibleModule):

    APPLIANCE_TYPES = Literal["manager", "replicator", "tunnel"]

    def __init__(self, *args, **kwargs) -> None:
        super(VCDAInit, self).__init__(*args, **kwargs)

    def vcda_init(self) -> dict():
        result = dict()
        result['changed'] = False
        result['failed'] = False
        result['warnings'] = []
        # Check password expirations and changing password if his expiried
        pass_expiried = self.get_appliance_password_expiried(result=result)
        if pass_expiried is None:  # get_appliance_password_expiried request return 400+ status code or another error, need exit
            return result
        elif pass_expiried:  # get_appliance_password_expiried return True - pass need change
            new_pass = self.params.get('new_password')
            change_pass = self.change_appliance_password(
                new_password=new_pass, result=result)
            if not change_pass:  # change_manager_appliance_password request return 400+ status code, need exit
                return result
        # Push license
        license_key = self.params.get('license_key')
        license_pushed = self.push_license(
            license_key=license_key, result=result)
        if not license_pushed:
            return result
        # Set Endpoints
        apiPubAddr = self.params.get('apiPublicAddress')
        apiPubPort = int(self.params.get('apiPublicPort'))
        endpoints_setted = self.set_endpoints(
            apiPublicAddress=apiPubAddr, apiPublicPort=apiPubPort, result=result)
        # Set Site
        site = self.params.get('site')
        site_setted = self.set_site(site=site, result=result)

        # Set Data Engine
        vmc_data_engine = self.params.get('vmc_data_engine')
        data_engine_setted = self.set_data_engine(
            vmc_data_engine=vmc_data_engine, result=result)

        if not endpoints_setted:
            result['failed'] = True
            result['msg'] = "Endpoints not setted"
            return result
        if not site_setted:
            result['failed'] = True
            result['msg'] = "Site not setted"
            return result
        if not data_engine_setted:
            result['failed'] = True
            result['msg'] = "Data Engine not setted"
            return result

        # Check vcdUrl
        # TODO Need check vcdUrl urlpase (schema, hostname, /api)
        vcdUrl = self.params.get('vcdUrl')
        vcdUser = self.params.get('vcdUsername')
        vcdPass = self.params.get('vcdPassword')

        vcd_setted = self.set_vcd(
            url=vcdUrl, user=vcdUser, password=vcdPass, result=result)

        if not vcd_setted:
            return result

        replicators = self.params.get('replicators')
        for replicator_address in replicators:

            replicator_pass_expired = self.get_appliance_password_expiried(
                result=result, appliance_address=replicator_address, appliance_type="replicator")
            if replicator_pass_expired:
                # epdb.serve()
                change_pass = self.change_appliance_password(
                    new_password=new_pass, result=result, appliance_address=replicator_address, appliance_type="replicator")
                if not change_pass:
                    return result

        return result

    def get_appliance_password_expiried(self, result: dict, appliance_address: str = "", appliance_type: APPLIANCE_TYPES = "manager"):

        match appliance_type:
            case "manager":
                url = f"https://{self.hostname}/appliance/root-password-expired"

                response, info = fetch_url(module=self, url=url, method="GET",
                                           headers=self.headers_vendor)
            case "replicator":
                url = f"https://{self.hostname}/config/replicators/root-password-expired"
                getted_cert, cert_thumb, cert_encoded = self.get_certificate(
                    url=appliance_address)
                if getted_cert:
                    body = {
                        "apiUrl": appliance_address,
                        "apiThumbprint": cert_thumb,
                        "rootPassword": self.password
                    }
                    response, info = fetch_url(module=self, url=url, method="POST",
                                               headers=self.headers_vendor, data=json.dumps(body))
                    # epdb.serve()
                else:
                    result['failed'] = True
                    result['msg'] = f"Can't get certificate from url '{appliance_address}'"
                    return
            case "tunnel":
                url = f"https://{self.hostname}/config/tunnels/root-password-expired"
                getted_cert, cert_thumb, cert_encoded = self.get_certificate(
                    url=appliance_address)
                if getted_cert:
                    body = {
                        "apiUrl": appliance_address,
                        "apiThumbprint": cert_thumb,
                        "rootPassword": deploy_pass
                    }
                    response, info = fetch_url(module=self, url=url, method="POST",
                                               headers=self.headers_vendor, data=json.dumps(body))
                else:
                    result['failed'] = True
                    result['msg'] = f"Can't get certificate from url '{appliance_address}'"
                    return
        status_code = info['status']
        if status_code == 200:
            r = json.loads(response.read())
            if r['rootPasswordExpired']:
                return True
            else:
                return False
        else:
            b = json.loads(info['body'].decode())
            result['msg'] = b['msg']
            result['failed'] = True

    def change_appliance_password(self, new_password: str, result: dict, appliance_address: str = "", appliance_type: APPLIANCE_TYPES = "manager"):
        secret_pass = self.headers_vendor.copy()
        secret_pass.update({'Config-Secret': self.password})
        match appliance_type:
            case "manager":
                url = f"https://{self.hostname}/config/root-password"
                body = {
                    "rootPassword": new_password
                }
            case "replicator":
                url = f"https://{self.hostname}/config/replicators/root-password"
                getted_cert, cert_thumb, cert_encoded = self.get_certificate(
                    url=appliance_address)
                if getted_cert:
                    body = {
                        "apiUrl": appliance_address,
                        "apiThumbprint": cert_thumb,
                        "rootPassword": new_password
                    }
                else:
                    result['failed'] = True
                    result['msg'] = f"Can't get certificate from url '{appliance_address}'"
                    return
            case "tunnel":
                url = f"https://{self.hostname}/config/tunnels/root-password"
                getted_cert, cert_thumb, cert_encoded = self.get_certificate(
                    url=appliance_address)
                if getted_cert:
                    body = {
                        "apiUrl": appliance_address,
                        "apiThumbprint": cert_thumb,
                        "rootPassword": new_password
                    }
                else:
                    result['failed'] = True
                    result['msg'] = f"Can't get certificate from url '{appliance_address}'"
                    return
        response, info = fetch_url(
            module=self, url=url, method="POST", headers=secret_pass, data=json.dumps(body))
        status_code = info['status']

        if 200 <= status_code < 400:
            result['changed'] = True
            result['warnings'].append(f"VCDA Appliance '{appliance_address}' password is changed. For new operations use new password.") if appliance_address != '' else result['warnings'].append(
                "Cloud Manager Appliance password is changed. For new operations use new password.")
            return True
        elif status_code >= 400:
            b = json.loads(info['body'].decode())
            result['msg'] = b['msg']
            result['failed'] = True
            return False

    def push_license(self, license_key: str, result: dict):
        url = f"https://{self.hostname}/license"

        response, info = fetch_url(
            module=self, url=url, method="GET", headers=self.headers_vendor)
        status_code = info['status']
        if status_code == 200:
            r = json.loads(response.read())
            if r['isLicensed']:
                return True
        body = {
            "key": license_key
        }
        response, info = fetch_url(
            module=self, url=url, method="POST", headers=self.headers_vendor, data=json.dumps(body))
        status_code = info['status']
        if status_code == 200:
            result['changed'] = True
            return True
        elif status_code >= 400:
            b = json.loads(info['body'].decode())
            result['msg'].append(b['msg'])
            result['failed'] = True
            return False

    def set_endpoints(self, apiPublicAddress: str, apiPublicPort: int, result: dict):
        url = f"https://{self.hostname}/config/endpoints"
        body = {
            "mgmtAddress": None,
            "mgmtPort": 8046,
            "mgmtPublicAddress": None,
            "mgmtPublicPort": None,
            "apiAddress": None,
            "apiPort": 8443,
            "apiPublicAddress": apiPublicAddress,
            "apiPublicPort": apiPublicPort
        }
        resp, info = fetch_url(
            module=self, url=url, method="POST", headers=self.headers_json, data=json.dumps(body))
        status_code = info['status']
        if status_code == 200:
            result['changed'] = True
            return True
        elif status_code >= 400:
            b = json.loads(info['body'].decode())
            result['msg'] = b['msg']
            result['failed'] = True
            return False
        else:
            result['failed'] = True
            return False

    def set_site(self, site: str, result: dict):
        url = f"https://{self.hostname}/config/site"
        body = {
            "localSite": site,
            "localSiteDescription": ""
        }
        resp, info = fetch_url(
            module=self, url=url, method="POST", headers=self.headers_json, data=json.dumps(body))
        status_code = info['status']
        if status_code == 200:
            result['changed'] = True
            return True
        elif status_code >= 400:
            b = json.loads(info['body'].decode())
            result['msg'] = b['msg']
            result['failed'] = True
            return False
        else:
            result['failed'] = True
            return False

    def set_data_engine(self, vmc_data_engine: bool, result: dict):
        url = f"https://{self.hostname}/config/data-engine"
        if vmc_data_engine:
            body = {
                "hbrsrv": False,
                "h4dm": True
            }
        else:
            body = {
                "hbrsrv": True,
                "h4dm": False
            }

        resp, info = fetch_url(module=self, url=url, method="POST",
                               headers=self.headers_vendor, data=json.dumps(body))
        status_code = info['status']

        if status_code == 204:
            result['changed'] = True
            return True
        elif status_code >= 400:
            b = json.loads(info['body'].decode())
            result['msg'] = b['msg']
            result['failed'] = True
            return False
        else:
            result['failed'] = True
            return False

    def get_config(self):
        url = f"https://{self.hostname}/config"
        resp, info = fetch_url(module=self, url=url,
                               method="GET", headers=self.headers_vendor)
        status_code = info['status']

        if status_code == 200:
            return True
        elif status_code >= 400:
            return False

    def get_certificate(self, url: str):
        cert_url = f"https://{self.hostname}/config/remote-certificate?url={url}"

        resp, info = fetch_url(module=self, url=cert_url,
                               method="GET", headers=self.headers_json)
        status_code = info['status']

        if status_code == 200:
            r = json.loads(resp.read())
            return True, r['certificate']['thumbPrint'], r['encoded']
        else:
            return False, '', ''

    def set_vcd(self, url: str, user: str, password: str, result: dict):

        getted_cert, certThumb, cert_enc = self.get_certificate(url=url)
        if getted_cert:
            vcda_url = f"https://{self.hostname}/config/vcloud"

            body = {
                "vcdPassword": password,
                "vcdThumbprint": certThumb,
                "vcdUrl": url,
                "vcdUsername": user
            }

            resp, info = fetch_url(module=self, url=vcda_url, method="POST",
                                   headers=self.headers_json, data=json.dumps(body))
            status_code = info['status']
            if status_code == 200:
                result['changed'] = True
                return True
            elif status_code >= 400:
                b = json.loads(info['body'].decode())
                result['msg'] = b['msg']
                result['failed'] = True
                return False
        else:
            result['failed'] = True
            result['msg'] = f"Can't get certificate details from url '{url}'"
            return False

    def set_lookup_service(self, result: dict, lookupUrl: str, appliance_type: APPLIANCE_TYPES = "manager"):

        match appliance_type:
            case "manager":
                url = f"https://{self.hostname}/config/manager/lookup-service"
                body = {
                    "url": lookupUrl,
                    "thumbprint": "SHA-256:5D:18:B8:D3:B5:B9:51:29:B3:9F:75:7F:84:1D:32:4F:73:0D:9C:08:12:03:F6:8C:96:09:C9:29:1A:42:57:60"
                }
                pass
            case "replicator":
                url = f"https://{self.hostname}/config/replicators/lookup-service"
                pass
            case "tunnel":
                url = f"https://{self.hostname}/config/tunnels/lookup-service"
                pass


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
