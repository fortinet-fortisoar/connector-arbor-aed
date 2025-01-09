"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import time
import requests, json
from connectors.core.connector import get_logger, ConnectorError

from .constants import *

logger = get_logger("arbor-aed")


class ArborAps(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_request(self, endpoint, method='GET', data=None, params=None, files=None):
        try:
            url = self.server_url + 'api/aed/v3/' + endpoint
            logger.info('Executing url {0}'.format(url))
            headers = {'X-Arbux-APIToken': self.api_key}

            if method in ["POST", "PUT", "PATCH"]:
                data = json.dumps(params)
                headers["Content-type"] = 'application/json'
                params = None

            # CURL UTILS CODE
            try:
                from connectors.debug_utils.curl_script import make_curl
                make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=self.verify_ssl)
            except Exception as err:
                logger.error(f"Error in curl utils: {str(err)}")

            response = requests.request(method, url, data=data, params=params, files=files, headers=headers,
                                        verify=self.verify_ssl)
            if response.status_code == 204 and method == "DELETE":
                return {"status": "success"}
            if response.ok:
                return response.json()
            else:

                if response.reason:
                    logger.error(response.reason)
                    raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
                else:
                    logger.error(response.text)
                    raise ConnectorError({'status_code': response.status_code, 'message': response.text})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def get_epoch(_date):
    try:
        if 'T' not in str(_date):
            return int(_date)
        else:
            pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
            return int(time.mktime(time.strptime(_date, pattern)))
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_params(params):
    if params.get('cid_pgid'):
        params.pop('cid_pgid')
    if params.get('timeCreated'):
        params.update({'timeCreated': get_epoch(params.get('timeCreated'))})
    if params.get('updateTime'):
        params.update({'updateTime': get_epoch(params.get('updateTime'))})
    if params.get('sort_param'):
        params.update({'sort': params.get('sort_param')})
        params.pop('sort_param')
    if params.get('other_fields'):
        params.update(params.get('other_fields'))
        del params['other_fields']
    params = {k: PARAM_MAP.get(v, v) for k, v in params.items() if v is not None and v != ''}
    return params


def get_countries(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='countries/', params=params)


def create_inbound_protection_groups(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/', method='POST', params=params)


def get_inbound_protection_groups(config, params):
    aps = ArborAps(config)

    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/', params=params)


def update_inbound_protection_groups(config, params):
    aps = ArborAps(config)
    pgid = ",".join([str(x) for x in params.get('pgid')])
    params.update({'pgid': pgid})
    data = get_params(params)
    response = aps.make_request(endpoint='protection-groups/', method='PATCH', params=data)
    if response.get('protection-groups'):
        return response
    else:
        return {'protection-groups': [response]}


def add_inbound_blacklist_countries(config, params):
    aps = ArborAps(config)
    params.update({'country': params.get('country').replace(" ","")})
    data = get_params(params)
    response = aps.make_request(endpoint='protection-groups/denied-countries/', method='POST', params=data)
    if response.get('countries'):
        return response
    else:
        return {'countries': [response]}


def get_inbound_blacklisted_countries(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/denied-countries/', params=params)


def remove_inbound_blacklisted_countries(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/denied-countries/', method='DELETE', params=params)


def add_inbound_blacklist_domains(config, params):
    aps = ArborAps(config)
    data = get_params(params)
    response = aps.make_request(endpoint='protection-groups/denied-domains/', method='POST', params=data)
    if response.get('domains'):
        return response
    else:
        return {'domains': [response]}


def get_inbound_blacklisted_domains(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/denied-domains/', params=params)


def remove_inbound_blacklisted_domains(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/denied-domains/', method='DELETE', params=params)


def add_inbound_blacklist_hosts(config, params):
    aps = ArborAps(config)
    data = get_params(params)
    response = aps.make_request(endpoint='protection-groups/denied-hosts/', method='POST', params=data)
    if response.get('hosts'):
        return response
    else:
        return {'hosts': [response]}


def get_inbound_blacklisted_hosts(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/denied-hosts/', params=params)


def remove_inbound_blacklisted_hosts(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/denied-hosts/', method='DELETE', params=params)


def add_inbound_whitelisted_hosts(config, params):
    aps = ArborAps(config)
    data = get_params(params)
    response = aps.make_request(endpoint='protection-groups/allowed-hosts/', method='POST', params=data)
    if response.get('hosts'):
        return response
    else:
        return {'hosts': [response]}


def get_inbound_whitelisted_hosts(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/allowed-hosts/', params=params)


def remove_inbound_whitelisted_hosts(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/allowed-hosts/', method='DELETE', params=params)


def add_inbound_blacklist_urls(config, params):
    aps = ArborAps(config)
    data = get_params(params)
    response = aps.make_request(endpoint='protection-groups/denied-urls/', method='POST', params=data)
    if response.get('urls'):
        return response
    else:
        return {'urls': [response]}


def get_inbound_blacklisted_urls(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/denied-urls/', params=params)


def remove_inbound_blacklisted_urls(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='protection-groups/denied-urls/', method='DELETE', params=params)


def add_outbound_blacklist_hosts(config, params):
    aps = ArborAps(config)
    data = get_params(params)
    response = aps.make_request(endpoint='otf/denied-hosts/', method='POST', params=data)
    if response.get('hosts'):
        return response
    else:
        return {'hosts': [response]}


def get_outbound_blacklisted_hosts(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='otf/denied-hosts/', params=params)


def remove_outbound_blacklisted_hosts(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='otf/denied-hosts/', method='DELETE', params=params)


def add_outbound_whitelisted_hosts(config, params):
    aps = ArborAps(config)
    data = get_params(params)
    response = aps.make_request(endpoint='otf/allowed-hosts/', method='POST', params=data)
    if response.get('hosts'):
        return response
    else:
        return {'hosts': [response]}


def get_outbound_whitelisted_hosts(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='otf/allowed-hosts/', params=params)


def remove_outbound_whitelisted_hosts(config, params):
    aps = ArborAps(config)
    params = get_params(params)
    return aps.make_request(endpoint='otf/allowed-hosts/', method='DELETE', params=params)


def _check_health(config):
    try:
        params = {}
        res = get_countries(config, params)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def execute_an_api_call(config, params):
    aps = ArborAps(config)
    method = params.get("method")
    endpoint = params.get("endpoint")
    if params.get("query_params"):
        query_params = params.get("query_params")
        query_params = get_params(query_params)
    else:
        query_params = None
    if params.get("payload"):
        payload = json.dumps(params.get("payload"))
    else:
        payload = None
    return aps.make_request(endpoint=endpoint, method=method, params=query_params, data=payload)


operations = {
    'get_countries': get_countries,
    'create_inbound_protection_groups': create_inbound_protection_groups,
    'get_inbound_protection_groups': get_inbound_protection_groups,
    'update_inbound_protection_groups': update_inbound_protection_groups,
    'add_inbound_blacklist_countries': add_inbound_blacklist_countries,
    'get_inbound_blacklisted_countries': get_inbound_blacklisted_countries,
    'remove_inbound_blacklisted_countries': remove_inbound_blacklisted_countries,
    'add_inbound_blacklist_domains': add_inbound_blacklist_domains,
    'get_inbound_blacklisted_domains': get_inbound_blacklisted_domains,
    'remove_inbound_blacklisted_domains': remove_inbound_blacklisted_domains,
    'add_inbound_blacklist_hosts': add_inbound_blacklist_hosts,
    'get_inbound_blacklisted_hosts': get_inbound_blacklisted_hosts,
    'remove_inbound_blacklisted_hosts': remove_inbound_blacklisted_hosts,
    'add_inbound_whitelisted_hosts': add_inbound_whitelisted_hosts,
    'get_inbound_whitelisted_hosts': get_inbound_whitelisted_hosts,
    'remove_inbound_whitelisted_hosts': remove_inbound_whitelisted_hosts,
    'add_inbound_blacklist_urls': add_inbound_blacklist_urls,
    'get_inbound_blacklisted_urls': get_inbound_blacklisted_urls,
    'remove_inbound_blacklisted_urls': remove_inbound_blacklisted_urls,
    'add_outbound_blacklist_hosts': add_outbound_blacklist_hosts,
    'get_outbound_blacklisted_hosts': get_outbound_blacklisted_hosts,
    'remove_outbound_blacklisted_hosts': remove_outbound_blacklisted_hosts,
    'add_outbound_whitelisted_hosts': add_outbound_whitelisted_hosts,
    'get_outbound_whitelisted_hosts': get_outbound_whitelisted_hosts,
    'remove_outbound_whitelisted_hosts': remove_outbound_whitelisted_hosts,
    'execute_an_api_call': execute_an_api_call
}
