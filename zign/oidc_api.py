import logging
import os
import socket
import time
import webbrowser
import random
from urllib.parse import urlparse, urlunsplit

import click
import requests
import stups_cli.config
import tokens
import yaml
from clickclick import UrlType, error, info
from requests import RequestException

from .config import (CONFIG_NAME, OLD_CONFIG_NAME, REFRESH_TOKEN_FILE_PATH,
                     TOKENS_FILE_PATH)
from .oauth2 import ClientRedirectServer

from .api import ServerError, AuthenticationFailed, ConfigurationError, get_config, get_tokens, load_config_ztoken, get_existing_token, store_token, store_config_ztoken, get_named_token, is_valid, is_user_scope, get_service_token, get_token

TOKEN_MINIMUM_VALIDITY_SECONDS = 60*5  # 5 minutes

logger = logging.getLogger('zign.api')

def generate_nonce(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def get_new_token(realm: str, scope: list, user, password, url=None, insecure=False):
    logger.warning('"get_new_token" is deprecated, please use "zign.api.get_token" instead')

    if not url:
        config = get_config(OLD_CONFIG_NAME)
        url = config.get('url')
    params = {'json': 'true'}
    if realm:
        params['realm'] = realm
    if scope:
        params['scope'] = 'openid profile email groups'
    response = requests.get(url, params=params, auth=(user, password), verify=not insecure)
    if response.status_code == 401:
        raise AuthenticationFailed('Token Service returned {}'.format(response.text))
    elif response.status_code != 200:
        raise ServerError('Token Service returned HTTP status {}: {}'.format(response.status_code, response.text))
    try:
        json_data = response.json()
    except:
        raise ServerError('Token Service returned invalid JSON data')

    if not json_data.get('id_token'):
        raise ServerError('Token Service returned invalid JSON (id_token missing)')
    return json_data

def perform_implicit_flow(config: dict):

    # Get new token
    success = False
    # Must match redirect URIs in client configuration (http://localhost:8081-8181)
    port_number = 8081
    max_port_number = port_number + 100

    while True:
        try:
            httpd = ClientRedirectServer(('127.0.0.1', port_number))
        except socket.error as e:
            if port_number > max_port_number:
                success = False
                break
            port_number += 1
        else:
            success = True
            break

    if success:
        params = {'response_type':          'id_token',
                  'scope':                  'openid profile email groups',
                  'business_partner_id':    config['business_partner_id'],
                  'client_id':              config['client_id'],
                  'redirect_uri':           'http://localhost:{}'.format(port_number),
                  'nonce':                  generate_nonce()}

        param_list = ['{}={}'.format(key, value) for key, value in sorted(params.items())]
        param_string = '&'.join(param_list)
        parsed_authorize_url = urlparse(config['authorize_url'])
        browser_url = urlunsplit((parsed_authorize_url.scheme, parsed_authorize_url.netloc, parsed_authorize_url.path,
                                  param_string, ''))

        # Redirect stdout and stderr. In Linux, a message is outputted to stdout when opening the browser
        # (and then a message to stderr because it can't write).
        saved_stdout = os.dup(1)
        saved_stderr = os.dup(2)
        os.close(1)
        os.close(2)
        os.open(os.devnull, os.O_RDWR)
        try:
            webbrowser.open(browser_url, new=1, autoraise=True)
        finally:
            os.dup2(saved_stdout, 1)
            os.dup2(saved_stderr, 2)

        info('Your browser has been opened to visit:\n\n\t{}\n'.format(browser_url))

    else:
        raise AuthenticationFailed('Failed to launch local server')

    while not httpd.query_params:
        # Handle first request, which will redirect to Javascript
        # Handle next request, with token
        httpd.handle_request()

    return httpd.query_params


def get_token_implicit_flow(name=None, authorize_url=None, token_url=None, client_id=None, business_partner_id=None,
                            refresh=False):
    '''Gets a Platform IAM access token using browser redirect flow'''

    if name and not refresh:
        existing_token = get_existing_token(name)
        # This will clear any non-JWT tokens
        if existing_token and existing_token.get('access_token').count('.') >= 2:
            return existing_token

    override = {'name':                 name,
                'authorize_url':        authorize_url,
                'token_url':            token_url,
                'client_id':            client_id,
                'business_partner_id':  business_partner_id}
    config = get_config(CONFIG_NAME, override=override)

    data = load_config_ztoken(REFRESH_TOKEN_FILE_PATH)

    # Force prompting for authorize-url and token-url if only one is specified in the parameter list.
    if authorize_url and not token_url:
        config['token_url'] = click.prompt('Please enter the OAuth 2 Token Endpoint URL', type=UrlType())
    elif token_url and not authorize_url:
        config['authorize_url'] = click.prompt('Please enter the OAuth 2 Authorize Endpoint URL', type=UrlType())

    use_refresh = not (authorize_url or token_url)
    # Refresh token will be used if authorize_url or token_url aren't specified

    refresh_token = data.get('refresh_token')
    if refresh_token and use_refresh:
        payload = {'grant_type':            'refresh_token',
                   'client_id':             config['client_id'],
                   'business_partner_id':   config['business_partner_id'],
                   'refresh_token':         refresh_token}
        try:
            r = requests.post(config['token_url'], timeout=20, data=payload)
            r.raise_for_status()

            token = r.json()
            token['scope'] = 'openid profile email groups'
            if name:
                token['name'] = name
                store_token(name, token)

            store_config_ztoken({'refresh_token': token['refresh_token']}, REFRESH_TOKEN_FILE_PATH)
            return token
        except RequestException as exception:
            error(exception)

    response = perform_implicit_flow(config)

    if 'id_token' in response:
        token = {'access_token':    response['id_token'],
                 'refresh_token':   response.get('refresh_token'),
                 'expires_in':      int(response['expires_in']),
                 'token_type':      response['token_type'],
                 'scope':           'openid profile email groups'}

        # Refresh token is only stored when the default configuration is used
        if token['refresh_token'] and use_refresh:
            store_config_ztoken({'refresh_token': token['refresh_token']}, REFRESH_TOKEN_FILE_PATH)

        if name:
            token['name'] = name
            store_token(name, token)
        return token
    else:
        raise AuthenticationFailed('Failed to retrieve token')
