#
#    Copyright 2022 - Carlos A. <https://github.com/dealfonso>
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
import os
import requests
from .common import *
from datetime import datetime, timedelta
from dateutil.parser import parse as datetimeparser

# A generic Token class, that can be used for any token type. It manages the token and the expiration time, 
#   from an agnostic point of view (i.e. it does not care about the token type or the expiration time).
class Token:
    @staticmethod
    def fromTokenString(token: str, expiration: datetime, body: dict):
        generatedToken = Token()
        generatedToken._setToken(token, expiration, body)
        return generatedToken

    def __init__(self):
        self._valid = False
        self._expiration = None
        self._token = None
        self._body = None

    def __str__(self) -> str:
        return "{}: {}\nExpiration: {}".format(type(self).__name__, self.getToken(), self.getExpiration())

    # Retrieve the body of the token
    def getBody(self) -> dict:
        return self._body

    # Sets the token, along with the expiration time and the body of the token
    def _setToken(self, token, expiration, body = None):
        self._token = token
        self._expiration = expiration
        if self._expiration > datetime.now(self._expiration.tzinfo):
            self._valid = True
        self._body = body
        p_debug("Token set {}".format(str(self)))

    # Obtains the token string if it is valid, otherwise returns None
    def getToken(self) -> str:
        if self.isValid():
            return self._token
        return None

    # Retrieves the expiration time
    def getExpiration(self) -> datetime:
        return self._expiration

    # Returns true if the token is considered to be valid (using the expiration time as a reference)
    def isValid(self) -> bool:
        if self._valid:
            if self._expiration < datetime.now(self._expiration.tzinfo):
                self._valid = False
                p_debug("Token {} expired {}".format(type(self).__name__, str(self)))
        return self._valid

    # A generic method that return true if the token is obtained
    def get(self) -> bool:
        return False

# A class to manage tokens that connect to an URL
class NetToken(Token):
    def __init__(self, url, timeout = 5):
        super().__init__()
        self._url = url
        self._timeout = timeout
          
    # Wrapper for requests.get method that will include a timeout
    def _get(self, url: str, *args, **kwargs):
        if "timeout" not in kwargs:
            kwargs["timeout"] = self._timeout
        try:
            p_debug("GET {}/{}".format(self._url, url.lstrip("/")))
            return requests.get(self._url if url == "" else "{}/{}".format(self._url, url.lstrip("/")), *args, **kwargs)
        except Exception as e:
            return r_error("Could not get {}: {}".format(url, e), None)

    # Wrapper for requests.post method that will include a timeout
    def _post(self, url: str, *args, **kwargs):
        if "timeout" not in kwargs:
            kwargs["timeout"] = self._timeout
        try:
            p_debug("POST {}/{}".format(self._url, url.lstrip("/")), *args)
            return requests.post(self._url if url == "" else "{}/{}".format(self._url, url.lstrip("/")), **kwargs)
        except Exception as e:
            return r_error("Could not post {}: {}".format(url, e), None)

    # Retrieves the URL to which the token is associated
    def getURL(self) -> str:
        return self._url

# A class to obtain bearer tokens from AAI, using a refresh token
class BearerToken(NetToken):
    def __init__(self, refreshToken, url = "https://aai.egi.eu/oidc/token", timeout = 5):
        super().__init__(url, timeout)
        self._refreshToken = refreshToken

    def get(self) -> bool:
        # Generate a bearer token, using the refresh token
        token = self._post("", params = {
                'client_id': 'token-portal',
                'grant_type': 'refresh_token',
                'refresh_token': self._refreshToken
            }, timeout=self._timeout
        )

        # If the token is not obtained, return False (the error has been reported)
        if token is None:
            return False

        if token.status_code in [ 200, 201 ]:
            token = token.json()
            self._setToken(token['access_token'], datetime.now() + timedelta(seconds = token['expires_in']), token)
            return True
        else:
            return r_error("Could not get a new bearer token. Status code: {}".format(token.status_code))

# A class to obtain auth token from a site
class AuthToken(NetToken):
    AUTH_URL = "/auth/tokens"

    def __init__(self, url, scope = None, headers = {}, timeout = 5):
        super().__init__(url, timeout)
        self._scope = scope
        self._headers = headers
        
    # Function that builds an 'auth' section to be used in the request
    # @return a dict with the 'auth' section
    # @return None if there is no auth section
    def _build_auth_json(self) -> dict:
        return None

    # Function that adds a scope to an 'auth' section, if the scope is set
    def _add_scope_to_auth(self, auth) -> None:
        if auth is None or self._scope is None:
            return auth
        auth["scope"] = self._scope

    # Function that builds the headers to be used in the request
    # @return a dict with the headers for the request
    # @return None if the headers could not be created
    def _build_headers(self) -> dict:
        headers = {}
        if self._headers != {}:
            headers = self._headers.copy()

        headers['Content-Type'] = 'application/json'
        return headers

    # Function that obtains an auth token from the site
    def get(self) -> bool:
        auth = self._build_auth_json()
        headers = self._build_headers()
        if headers is None:
            return r_error("Could not build headers")

        # get or post, depending on if we have a body to post or not
        if auth is None:
            token = self._get(self.AUTH_URL,
                headers=headers)
        else:
            body = { "auth": auth }

            # Add a scope if we have one
            if self._scope is not None:
                body["auth"]["scope"] = self._scope

            token = self._post(self.AUTH_URL,
                headers=headers,
                json=body)

        # If we do not get a token, there was an error (and it was reported)
        if token is None:
            return False

        # If the token is valid, process it
        if token.status_code in [ 200, 201 ]:
            authToken = token.headers["X-Subject-Token"]
            token = token.json()
            self._setToken(authToken, datetimeparser(token["token"]["expires_at"]), token)
            return True
        else:
            # Otherwise, report the error
            return r_error("Could not get a new auth token. Status code: {}".format(token.status_code))

# Class to obtain a token from a site using a username and password
class AuthTokenPassword(AuthToken):
    def _build_auth_json(self) -> dict:
        # Retrieves the username and password from the environment (using the standard OpenStack environment variables)
        user = os.environ.get('OS_USERNAME')
        passwd = os.environ.get('OS_PASSWORD')
        auth = {
            "identity": { 
                "methods": [ "password" ], 
                "password": { 
                    "user": { 
                        "name": user, 
                        "domain": { 
                            "id": "default" 
                        }, 
                        "password": passwd 
                    } 
                } 
            }
        }
        return auth

# Class to obtain a token from a site using a token
class AuthTokenToken(AuthToken):

    def __init__(self, token: Token, siteURL = "https://localhost:5000", scope = None, headers = {}) -> None:
        super().__init__(siteURL, scope, headers)
        self._token = token

    def _build_auth_json(self):
        # If the token string is not valid, return None
        token = self._token.getToken()
        if token is None:
            return r_error("Cannot get a valid token", None)

        return {
            "identity": {
                "methods": [ "token" ],
                "token": {
                    "id": token
                }
            }
        }

    def get(self) -> bool:
        # If the token is not valid, try to get a new one or fail
        if not self._token.isValid():
            if not self._token.get():
                return False

        # Use the regular workflow to get the token
        return super().get()

# Class to obtain a token from a site, using a bearer token
class OpenIDToken(AuthTokenToken):
    AUTH_URL = "/OS-FEDERATION/identity_providers/egi.eu/protocols/openid/auth"

    def _build_auth_json(self):
        return None

    def _build_headers(self):

        # If the token is not valid, try to get a new one or fail
        bearerToken = self._token.getToken()
        if bearerToken is None:
            return r_error("Cannot get a valid bearer token", None)

        return {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {}'.format(bearerToken)
        }
