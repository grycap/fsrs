#!/bin/python3
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
import requests
import json
import os
import sys
import argparse
from .common import *
from .tokens import *

def main():
    # Get the options from the commandline
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.description = "Fedcloud Server Resource Status (FSRS) - A took to obtain the usage of resources from a OpenStack server that is integrated in Fedcloud. FSS is able to use EGI-AAI to authenticate in the target site"
    parser.add_argument('-q', "--quiet", dest = "quiet", action="store_true", help="Mutes any debug information", default=False)
    parser.add_argument('-i', "--open-id-url", dest = "openid_url", help="OpenID URL", default="https://aai.egi.eu/oidc/token")
    parser.add_argument('-b', "--bearer-token", dest = "bearer_token", help="Bearer token (if provided, the app ignores the use refresh token)", default=None)
    parser.add_argument("-r", "--refresh-token", dest = "refresh_token" , help="Refresh token from AAI", default=os.environ.get('OS_REFRESH_TOKEN'))
    parser.add_argument("-a", "--os-auth-url", dest = "auth_url" , help="Auth URL (e.g. https://localhost:5000/v3)", default=os.environ.get('OS_AUTH_URL'))
    parser.add_argument("-p", "--os-project", dest = "project", required=True, help="Project ID or NAME to scope authorization", default=os.environ.get('OS_PROJECT_ID'))
    parser.add_argument("-t", "--timeout", dest="timeout", help="Timeout in seconds for http requests (default: 5)", default=5)
    args = parser.parse_args()

    if args.quiet:
        setVerbose(False)
    else:
        setVerbose(1)

    # Obtain a token from the AAI
    if args.bearer_token is None:
        openIDToken = OpenIDToken(
            BearerToken(
                args.refresh_token, 
                args.openid_url), 
            args.auth_url)
    else:
        p_debug("Using bearer token provided by the user")
        openIDToken = OpenIDToken(
            Token.fromTokenString(args.bearer_token, datetime.now() + timedelta(seconds = 30), None), 
            args.auth_url)

    if openIDToken.get() == False:
        sys.exit(r_error("Could not get a new OpenID token", 0))

    # Get the projects in the site and obtain the ID of the project to which we want to scope the authorization
    project_id = None
    projects = requests.get("{}/auth/projects".format(args.auth_url), headers = { "X-Auth-Token" : openIDToken.getToken()} )
    if projects.status_code == 200:
        projects = projects.json()
        for p in projects["projects"]:
            if (p["id"] == args.project) or (p["name"] == args.project):
                project_id = p["id"]
                break
    else:
        r_error("Failed to retrieve projects: {}".format(projects.status_code))

    if project_id is None:
        sys.exit(r_error("Project {} not found".format(args.project)))

    # Get a token for the user in the project
    authToken = AuthTokenToken(openIDToken, args.auth_url, {"project": { "id" : project_id } })
    if not authToken.get():
        sys.exit(r_error("Failed to get a valid token", 1))

    # We need the token in the headers
    token = authToken.getToken()

    # Retrieve the endpoints for the project (we need the endpoint for "nova")
    body = authToken.getBody()
    if body is None:
        sys.exit(r_error("could not get body from the token", 1))
    if "token" not in body:
        sys.exit(r_error("could not get information about the token obtained", 1))
    if "catalog" not in body["token"]:
        sys.exit(r_error("could not get information about the catalog obtained", 1))
    catalog = body["token"]["catalog"]
    if len(catalog) == 0:
        sys.exit(r_error("the catalog had no endpoint available", 1))

    nova_ep = None
    for service in catalog:
        if service["type"] == "compute":
            for endpoint in service["endpoints"]:
                if endpoint["interface"] == "public":
                    nova_ep = endpoint["url"]
                    break
            break

    if nova_ep is None:
        sys.exit(r_error("could not find nova endpoint", 1))

    # Get the list of IDs of the servers in the project 
    r = requests.get(nova_ep + "/servers", headers = {'X-Auth-Token': token })
    if r.status_code != 200:
        sys.exit(r_error("could not get servers", 1))

    servers = r.json()
    server_ids = []
    for server in servers["servers"]:
        server_ids.append(server["id"])

    # Finally, retrieve the details of the servers (we'll retrieve the details using API version 2.48, which is better parsed)
    server_info = {}
    for id in server_ids:
        r = requests.get("{}/servers/{}/diagnostics".format(nova_ep, id), headers = {'X-Auth-Token': token, "X-OpenStack-Nova-API-Version": "2.48" })
        if r.status_code != 200:
            r_error("could not get diagnostics for server {}".format(id))
        else:
            server_info[id] = r.json()

    print(json.dumps(server_info, indent=4))