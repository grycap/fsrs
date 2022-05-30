# Fedcloud Server Resource Status (FSRS)
A tool to obtain the usage of resources from an OpenStack server that is integrated into Fedcloud, using EGI-AAI.

## Getting FSRS

```
git clone https://github.com/grycap/fsrs.git
```

## Usage

### Using a _bearer token_

Get to https://aai.egi.eu/token/refreshtoken.php and get an `Access Token` (_Bearer token_).

```console
./fsrs-cli -b <YOUR BEARER TOKEN> -a https://keystone.my.site:5000/v3 --os-project my-vo
```

**(*)** the _bearer token_ is usually valid for only 1 hour.

### Using a _refresh token_

Get to https://aai.egi.eu/token/refreshtoken.php and get a `Refresh Token`.

```console
./fsrs-cli -r <YOUR REFRESH TOKEN> -a https://keystone.my.site:5000/v3 --os-project my-vo
```

**(*)** the _refresh token_ is usually valid for only 13 months and is used to generate new bearer tokens.

## IMPORTANT

Users that do not have OpenStack permission `os_compute_api:os-server-diagnostics` will not be able to retrieve the resource usage stats.

It is set to `rule:admin_api` as a default value. To enable users to get the stats of their servers, please set it to a more permissive rule (e.g. `rule:admin_or_owner`) in nova-api's policy file.
