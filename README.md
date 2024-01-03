# Fork from [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden)

Goal is to help testing code for the SSO [PR](https://github.com/dani-garcia/vaultwarden/pull/3899).
Based on [Timshel/sso-support](https://github.com/Timshel/vaultwarden/tree/sso-support)

#### :warning: Branch will be rebased and forced-pushed when updated. :warning:

## Versions

Tagged version are based on Vaultwarden releases, Ex: `1.31.0-1` is the first release based on Vaultwarden `1.31.0`.
\
See [changelog](CHANGELOG.md) for more details.

## Additionnal features

This branch now contain additionnal features not added to the SSO [PR](https://github.com/dani-garcia/vaultwarden/pull/3899) since it would slow even more it's review.

### Role mapping

Allow to map roles from the Access token to users to grant access to `VaultWarden` `admin` console.
Support two roles: `admin` or `user`.

This feature is controlled by the following conf:

- `SSO_ROLES_ENABLED`: control if the mapping is done, default is `false`
- `SSO_ROLES_DEFAULT_TO_USER`: do not block login in case of missing or invalid roles, default is `true`.
- `SSO_ROLES_TOKEN_PATH=/resource_access/${SSO_CLIENT_ID}/roles`: path to read roles in the Access token

### Experimental Version

Made a version which additionnaly allow to run the server without storing the master password (it's still required just not sent to the server).
It´s experimental, more information in [timshel/experimental](https://github.com/Timshel/vaultwarden/tree/experimental).

## Docker

Change the docker files to package both front-end from [Timshel/oidc_web_builds](https://github.com/Timshel/oidc_web_builds/releases).
\
By default it will use the release which only make the `sso` button visible.

If you want to use the version which additionally change the default redirection to `/sso` and fix organization invitation to persist.
You need to pass an env variable: `-e SSO_FRONTEND='override'` (cf [start.sh](docker/start.sh)).

Docker images available at:

 - Docker hub [hub.docker.com/r/timshel/vaultwarden](https://hub.docker.com/r/timshel/vaultwarden/tags)
 - Github container registry [ghcr.io/timshel/vaultwarden](https://github.com/Timshel/vaultwarden/pkgs/container/vaultwarden)

### Front-end version

By default front-end version is fixed to prevent regression (check [CHANGELOG.md](CHANGELOG.md)).
\
When building the docker image it can be overrided by passing the `OIDC_WEB_RELEASE` arg.
\
Ex to build with latest: `--build-arg OIDC_WEB_RELEASE="https://github.com/Timshel/oidc_web_builds/releases/latest/download"`

## To test VaultWarden with Keycloak

[Readme](docker/keycloak/README.md)

## DB Migration

ATM The migrations add two tables `sso_nonce`, `sso_users` and a column `invited_by_email` to `users_organizations`.

### Revert to default VW

Reverting to the default VW DB state can easily be done manually (Make a backup :) :

```psql
>BEGIN;
BEGIN
>DELETE FROM __diesel_schema_migrations WHERE version in ('20230910133000', '20230914133000', '20240214170000', '20240226170000', '20240306170000', '20240313170000');
DELETE 5
>DROP TABLE sso_nonce;
DROP TABLE
>DROP TABLE sso_users;
DROP TABLE
>ALTER TABLE users_organizations DROP COLUMN invited_by_email;
ALTER TABLE
> COMMIT / ROLLBACK;
```
