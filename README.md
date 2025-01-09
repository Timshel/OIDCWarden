# OIDCWarden

Fork from [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden).
Goal is to provide an OIDC compatible solution with the ultimate goal of merging features back in Vaultwarden.

A master password is still required and not controlled by the SSO (depending on your point of view this might be a feature ;).

Bitwarden [key connector](https://bitwarden.com/help/about-key-connector) is not supported and due to the [license](https://github.com/bitwarden/key-connector/blob/main/LICENSE.txt) it's highly unlikely that it will ever be:

> 2.1 Commercial Module License. Subject to Your compliance with this Agreement, Bitwarden hereby grants to You a limited, non-exclusive, non-transferable, royalty-free license to use the Commercial Modules for the sole purposes of internal development and internal testing, and only in a non-production environment.

## Versions

Tagged version are based on Bitwarden web client releases, Ex: `v2024.8.3-1` is the first release compatible with web client `v2024.8.3`.
\
See [changelog](CHANGELOG.md) for more details.

## Differences with [timshel/vaultwarden](https://github.com/timshel/vaultwarden)

This project was created in an effort to gain more support to maintain the [PR](https://github.com/dani-garcia/vaultwarden/pull/3899) adding OpenID Connect to Vaultwarden.

Main differences now:

- Renamed project / changed icons
- Abitility to release `web-vault` independantly of the [bw_web_builds](https://github.com/dani-garcia/bw_web_builds), the [timshel/vaultwarden](https://github.com/timshel/vaultwarden) will stay in sync.

In the long term distribution will focus on a better OpenID flow (`web-vault` `override` distribution).

## Testing

New release are tested using Playwright integration tests. Currenttly tested flow include:

- Login flow using Master password and/or SSO
- 2FA using email and TOTP
- Organization invitation using Master password and SSO
- Organization auto-invitation
- Role mapping

Goal will be to continue to increase the test coverage but I would recommand to always deploy a specific version and always backup/test before deploying a new release.

## Configuration

See details in [SSO.md](SSO.md).

## Features

### Role mapping

Allow to map roles from the Access token to users to grant access to `VaultWarden` `admin` console.
Support two roles: `admin` or `user`.

This feature is controlled by the following conf:

- `SSO_ROLES_ENABLED`: control if the mapping is done, default is `false`
- `SSO_ROLES_DEFAULT_TO_USER`: do not block login in case of missing or invalid roles, default is `true`.
- `SSO_ROLES_TOKEN_PATH=/resource_access/${SSO_CLIENT_ID}/roles`: path to read roles in the Access token

### Group/Organization invitation mapping

Allow to invite user to existing Oganization if they are listed in the Access token.
If activated it will check if the token contain a list of potential Orgnaization.
If an Oganization with a matching name (case sensitive) is found it will the start the invitation process for this user.
It will use the email associated with the Organization to send further notifications (admin side).

The flow look like this:

- Decode the JWT Access token and check if a list of organization is present (default path is `/groups`).
- Check if an Organization with a matching name exist and the user is not part of it (Use group name mapping if `SSO_ORGANIZATIONS_ID_MAPPING` is defined).
- if mail are activated invite the user to the Orgnization
  - The user will need to click on the link in the mail he received
  - A notification is sent tto he `email` associated with the Organization that a new user is ready to join
  - An admin will have to validate the user to finalize the user joining the org.
- Otherwise just add the user to the Organization
  - An admin will have to validate the user to confirm the user joining the org.

One of the bonus of invitation is that if an organization define a specific password policy then it will apply to new user when they set their new master password.
If a user is part of two organizations then it will order them using the role of the user (`Owner`, `Admin`, `User` or `Manager` for now manager is last :() and return the password policy of the first one.

This feature is controlled with the following conf:

- `SSO_SCOPES`: Optional scope override if additionnal scopes are needed, default is `"email profile"`
- `SSO_ORGANIZATIONS_INVITE`: control if the mapping is done, default is `false`
- `SSO_ORGANIZATIONS_TOKEN_PATH`: path to read groups/organization in the Access token, default is `/groups`
- `SSO_ORGANIZATIONS_ID_MAPPING`: Optional, allow to map provider group to a Vaultwarden organization `uuid` (default `""`, format: `"ProviderId:VaultwardenId;"`)

## Docker

Change the docker files to package both front-end from [Timshel/oidc_web_vault](https://github.com/Timshel/oidc_web_vault/releases).
\
By default it will use the release which only make the `sso` button visible.

If you want to use the version with the additional features mentionned, default redirection to `/sso` and fix organization invitation.
You need to pass an env variable: `-e SSO_FRONTEND='override'` (cf [start.sh](docker/start.sh)).

Docker images available at:

 - Docker hub [hub.docker.com/r/timshel/oidcwarden](https://hub.docker.com/r/timshel/oidcwarden/tags)
 - Github container registry [ghcr.io/timshel/oidcwarden](https://github.com/Timshel/oidcwarden/pkgs/container/oidcwarden)

### Front-end version

By default front-end version is fixed to prevent regression (check [CHANGELOG.md](CHANGELOG.md)).
\
When building the docker image it can be overrided by passing the `OIDC_WEB_RELEASE` arg.
\
Ex to build with latest: `--build-arg OIDC_WEB_RELEASE="https://github.com/Timshel/oidc_web_vault/releases/latest/download"`

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

## Configuration

### Zitadel

To use the role mapping feature you will need to define a custom mapping to return a simple list of role.
More details in Zitadel [documentation](https://zitadel.com/docs/guides/integrate/retrieve-user-roles#customize-roles-using-actions); the cutomization will look something like this:

```javascript
function flatRoles(ctx, api) {
  if (ctx.v1.user.grants == undefined || ctx.v1.user.grants.count == 0) {
    return;
  }

  let grants = [];
  ctx.v1.user.grants.grants.forEach(claim => {
    claim.roles.forEach(role => {
        grants.push(role)
    })
  })

  api.v1.claims.setClaim('my:zitadel:grants', grants)
}
```
