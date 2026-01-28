# OIDCWarden

Soft fork from [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden).
Goal is to provide an OIDC compatible solution with the ultimate goal of merging features back in Vaultwarden.

A master password is still required and not controlled by the SSO (depending on your point of view this might be a feature ;).

Bitwarden [key connector](https://bitwarden.com/help/about-key-connector) is not supported and due to the [license](https://github.com/bitwarden/key-connector/blob/main/LICENSE.txt) it's highly unlikely that it will ever be:

> 2.1 Commercial Module License. Subject to Your compliance with this Agreement, Bitwarden hereby grants to You a limited, non-exclusive, non-transferable, royalty-free license to use the Commercial Modules for the sole purposes of internal development and internal testing, and only in a non-production environment.

## Sponsors

Project made possible with support from the [sponsors](https://github.com/sponsors/Timshel).
\
Would not be possible without the maintainers and contributors of the source project [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden).

More sponsors are needed to ensure continued support, if possible please help :).

It would make possible working on new features such as [Trusted device](https://bitwarden.com/help/about-trusted-devices/), Backchannel logout and adding more integration tests.

## Versions

Tagged version are based on Bitwarden web client releases, Ex: `v2024.8.3-1` is the first release compatible with web client `v2024.8.3`.
\
See [changelog](CHANGELOG.md) for more details.

## Testing

New release are tested using Playwright integration tests. Currenttly tested flow include:

- Login flow using Master password and/or SSO
- 2FA using email and TOTP (with/without SSO)
- Role mapping (access to admin console)
- Organization and collection creation
- Organization invitation using Master password and SSO
- Organization auto-invitation
- Organization membership role sync (Owner, admin ...)
- Organization membership revocation

Goal will be to continue to increase the test coverage but I would recommend to always deploy a specific version and always backup/test before deploying a new release.

## Configuration

See details in [SSO.md](SSO.md).

## Additional Features

Role and Organization mapping can be read from the id token or the user info endpoint.
Sync is done by default at login and optionally on token refresh (this can be expensive since the client can span the endpoint).

- `SSO_SYNC_ON_REFRESH`: Enable to refresh role, orgs and groups on refresh_token.

### Role mapping

Allow to map roles from the Access token to users to grant access to `VaultWarden` `admin` console.
Support two roles: `admin` or `user`.

This feature is controlled by the following conf:

- `SSO_ROLES_ENABLED`: control if the mapping is done, default is `false`
- `SSO_ROLES_DEFAULT_TO_USER`: do not block login in case of missing or invalid roles, default is `true`.
- `SSO_ROLES_TOKEN_PATH=/resource_access/${SSO_CLIENT_ID}/roles`: path to read roles in the id token or user info (used by organization membership role too).

### Organization sync

Allow to synchronize Organization, Groups and User roles.

#### Organization invitation

The organization need to be manually created first.
Will use the email associated with the Organization to send further notifications (admin side).

Invitation flow will look like this:

- Decode the JWT Access token and check if a list of organization is present (default path is `/groups`).
- Check if a matching Organization exists and if the user is not part of it.
- if mail are activated invite the user to the Organization
  - The user will need to click on the link in the mail he received
  - A notification is sent to the `email` associated with the Organization that a new user is ready to join
  - An admin will have to validate the user to finalize the user joining the org.
- Otherwise just add the user to the Organization
  - An admin will have to validate the user to confirm the user joining the org.

One of the bonus of invitation is that if an organization defines a specific password policy then it will apply to new user when they set their new master password.
If a user is part of two organizations then it will order them using the role of the user (`Owner`, `Admin`, `User` or `Manager` for now manager is last :() and return the password policy of the first one.

This feature is controlled with the following configuration:

- `SSO_SCOPES`: Optional scope override if additional scopes are needed, default is `"email profile"`
- `SSO_ORGANIZATIONS_ENABLED`: control if the mapping is done, default is `false`
- `SSO_ORGANIZATIONS_TOKEN_PATH`: path to read organization and groups in the id token or user info, default is `/groups`

#### Organization revocation

If a user is removed from the provider group, the membership will be revoked. User will lose access but no admin intervention will be needed to grant access back.
\
The state of the membership is kept (`invited`, `confirmed`, `accepted`) and will be restored if the user is once again added to the group/organization.

This feature is controlled with the following configuration:

- `SSO_ORGANIZATIONS_REVOCATION`: control if user revocation are made (default `false`).


#### Organization member role

Custom roles can be sent to set the organization member role. Only on role can be defined for all organization.
If not present the user will be assigned the `User` membership.

Possible values include:

- `OrgNoSync`: Disable all organization sync for this user.
- `OrgOwner`: map to the `Owner` role, adding/removing this role has some requirements (is 2FA activated ? is-it the last `Owner` of the org ?).
- `OrgAdmin`: map to the `Admin` role.
- `OrgManager`: map to the custom role with with the ability to manage all collections.
- `OrgUser`: default, `User` can be granted access to all on no collections.

If no role is provided it will default to `User` on invitation and no change will be made for existing member role.

This feature is controlled with the following conf:

- `SSO_ROLES_TOKEN_PATH=/resource_access/${SSO_CLIENT_ID}/roles`: path to read roles in the Access token (The feature is active even if `SSO_ROLES_ENABLED` is disabled).
- `SSO_ORGANIZATIONS_ALL_COLLECTIONS`: are `User` granted access to all collections, default is `true` (will apply only when the user membership role change).

#### Organization groups

The groups will need to be created first. Then if present in the token user can be added/removed.

This feature is controlled with the following conf:

- `ORG_GROUPS_ENABLED`: Need to be activated.

#### Organization and Group mapping

There is multiple ways to match a given provider group value to an organization or a group.
\
Organizations (only when modifying it) and groups allow to set an `ExternalId` to help with this association.

Depending on the format of the provider value different logic will be used:

- simple `toto`:
  - Will match an Organization with a matching `name` or `ExternalId`
  - Will match a Group with a matching `ExternalId`.
- path style: `/org/group` or `org/group` will match using only the names of the organization and group.

Only the `path` style allows to match a group using its name. A simple value can match multiple Organization/Group, this will generate an error and disable sync.
When matching a group then the user will be considered part of the parent Organization even if it's not listed in the provider groups.

## Docker

Change the docker files to package both front-end from [Timshel/oidc_web_vault](https://github.com/Timshel/oidc_web_vault/releases).
\
By default it will use the release which only make the `sso` button visible.

If you want to use the version with the additional features mentioned, default redirection to `/sso` and fix organization invitation.
You need to pass an env variable: `-e SSO_FRONTEND='override'` (cf [start.sh](docker/start.sh)).

Docker images available at:

 - Docker hub [hub.docker.com/r/timshel/oidcwarden](https://hub.docker.com/r/timshel/oidcwarden/tags)
 - Github container registry [ghcr.io/timshel/oidcwarden](https://github.com/Timshel/oidcwarden/pkgs/container/oidcwarden)

### Front-end version

By default front-end version is fixed to prevent regression (check [CHANGELOG.md](CHANGELOG.md)).
\
When building the docker image it can be overridden by passing the `OIDC_WEB_RELEASE` arg.
\
Ex to build with latest: `--build-arg OIDC_WEB_RELEASE="https://github.com/Timshel/oidc_web_vault/releases/latest/download"`

## To test VaultWarden with Keycloak

[Readme](docker/keycloak/README.md)

## Migration from Vaultwarden

Only database difference is adding a column (`external_id`) on the `organizations` table the database.
But due to the history of the project the `__diesel_schema_migrations` table will contain additional migrations (which can safely run on a Vaultwarden DB).

### Revert database for Vaultwarden

Vaultwarden can run directly on the OIIDCWarden database.
\
But when reverting longterm to Vaultwarden I would recommend to cleanup the DB.
\
It can easily be done manually (Make a backup :) :

```psql
>BEGIN;
>DELETE FROM __diesel_schema_migrations WHERE version in ('20250514120000', '20251104120000', '20260128120000'); -- sqlite won't have the `20251104120000` migration
>DROP INDEX IF EXISTS organizations_external_id; -- only sqlite
>ALTER TABLE organizations DROP COLUMN external_id;
> COMMIT / ROLLBACK;
```

## Configuration

### Zitadel

To use the role mapping feature you will need to define a custom mapping to return a simple list of role.
More details in Zitadel [documentation](https://zitadel.com/docs/guides/integrate/retrieve-user-roles#customize-roles-using-actions); the customization will look something like this:

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

## Experimental

### Cockroachdb db support

Initial work done by @haras-unicorn for `Vaultwarden`. Integrated here to see if there is any interest in the feature.

Support is present by default in the docker image (When compiling ensure to activcate the `cockroachdb` feature).
\
You can then configure the database url with:

```env
DATABASE_URL=cockroachdb://user:password@host[:port]/database_name
```
