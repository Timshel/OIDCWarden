# Changelog

# testing

- Rebased on `main` from `dani-garcia/vaultwarden` (`2024-09-10`)
- Org invitation now redirect to SSO login if `SSO_ONLY=true` is set.
- Upgrade [oidc_web_builds](https://github.com/Timshel/oidc_web_builds) version to `v2024.6.2-4`
- Add ORGANIZATION_INVITE_AUTO_ACCEPT

# 1.32.0-2

- Based on `1.32.0` from `dani-garcia/vaultwarden`
- Upgrade [oidc_web_builds](https://github.com/Timshel/oidc_web_builds) version to `v2024.6.2-2`
  Org invitation was lost when creating the master password post SSO loogin.

# 1.32.0-1

- Rebased on `1.32.0` from `dani-garcia/vaultwarden`
- Upgrade [oidc_web_builds](https://github.com/Timshel/oidc_web_builds) version to `v2024.6.2-1`
- Removed `LOG_LEVEL_OVERRIDE` since `LOG_LEVEL=info,vaultwarden::sso=debug` is now available

# 1.32.0-1

- Rebased on `1.32.0` from `dani-garcia/vaultwarden`
- Upgrade [oidc_web_builds](https://github.com/Timshel/oidc_web_builds) version to `v2024.6.2-1`
- Removed `LOG_LEVEL_OVERRIDE` since `LOG_LEVEL=info,vaultwarden::sso=debug` is now available

## 1.31.0-1

- Rebased on `1.31.0` from `dani-garcia/vaultwarden`
- Upgrade [oidc_web_builds](https://github.com/Timshel/oidc_web_builds) version to `v2024.5.1-3`
- Use `WEB_VAULT_FOLDER` to switch front-end without modifying the FS

## 1.30.5-9

- Fix organization invitation when SMTP is disabled.
- Add `SSO_ORGANIZATIONS_ALL_COLLECTIONS` config to allow to grant or not access to all collections (default `true`)

## 1.30.5-8

- Rebased on top dani-garcia/vaultwarden latest `main`.
- Update [oidc_web_builds](https://github.com/Timshel/oidc_web_builds) version to `v2024.3.1-1` which introduce new layout.
- Stop rolling the device token (too many issues with refresh token calls in parallel).

## 1.30.5-7

- Fix mysql sso_users.identifier key creation error.

## 1.30.5-6

- Fix lower case issue which generated invalid "your email has changed" (thx @tribut).

## 1.30.5-5

- Add `SSO_ORGANIZATIONS_ID_MAPPING` to map a Provider group `id` to a Vaultwarden organization `uuid`.

## 1.30.5-4

- Rebased on latest from [dani-garcia:main](https://github.com/dani-garcia/vaultwarden/tree/main)
- Move docker release to [timshel](https://hub.docker.com/repository/docker/timshel/vaultwarden/general)
- Split the `experimental` version to a separate [repository](https://hub.docker.com/repository/docker/timshel/oidcwarden/general).

## 1.30.5-3

- Fix `ForeignKeyViolation` when trying to delete sso user.

## 1.30.5-2

- Store SSO identifier to prevent account takeover

## 1.30.5-1

- Rebased on latest from `dani-garcia/vaultwarden`

## 1.30.3-2

- Add `SSO_CLIENT_CACHE_EXPIRATION` config, to optionally cache the calls to the OpenID discovery endpoint.
- Add a `scope` and `iss` in the oidc redirection to try to fix the IOS login failure.

## 1.30.3-1

- Add `SSO_PKCE` config, disabled for now will probably be activated by defaut in next release.

## 1.30.2-7

- Reduce default `refresh_validity` to 7 days (reset with each `access_token` refresh, so act as an idle timer).
   Apply to non sso login and SSO which return a non JWT token with no expiration information.
- Roll the already present `Device.refresh_token` which will invalidate past `refresh_token` (SSO and non SSO login).
- Remove the `openidconnect` cache since it's not [recommended](https://github.com/ramosbugs/openidconnect-rs/issues/25).

## 1.30.2-6

- Add `SSO_AUDIENCE_TRUSTED` config to allow to trust additionnal audience.

## 1.30.2-5

- Fix mysql migration `2024-02-14-170000_add_state_to_sso_nonce`

## 1.30.2-4

- Upgrade [oidc_web_builds](https://github.com/Timshel/oidc_web_builds) version to `v2024.1.2-6`
- Use `openidconnect` to validate Id Token claims
- Remove `SSO_KEY_FILEPATH` should not be useful now
- Add `SSO_DEBUG_TOKENS` to log Id/Access/Refresh token to debug
- Hardcoded redircetion url
- Switch to reading the roles and groups Claims from the Id Token

## 1.30.2-3

- Add `SSO_AUTHORIZE_EXTRA_PARAMS` to add extra parameter to the authorize redirection (needed to obtain a `refresh_token` with Google Auth).

## 1.30.2-2

- Fix non jwt `acess_token` check when there is no `refresh_token`
- Add `SSO_AUTH_ONLY_NOT_SESSION` to use SSO only for auth not the session lifecycle.

## 1.30.2-1

- Update [oidc_web_builds](https://github.com/Timshel/oidc_web_builds) version to `v2024.1.2-4` which move the org invite patch to the `button` release (which is expected to be merged in VW).
- Remove the `sso_acceptall_invites` setting
- Allow to override log level for specific target

## 1.30.1-11

- Encode redirect url parameters and add `debug` logging.

## 1.30.1-10

- Keep old prevalidate endpoint for Mobile apps

## 1.30.1-9

- Add non jwt access_token support

## 1.30.1-8

- Prevalidate endpoint change in Bitwarden WebVault [web-v2024.1.2](https://github.com/bitwarden/clients/tree/web-v2024.1.2/apps/web)
- Add support for `experimental` front-end which stop sending the Master password hash to the server
- Fix the in docker images

## 1.30.1-7

- Switch user invitation status to `Confirmed` on when user login not before (cf https://github.com/Timshel/vaultwarden/issues/17)
- Return a 404 when user has no `public_key`, will prevent confirming the user in case previous fix is insufficient.

## 1.30.1-6

- Ensure the token endpoint always return a `refresh_token` (cf https://github.com/Timshel/vaultwarden/issues/16)
