# Changelog

# v2025.7.2-1

- Integrate latest change from `Vaultwarden`/`SSO PR` up to [a71da2d](https://github.com/dani-garcia/vaultwarden/commit/a71da2d0a4e93034397134b17078a27829264043)
- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.7.2-1`
- Change to `SSO_ORGANIZATIONS_ALL_COLLECTIONS` to stop using a hidden field.
  On user invitation will now add read only access to all available collection (Does not grant access to collections created afterwards.).

# v2025.6.2-1

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.6.2-1`

# v2025.6.1-3

- Fix single org policy check regression

# v2025.6.1-2

- Integrate latest change from `Vaultwarden` up to [3b48e6e](https://github.com/dani-garcia/vaultwarden/commit/3b48e6e)
  Should fix inability to delete secrets.

# v2025.6.1-1

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.6.1-1`
- Provider role and groups are now read from `user_info` endpoint too.
- `SSO_SYNC_ON_REFRESH` allow to trigger role and orgs sync on token refresh.
  This can be expensive since the client can span the endpoint

# v2025.6.0-2

- Update server start message

# v2025.6.0-1

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.6.0-1`

# v2025.5.1-5

- Check `email_verified` in id_token and user_info

# v2025.5.1-4

- Fix organization group sync when using `Mariadb`

# v2025.5.1-3

- Fix invalid organization sync query with `postgres` and `mysql`

# v2025.5.1-2

- Fix enforcing of organization master password policies.
- Deprecation from `v2025.5.0-1` are still pending (Will wait at least one more week).

# v2025.5.1-1

- Integrate change from `Vaultwarden` [1.34.1](https://github.com/dani-garcia/vaultwarden/tree/1.34.1)
- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.5.1-1`

# v2025.5.0-1

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.5.0-1`
- :warning: Rework of the organization sync, see [README.md#organization_sync](README.md#organization_sync) :warning:
- Add support for oganization groups sync
  - Initially the feature will be avaible only if `ORG_GROUPS_ENABLED` and `SSO_ORGANIZATIONS_GROUPS_ENABLED` are activated
  - `SSO_ORGANIZATIONS_GROUPS_ENABLED` will be removed in subsequent release (feature will be active if `ORG_GROUPS_ENABLED` is enabled).
- :warning: multiple deprecations
  - `SSO_ORGANIZATIONS_INVITE`: Will be removed with the next release. replaced with `SSO_ORGANIZATIONS_ENABLED`.
  - `SSO_ORGANIZATIONS_ID_MAPPING` Will be removed with the next release. For now if present is still used, only Organization and User role mapping is done.
- :warning: new database modification (add a column with a default value, old version will run on the modified db).

# v2025.4.2-1 (Never released)

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.4.2-1`
- Add support for organization role mapping

# v2025.3.1-1 (Never released)

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.3.1-4`
  \
  :warning: `v2025.3.x` brings change to the login flow, the SSO button is now available on the landing page.
- Integrate latest change from `Vaultwarden` up to [e7c796a6](https://github.com/dani-garcia/vaultwarden/commit/e7c796a6)
- Fix invited user registration without SMTP
- Add sso identifier in admin user panel

# v2025.2.2-2

- Ignore unsupported User role

# v2025.2.2-1

- Integrate latest change from `Vaultwarden` up to [6edceb5](https://github.com/dani-garcia/vaultwarden/commit/6edceb5f7acfee8ffe1ae2f07afd76dc588dda60)
- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.2.2-1`

# v2025.1.2-3

- Fix member invite, `Owner` and `Admin` were not granted collection access.

# v2025.1.2-2

- Fix member edit, `Owner` and `Admin` were losing collection access.

# v2025.1.2-1

- :warning: upgrade to `openidconnect` `4.0.0`, proceed with caution :warning:
- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.1.2-4`

# v2025.1.1-7

- Integrate latest change from `Vaultwarden` up to [8d1df08](https://github.com/dani-garcia/vaultwarden/commit/8d1df08b81e1e0eea28e480de236dc0501674edc)
  \
  :warning: endup not being built due to a merge error.

# v2025.1.1-6

- `SSO_ORGANIZATIONS_ID_MAPPING` organization can now be mapped using `uuid` or `name`.

# v2025.1.1-5

- If `SSO_ORGANIZATIONS_ID_MAPPING` is defined then revocation will apply only to the listed organizations.
  \
  Can be used to restrict on which organizations the revocation logic apply.

# v2025.1.1-4

- Added `SSO_ORGANIZATIONS_REVOCATION` to control membership revocation activation, disabled by default.

# v2025.1.1-3

- Add revocation support
  \
  :warning: if `SSO_ORGANIZATIONS_INVITE` is activated and the provider do not return a matching group for an organization then the user membership will be revoked.
  \
  More details in [README.md#Revocation](https://github.com/Timshel/vaultwarden/blob/main/README.md#revocation)

# v2025.1.1-2

- Integrate change from `Vaultwarden` [1.33.0](https://github.com/dani-garcia/vaultwarden/tree/1.33.0)

# v2025.1.1-1

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.1.1-1`
- Integrate latest change from `Vaultwarden` up to [c0be36a1](https://github.com/dani-garcia/vaultwarden/commit/c0be36a1)
  \
  :warning: This includes a DB migration; but the added column comes with a default value so a rollback is still possible.:warning:

# v2025.1.0-3

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.1.0-2`

# v2025.1.0-2

- Use css classes to toggle 2FA providers

# v2025.1.0-1

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.1.0-1`
  Add dynamic CSS support
- Integrate latest change from `Vaultwarden` up to [ef2695d](https://github.com/dani-garcia/vaultwarden/commit/ef2695de0cb81feaa5cab8045f0bff71ab3e8c71)
- Allow set-password only if account is unitialized
- Disable signups if SSO_ONLY is activated

# v2024.12.1-2

- Check stored key before disabling TOTP
- Restore old TOTP disable logic for old clients

# v2024.12.1-1

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2024.12.1-2`
- Add dynamic CSS support
- Integrate change from `Vaultwarden` [1.32.7](https://github.com/dani-garcia/vaultwarden/tree/1.32.7)

# v2024.10.2-7

- Integrate change from `Vaultwarden` [1.32.6](https://github.com/dani-garcia/vaultwarden/tree/1.32.6)

# v2024.10.2-6

- Prevent disabled User from logging with SSO
- Fix SSO organization Identifier prefill

# v2024.10.2-5

- Base64 encode state before sending it to providers to prevent issues

# v2024.10.2-4

- Fix docker images to use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2024.10.2-1`

# v2024.10.2-3

- Integrate change from `Vaultwarden` [1.32.5](https://github.com/dani-garcia/vaultwarden/tree/1.32.5)

# v2024.10.2-2

- Integrate change from `Vaultwarden` [1.32.4](https://github.com/dani-garcia/vaultwarden/tree/1.32.4)

# v2024.10.2-1

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2024.10.2-1`
- :warning: Breaking change :warning:
  - `SSO_PKCE` is now on by default, if you are running Zitadel you'll probably need to set it to `false` since it's incompatible with `CLIENT_SECRET`
  - On first SSO login if the provider does not return the email verification status log in will be blocked.
    Check the [documentation](https://github.com/Timshel/vaultwarden/blob/main/SSO.md#on-sso_allow_unknown_email_verification) for more details.
- Integrate latest change from `Vaultwarden` up to [f60502a1](https://github.com/dani-garcia/vaultwarden/commit/f60502a17e578cbfcd98bfd4763dc054948c1662)

# v2024.8.3-3

- Integrate latest change from `Vaultwarden` [1.32.1](https://github.com/dani-garcia/vaultwarden/tree/1.32.1)

# v2024.8.3-2

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version to `v2024.8.3-4`

# v2024.8.3-1

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version to `v2024.8.3-1`
