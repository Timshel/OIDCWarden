# Changelog

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
