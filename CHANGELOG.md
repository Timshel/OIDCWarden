# Changelog

# testing

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2025.1.0-1`
- Integrate latest change from `Vaultwarden` up to [10d12676](https://github.com/dani-garcia/vaultwarden/commit/10d12676)

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
