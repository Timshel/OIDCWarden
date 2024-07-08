# OpenID Connect test setup

This `docker-compose` template allow to run locally a `VaultWarden` and [`Authentik`](https://goauthentik.io/) instance to test OIDC.

## Usage

You'll need `docker` and `docker-compose` ([cf](https://docs.docker.com/engine/install/)).

First create a copy of `.env.template` as `.env` (This is done to prevent commiting your custom settings, Ex `SMTP_`).

Then start the stack (the `profile` is required to run the `VaultWarden`).
Then you can access :

 - `VaultWarden` on http://127.0.0.1:8000 with the default user `test@yopmail.com/test`.
 - `Authentik` on http://127.0.0.1:9000/ with the default user `akadmin/admin`

## Switching VaultWarden front-end

You can switch between both [version](https://github.com/Timshel/oidc_web_builds) of the front-end using the env variable `SSO_FRONTEND` with `button` or `override` (default is `button`).

## Running only Authentik

Since the `VaultWarden` service is defined with a `profile` you can just use the default `docker-compose` command :

```bash
> docker-compose up
```

When running with a local VaultWarden, if you are using a front-end build from [dani-garcia/bw_web_builds](https://github.com/dani-garcia/bw_web_builds/releases) you'll need to make the SSO button visible using :

```bash
sed -i 's#a\[routerlink="/sso"\],##' /web-vault/app/main.*.css
```

Or use one of the prebuilt front-end from [timshel/oidc_web_builds](https://github.com/Timshel/oidc_web_builds/releases).

Otherwise you'll need to reveal the SSO login button using the debug console (F12)

 ```js
 document.querySelector('a[routerlink="/sso"]').style.setProperty("display", "inline-block", "important");
 ```

## To force rebuilding the VaultWarden image

Use `DOCKER_BUILDKIT=1 docker-compose --profile VaultWarden up --build VaultWarden`.

If after building the `Authentik` configuration is not run, just interrupt and run without `--build`

## Cleanup

Use `docker-compose --profile VaultWarden down`.

## Issues

At the moment the access token lifetime is set to `5min` which will collide with the expiration detection of `VaultWarden` which is set to `5min` too.
This might result in spamming of the refresh token endpoint and race condition might trigger a logout.
