use chrono::Utc;
use derive_more::{AsRef, Deref, Display, From};
use regex::Regex;
use serde::de::DeserializeOwned;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use url::Url;

use mini_moka::sync::Cache;
use once_cell::sync::Lazy;
use openidconnect::core::{
    CoreClient, CoreIdTokenVerifier, CoreProviderMetadata, CoreResponseType, CoreUserInfoClaims,
};
use openidconnect::reqwest;
use openidconnect::{
    AccessToken, AuthDisplay, AuthPrompt, AuthenticationFlow, AuthorizationCode, AuthorizationRequest, ClientId,
    ClientSecret, CsrfToken, EndpointNotSet, EndpointSet, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RefreshToken, ResponseType, Scope,
};

use crate::{
    api::core::organizations::CollectionData,
    api::ApiResult,
    auth,
    auth::{AuthMethod, AuthMethodScope, AuthTokens, ClientIp, TokenWrapper, BW_EXPIRATION, DEFAULT_REFRESH_VALIDITY},
    business::organization_logic,
    db::{
        models::{
            Device, EventType, GroupId, Membership, MembershipType, Organization, OrganizationId, SsoNonce, User,
        },
        DbConn,
    },
    CONFIG,
};

pub static FAKE_IDENTIFIER: &str = "OIDCWarden";
pub const ACTING_AUTO_ENROLL_USER: &str = "oidcwarden-auto-00000-000000000000";

static AC_CACHE: Lazy<Cache<OIDCState, AuthenticatedUser>> =
    Lazy::new(|| Cache::builder().max_capacity(1000).time_to_live(Duration::from_secs(10 * 60)).build());

static CLIENT_CACHE_KEY: Lazy<String> = Lazy::new(|| "sso-client".to_string());
static CLIENT_CACHE: Lazy<Cache<String, Client>> = Lazy::new(|| {
    Cache::builder().max_capacity(1).time_to_live(Duration::from_secs(CONFIG.sso_client_cache_expiration())).build()
});

static SSO_JWT_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|sso", CONFIG.domain_origin()));

pub static NONCE_EXPIRATION: Lazy<chrono::Duration> = Lazy::new(|| chrono::TimeDelta::try_minutes(10).unwrap());

trait AuthorizationRequestExt<'a> {
    fn add_extra_params<N: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>>(self, params: Vec<(N, V)>) -> Self;
}

impl<'a, AD: AuthDisplay, P: AuthPrompt, RT: ResponseType> AuthorizationRequestExt<'a>
    for AuthorizationRequest<'a, AD, P, RT>
{
    fn add_extra_params<N: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>>(mut self, params: Vec<(N, V)>) -> Self {
        for (key, value) in params {
            self = self.add_extra_param(key, value);
        }
        self
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCCode(String);

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCState(String);

#[derive(Debug, Serialize, Deserialize)]
struct SsoTokenJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,
}

pub fn encode_ssotoken_claims() -> String {
    let time_now = Utc::now();
    let claims = SsoTokenJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + chrono::TimeDelta::try_minutes(2).unwrap()).timestamp(),
        iss: SSO_JWT_ISSUER.to_string(),
        sub: "vaultwarden".to_string(),
    };

    auth::encode_jwt(&claims)
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OIDCCodeWrapper {
    Ok {
        state: OIDCState,
        code: OIDCCode,
    },
    Error {
        state: OIDCState,
        error: String,
        error_description: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct OIDCCodeClaims {
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,

    pub code: OIDCCodeWrapper,
}

pub fn encode_code_claims(code: OIDCCodeWrapper) -> String {
    let time_now = Utc::now();
    let claims = OIDCCodeClaims {
        exp: (time_now + chrono::TimeDelta::try_minutes(5).unwrap()).timestamp(),
        iss: SSO_JWT_ISSUER.to_string(),
        code,
    };

    auth::encode_jwt(&claims)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BasicTokenClaims {
    iat: Option<i64>,
    nbf: Option<i64>,
    exp: i64,
}

impl BasicTokenClaims {
    fn nbf(&self) -> i64 {
        self.nbf.or(self.iat).unwrap_or_else(|| Utc::now().timestamp())
    }
}

// IdToken validation is handled by IdToken.claims
// This is only used to retrive additionnal claims which are configurable
// Or to try to parse access_token and refresh_tken as JWT to find exp
fn insecure_decode<T: DeserializeOwned>(token_name: &str, token: &str) -> ApiResult<T> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.set_issuer(&[CONFIG.sso_authority()]);
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;

    match jsonwebtoken::decode::<T>(token, &jsonwebtoken::DecodingKey::from_secret(&[]), &validation) {
        Ok(btc) => Ok(btc.claims),
        Err(err) => err_silent!(format!("Failed to decode {token_name}: {err}")),
    }
}

#[derive(Clone)]
struct Client {
    http_client: reqwest::Client,
    core_client: CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet, EndpointSet>,
}

impl Client {
    // Call the OpenId discovery endpoint to retrieve configuration
    async fn _get_client() -> ApiResult<Self> {
        let client_id = ClientId::new(CONFIG.sso_client_id());
        let client_secret = ClientSecret::new(CONFIG.sso_client_secret());

        let issuer_url = CONFIG.sso_issuer_url()?;

        let http_client = match reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none()).build() {
            Err(err) => err!(format!("Failed to build http client: {err}")),
            Ok(client) => client,
        };

        let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, &http_client).await {
            Err(err) => err!(format!("Failed to discover OpenID provider: {err}")),
            Ok(metadata) => metadata,
        };

        let base_client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret));

        let token_uri = match base_client.token_uri() {
            Some(uri) => uri.clone(),
            None => err!("Failed to discover token_url, cannot proceed"),
        };

        let user_info_url = match base_client.user_info_url() {
            Some(url) => url.clone(),
            None => err!("Failed to discover user_info url, cannot proceed"),
        };

        let core_client = base_client
            .set_redirect_uri(CONFIG.sso_redirect_url()?)
            .set_token_uri(token_uri)
            .set_user_info_url(user_info_url);

        Ok(Client {
            http_client,
            core_client,
        })
    }

    // Simple cache to prevent recalling the discovery endpoint each time
    async fn cached() -> ApiResult<Self> {
        if CONFIG.sso_client_cache_expiration() > 0 {
            match CLIENT_CACHE.get(&*CLIENT_CACHE_KEY) {
                Some(client) => Ok(client),
                None => Self::_get_client().await.inspect(|client| {
                    debug!("Inserting new client in cache");
                    CLIENT_CACHE.insert(CLIENT_CACHE_KEY.clone(), client.clone());
                }),
            }
        } else {
            Self::_get_client().await
        }
    }

    async fn user_info(&self, access_token: AccessToken) -> ApiResult<CoreUserInfoClaims> {
        match self.core_client.user_info(access_token, None).request_async(&self.http_client).await {
            Err(err) => err!(format!("Request to user_info endpoint failed: {err}")),
            Ok(user_info) => Ok(user_info),
        }
    }

    fn vw_id_token_verifier(&self) -> CoreIdTokenVerifier<'_> {
        let mut verifier = self.core_client.id_token_verifier();
        if let Some(regex_str) = CONFIG.sso_audience_trusted() {
            match Regex::new(&regex_str) {
                Ok(regex) => {
                    verifier = verifier.set_other_audience_verifier_fn(move |aud| regex.is_match(aud));
                }
                Err(err) => {
                    error!("Failed to parse SSO_AUDIENCE_TRUSTED={regex_str} regex: {err}");
                }
            }
        }
        verifier
    }
}

pub fn deocde_state(base64_state: String) -> ApiResult<OIDCState> {
    let state = match data_encoding::BASE64.decode(base64_state.as_bytes()) {
        Ok(vec) => match String::from_utf8(vec) {
            Ok(valid) => OIDCState(valid),
            Err(_) => err!(format!("Invalid utf8 chars in {base64_state} after base64 decoding")),
        },
        Err(_) => err!(format!("Failed to decode {base64_state} using base64")),
    };

    Ok(state)
}

// The `nonce` allow to protect against replay attacks
// The `state` is encoded using base64 to ensure no issue with providers (It contains the Organization identifier).
// redirect_uri from: https://github.com/bitwarden/server/blob/main/src/Identity/IdentityServer/ApiClient.cs
pub async fn authorize_url(
    state: OIDCState,
    client_id: &str,
    raw_redirect_uri: &str,
    mut conn: DbConn,
) -> ApiResult<Url> {
    let scopes = CONFIG.sso_scopes_vec().into_iter().map(Scope::new);
    let base64_state = data_encoding::BASE64.encode(state.to_string().as_bytes());

    let redirect_uri = match client_id {
        "web" | "browser" => format!("{}/sso-connector.html", CONFIG.domain()),
        "desktop" | "mobile" => "bitwarden://sso-callback".to_string(),
        "cli" => {
            let port_regex = Regex::new(r"^http://localhost:([0-9]{4})$").unwrap();
            match port_regex.captures(raw_redirect_uri).and_then(|captures| captures.get(1).map(|c| c.as_str())) {
                Some(port) => format!("http://localhost:{}", port),
                None => err!("Failed to extract port number"),
            }
        }
        _ => err!(format!("Unsupported client {client_id}")),
    };

    let client = Client::cached().await?;
    let mut auth_req = client
        .core_client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            || CsrfToken::new(base64_state),
            Nonce::new_random,
        )
        .add_scopes(scopes)
        .add_extra_params(CONFIG.sso_authorize_extra_params_vec()?);

    let verifier = if CONFIG.sso_pkce() {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        auth_req = auth_req.set_pkce_challenge(pkce_challenge);
        Some(pkce_verifier.secret().to_string())
    } else {
        None
    };

    let (auth_url, _, nonce) = auth_req.url();

    let sso_nonce = SsoNonce::new(state, nonce.secret().to_string(), verifier, redirect_uri);
    sso_nonce.save(&mut conn).await?;

    Ok(auth_url)
}

#[derive(Debug)]
struct AdditionnalClaims {
    role: Option<UserRole>,
    groups: Vec<String>,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
    #[serde(other)]
    UNKNOWN,
}

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCIdentifier(String);

impl OIDCIdentifier {
    fn new(issuer: &str, subject: &str) -> Self {
        OIDCIdentifier(format!("{}/{}", issuer, subject))
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub refresh_token: Option<String>,
    pub access_token: String,
    pub expires_in: Option<Duration>,
    pub identifier: OIDCIdentifier,
    pub email: String,
    pub email_verified: Option<bool>,
    pub user_name: Option<String>,
    pub role: Option<UserRole>,
    pub groups: Vec<String>,
}

impl AuthenticatedUser {
    pub fn is_admin(&self) -> bool {
        self.role.as_ref().is_some_and(|x| x == &UserRole::Admin)
    }
}

#[derive(Clone, Debug)]
pub struct UserInformation {
    pub state: OIDCState,
    pub identifier: OIDCIdentifier,
    pub email: String,
    pub email_verified: Option<bool>,
    pub user_name: Option<String>,
}

// Errors are logged but will return None
fn roles_claim(email: &str, token: &serde_json::Value) -> Option<UserRole> {
    if let Some(json_roles) = token.pointer(&CONFIG.sso_roles_token_path()) {
        match serde_json::from_value::<Vec<UserRole>>(json_roles.clone()) {
            Ok(mut roles) => {
                roles.sort();
                roles.into_iter().next()
            }
            Err(err) => {
                debug!("Failed to parse user ({email}) roles: {err}");
                None
            }
        }
    } else {
        debug!("No roles in {email} id_token at {}", &CONFIG.sso_roles_token_path());
        None
    }
}

// Errors are logged but will return an empty Vec
fn groups_claim(email: &str, token: &serde_json::Value) -> Vec<String> {
    if let Some(json_groups) = token.pointer(&CONFIG.sso_organizations_token_path()) {
        match serde_json::from_value::<Vec<String>>(json_groups.clone()) {
            Ok(groups) => groups,
            Err(err) => {
                error!("Failed to parse user ({email}) groups: {err}");
                Vec::new()
            }
        }
    } else {
        debug!("No groups in {email} id_token at {}", &CONFIG.sso_organizations_token_path());
        Vec::new()
    }
}

// Trying to conditionnally read additionnal configurable claims using openidconnect appear nightmarish
// So we just decode the token again as a JsValue
fn additional_claims(email: &str, token: &str) -> ApiResult<AdditionnalClaims> {
    let mut role = None;
    let mut groups = Vec::new();

    if CONFIG.sso_roles_enabled() || CONFIG.sso_organizations_invite() {
        match insecure_decode::<serde_json::Value>("id_token", token) {
            Err(err) => err!(format!("Could not decode access token: {:?}", err)),
            Ok(claims) => {
                if CONFIG.sso_roles_enabled() {
                    role = roles_claim(email, &claims);
                    if !CONFIG.sso_roles_default_to_user() && role.is_none() {
                        info!("User {email} failed to login due to missing/invalid role");
                        err!(
                            "Invalid user role. Contact your administrator",
                            ErrorEvent {
                                event: EventType::UserFailedLogIn
                            }
                        )
                    }
                }

                if CONFIG.sso_organizations_invite() {
                    groups = groups_claim(email, &claims);
                }
            }
        }
    }

    Ok(AdditionnalClaims {
        role,
        groups,
    })
}

async fn decode_code_claims(code: &str, conn: &mut DbConn) -> ApiResult<(OIDCCode, OIDCState)> {
    match auth::decode_jwt::<OIDCCodeClaims>(code, SSO_JWT_ISSUER.to_string()) {
        Ok(code_claims) => match code_claims.code {
            OIDCCodeWrapper::Ok {
                state,
                code,
            } => Ok((code, state)),
            OIDCCodeWrapper::Error {
                state,
                error,
                error_description,
            } => {
                if let Err(err) = SsoNonce::delete(&state, conn).await {
                    error!("Failed to delete database sso_nonce using {state}: {err}")
                }
                err!(format!(
                    "SSO authorization failed: {error}, {}",
                    error_description.as_ref().unwrap_or(&String::new())
                ))
            }
        },
        Err(err) => err!(format!("Failed to decode code wrapper: {err}")),
    }
}

// During the 2FA flow we will
//  - retrieve the user information and then only discover he needs 2FA.
//  - second time we will rely on the `AC_CACHE` since the `code` has already been exchanged.
// The `nonce` will ensure that the user is authorized only once.
// We return only the `UserInformation` to force calling `redeem` to obtain the `refresh_token`.
pub async fn exchange_code(wrapped_code: &str, conn: &mut DbConn) -> ApiResult<UserInformation> {
    let (code, state) = decode_code_claims(wrapped_code, conn).await?;

    if let Some(authenticated_user) = AC_CACHE.get(&state) {
        return Ok(UserInformation {
            state,
            identifier: authenticated_user.identifier,
            email: authenticated_user.email,
            email_verified: authenticated_user.email_verified,
            user_name: authenticated_user.user_name,
        });
    }

    let oidc_code = AuthorizationCode::new(code.to_string());
    let client = Client::cached().await?;

    let nonce = match SsoNonce::find(&state, conn).await {
        None => err!(format!("Invalid state cannot retrieve nonce")),
        Some(nonce) => nonce,
    };

    let mut exchange = client.core_client.exchange_code(oidc_code);

    if CONFIG.sso_pkce() {
        match nonce.verifier {
            None => err!(format!("Missing verifier in the DB nonce table")),
            Some(secret) => exchange = exchange.set_pkce_verifier(PkceCodeVerifier::new(secret)),
        }
    }

    if CONFIG.sso_debug_force_fail_auth_code() {
        err!(format!("Exhange code {}", code.clone()));
    }

    match exchange.request_async(&client.http_client).await {
        Ok(token_response) => {
            let user_info = client.user_info(token_response.access_token().to_owned()).await?;
            let oidc_nonce = Nonce::new(nonce.nonce.clone());

            let id_token = match token_response.extra_fields().id_token() {
                None => err!("Token response did not contain an id_token"),
                Some(token) => token,
            };

            if CONFIG.sso_debug_tokens() {
                debug!("Id token: {}", id_token.to_string());
                debug!("Access token: {}", token_response.access_token().secret().to_string());
                debug!("Refresh token: {:?}", token_response.refresh_token().map(|t| t.secret().to_string()));
                debug!("Expiration time: {:?}", token_response.expires_in());
            }

            let id_claims = match id_token.claims(&client.vw_id_token_verifier(), &oidc_nonce) {
                Ok(claims) => claims,
                Err(err) => {
                    if CONFIG.sso_client_cache_expiration() > 0 {
                        CLIENT_CACHE.invalidate(&*CLIENT_CACHE_KEY);
                    }
                    err!(format!("Could not read id_token claims, {err}"));
                }
            };

            let email = match id_claims.email() {
                Some(email) => email.to_string(),
                None => match user_info.email() {
                    None => err!("Neither id token nor userinfo contained an email"),
                    Some(email) => email.to_owned().to_string(),
                },
            }
            .to_lowercase();
            let user_name = id_claims.preferred_username().map(|un| un.to_string());

            let additional_claims = additional_claims(&email, &id_token.to_string())?;

            let refresh_token = token_response.refresh_token().map(|t| t.secret().to_string());
            if refresh_token.is_none() && CONFIG.sso_scopes_vec().contains(&"offline_access".to_string()) {
                error!("Scope offline_access is present but response contain no refresh_token");
            }

            let identifier = OIDCIdentifier::new(id_claims.issuer(), id_claims.subject());

            let authenticated_user = AuthenticatedUser {
                refresh_token,
                access_token: token_response.access_token().secret().to_string(),
                expires_in: token_response.expires_in(),
                identifier: identifier.clone(),
                email: email.clone(),
                email_verified: id_claims.email_verified(),
                user_name: user_name.clone(),
                role: additional_claims.role,
                groups: additional_claims.groups,
            };

            AC_CACHE.insert(state.clone(), authenticated_user);

            Ok(UserInformation {
                state,
                identifier,
                email,
                email_verified: id_claims.email_verified(),
                user_name,
            })
        }
        Err(err) => err!(format!("Failed to contact token endpoint: {:?}", err)),
    }
}

// User has passed 2FA flow we can delete `nonce` and clear the cache.
pub async fn redeem(state: &OIDCState, conn: &mut DbConn) -> ApiResult<AuthenticatedUser> {
    if let Err(err) = SsoNonce::delete(state, conn).await {
        error!("Failed to delete database sso_nonce using {state}: {err}")
    }

    if let Some(au) = AC_CACHE.get(state) {
        AC_CACHE.invalidate(state);
        Ok(au)
    } else {
        err!("Failed to retrieve user info from sso cache")
    }
}

// We always return a refresh_token (with no refresh_token some secrets are not displayed in the web front).
// If there is no SSO refresh_token, we keep the access_token to be able to call user_info to check for validity
pub fn create_auth_tokens(
    device: &Device,
    user: &User,
    refresh_token: Option<String>,
    access_token: &str,
    expires_in: Option<Duration>,
) -> ApiResult<AuthTokens> {
    if !CONFIG.sso_auth_only_not_session() {
        let now = Utc::now();

        let (ap_nbf, ap_exp) = match (insecure_decode::<BasicTokenClaims>("access_token", access_token), expires_in) {
            (Ok(ap), _) => (ap.nbf(), ap.exp),
            (Err(_), Some(exp)) => (now.timestamp(), (now + exp).timestamp()),
            _ => err!("Non jwt access_token and empty expires_in"),
        };

        let access_claims = auth::LoginJwtClaims::new(device, user, ap_nbf, ap_exp, AuthMethod::Sso.scope_vec(), now);

        _create_auth_tokens(device, refresh_token, access_claims, access_token)
    } else {
        Ok(AuthTokens::new(device, user, AuthMethod::Sso))
    }
}

fn _create_auth_tokens(
    device: &Device,
    refresh_token: Option<String>,
    access_claims: auth::LoginJwtClaims,
    access_token: &str,
) -> ApiResult<AuthTokens> {
    let (nbf, exp, token) = if let Some(rt) = refresh_token.as_ref() {
        match insecure_decode::<BasicTokenClaims>("refresh_token", rt) {
            Err(_) => {
                let time_now = Utc::now();
                let exp = (time_now + *DEFAULT_REFRESH_VALIDITY).timestamp();
                debug!("Non jwt refresh_token (expiration set to {})", exp);
                (time_now.timestamp(), exp, TokenWrapper::Refresh(rt.to_string()))
            }
            Ok(refresh_payload) => {
                debug!("Refresh_payload: {:?}", refresh_payload);
                (refresh_payload.nbf(), refresh_payload.exp, TokenWrapper::Refresh(rt.to_string()))
            }
        }
    } else {
        debug!("No refresh_token present");
        (access_claims.nbf, access_claims.exp, TokenWrapper::Access(access_token.to_string()))
    };

    let refresh_claims = auth::RefreshJwtClaims {
        nbf,
        exp,
        iss: auth::JWT_LOGIN_ISSUER.to_string(),
        sub: AuthMethod::Sso,
        device_token: device.refresh_token.clone(),
        token: Some(token),
    };

    Ok(AuthTokens {
        refresh_claims,
        access_claims,
    })
}

// This endpoint is called in two case
//  - the session is close to expiration we will try to extend it
//  - the user is going to make an action and we check that the session is still valid
pub async fn exchange_refresh_token(
    device: &Device,
    user: &User,
    refresh_claims: &auth::RefreshJwtClaims,
) -> ApiResult<AuthTokens> {
    match &refresh_claims.token {
        Some(TokenWrapper::Refresh(refresh_token)) => {
            let rt = RefreshToken::new(refresh_token.to_string());

            let client = Client::cached().await?;

            let token_response =
                match client.core_client.exchange_refresh_token(&rt).request_async(&client.http_client).await {
                    Err(err) => err!(format!("Request to exchange_refresh_token endpoint failed: {:?}", err)),
                    Ok(token_response) => token_response,
                };

            // Use new refresh_token if returned
            let rolled_refresh_token = token_response
                .refresh_token()
                .map(|token| token.secret().to_string())
                .unwrap_or(refresh_token.to_string());

            create_auth_tokens(
                device,
                user,
                Some(rolled_refresh_token),
                token_response.access_token().secret(),
                token_response.expires_in(),
            )
        }
        Some(TokenWrapper::Access(access_token)) => {
            let now = Utc::now();
            let exp_limit = (now + *BW_EXPIRATION).timestamp();

            if refresh_claims.exp < exp_limit {
                err_silent!("Access token is close to expiration but we have no refresh token")
            }

            let client = Client::cached().await?;
            match client.user_info(AccessToken::new(access_token.to_string())).await {
                Err(err) => {
                    err_silent!(format!("Failed to retrieve user info, token has probably been invalidated: {err}"))
                }
                Ok(_) => {
                    let access_claims = auth::LoginJwtClaims::new(
                        device,
                        user,
                        now.timestamp(),
                        refresh_claims.exp,
                        AuthMethod::Sso.scope_vec(),
                        now,
                    );
                    _create_auth_tokens(device, None, access_claims, access_token)
                }
            }
        }
        None => err!("No token present while in SSO"),
    }
}

pub async fn sync_groups(
    user: &User,
    device: &Device,
    ip: &ClientIp,
    groups: &Vec<String>,
    conn: &mut DbConn,
) -> ApiResult<()> {
    if CONFIG.sso_organizations_invite() {
        let acting_user = ACTING_AUTO_ENROLL_USER.into();
        let id_mapping = CONFIG.sso_organizations_id_mapping_map();
        let org_collections: Vec<CollectionData> = vec![];
        let org_groups: Vec<GroupId> = vec![];

        let db_user_orgs = Membership::find_any_state_by_user(&user.uuid, conn).await;
        let mut memberships = db_user_orgs.into_iter().map(|m| (m.org_uuid.clone(), m)).collect::<HashMap<_, _>>();

        let orgs = if id_mapping.is_empty() {
            Organization::find_by_uuids_or_names(&vec![], groups, conn).await
        } else {
            use itertools::Itertools;

            let (names, uuids) = groups
                .iter()
                .flat_map(|group| match id_mapping.get(group) {
                    Some(e) => Some(e.clone()),
                    None => {
                        warn!("Missing organization mapping for {group}");
                        None
                    }
                })
                .partition_map(std::convert::identity);

            Organization::find_by_uuids_or_names(&uuids, &names, conn).await
        };

        for org in &orgs {
            if let Some((_, m)) = memberships.remove_entry(&org.uuid) {
                if m.is_revoked() {
                    drop(organization_logic::restore_member(&acting_user, device, ip, m, conn).await);
                }
            } else {
                info!("Invitation to {} organization sent to {}", org.name, user.email);
                organization_logic::invite(
                    &acting_user,
                    device,
                    ip,
                    org,
                    user,
                    MembershipType::User,
                    &org_groups,
                    CONFIG.sso_organizations_all_collections(),
                    &org_collections,
                    org.billing_email.clone(),
                    true,
                    conn,
                )
                .await?;
            };
        }

        if CONFIG.sso_organizations_revocation() {
            if groups.len() == orgs.len() {
                let org_mapped: HashSet<&OrganizationId> = orgs.iter().map(|o| &o.uuid).collect();
                for m in memberships.into_values() {
                    if id_mapping.is_empty() || org_mapped.contains(&m.org_uuid) {
                        drop(organization_logic::revoke_member(&acting_user, device, ip, m, conn).await);
                    }
                }
            } else {
                let org_names: Vec<String> = orgs.into_iter().map(|o| o.name).collect();
                warn!(
                    "Failed to match all groups ({:?}) to organizations ({:?}) with mapping ({:?}), will not revoke",
                    groups, org_names, id_mapping
                );
            }
        }
    }

    Ok(())
}
