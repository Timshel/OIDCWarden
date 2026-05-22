//! `UserDecryptionOptions` (login) and `userDecryption` (sync) payloads for Bitwarden-compatible clients.
//!
//! References: Bitwarden `UserDecryptionOptionsBuilder`, `TrustedDeviceUserDecryptionOption`, and
//! `libs/common/.../user-decryption-options.response.ts` in bitwarden/clients.

use serde_json::{Value, json};

use crate::CONFIG;
use crate::db::DbConn;
use crate::db::models::{Device, SsoUser, User};

pub async fn build_sync_user_decryption(user: &User, device: &Device, conn: &DbConn) -> Value {
    let with_trusted =
        CONFIG.sso_enabled() && (CONFIG.sso_only() || SsoUser::find_by_user(&user.uuid, conn).await.is_some());
    build_token_user_decryption_options(user, device, with_trusted)
}

//  Bitwarden only builds trusted-device options when SSO Identity context exists (authorization_code grant).
pub fn build_token_user_decryption_options(user: &User, device: &Device, with_trusted: bool) -> Value {
    let has_master_password = !user.password_hash.is_empty();
    let master_password_unlock = if has_master_password {
        json!({
            "kdf": {
                "kdfType": user.client_kdf_type,
                "iterations": user.client_kdf_iter,
                "memory": user.client_kdf_memory,
                "parallelism": user.client_kdf_parallelism
            },
            "masterKeyEncryptedUserKey": user.akey,
            "masterKeyWrappedUserKey": user.akey,
            "salt": user.email
        })
    } else {
        Value::Null
    };

    let mut out = json!({
        "hasMasterPassword": has_master_password,
        "masterPasswordUnlock": master_password_unlock,
        "object": "userDecryptionOptions"
    });

    if with_trusted {
        let is_tde_active = CONFIG.sso_trusted_device_encryption();
        let is_tde_offboarding = !has_master_password && device.is_trusted() && !is_tde_active;

        if is_tde_active || is_tde_offboarding {
            let mut trusted = json!({
                "hasAdminApproval": has_master_password,
                "hasLoginApprovingDevice": device.can_approve_trusted_login(),
                "hasManageResetPasswordPermission": true,
                "isTdeOffboarding": is_tde_offboarding,
            });

            device.encrypted_user_key.as_ref().map(|key| {
                trusted["encryptedUserKey"] = json!(key);
                trusted["EncryptedUserKey"] = json!(key);
            });
            device.encrypted_private_key.as_ref().map(|key| {
                trusted["encryptedPrivateKey"] = json!(key);
                trusted["EncryptedPrivateKey"] = json!(key);
            });

            out["trustedDeviceOption"] = trusted.clone();
            out["TrustedDeviceOption"] = trusted;
        }
    }

    out
}
