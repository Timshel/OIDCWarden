use crate::{
    api::{core::log_event, core::organizations::CollectionData, ApiResult},
    auth::ClientIp,
    db::models::*,
    db::DbConn,
    mail, CONFIG,
};

#[allow(clippy::too_many_arguments)]
pub async fn invite(
    user: &User,
    device: &Device,
    ip: &ClientIp,
    org: &Organization,
    user_org_type: UserOrgType,
    groups: &Vec<String>,
    access_all: bool,
    collections: &Vec<CollectionData>,
    invited_by_email: String,
    conn: &mut DbConn,
) -> ApiResult<()> {
    let mut user_org_status = UserOrgStatus::Invited;

    // automatically accept existing users if mail is disabled
    if !user.password_hash.is_empty() && !CONFIG.mail_enabled() {
        user_org_status = UserOrgStatus::Accepted;
    }

    let mut new_uo = UserOrganization::new(user.uuid.clone(), org.uuid.clone(), Some(invited_by_email.clone()));
    new_uo.access_all = access_all;
    new_uo.atype = user_org_type as i32;
    new_uo.status = user_org_status as i32;

    // If no accessAll, add the collections received
    if !access_all {
        for col in collections {
            match Collection::find_by_uuid_and_org(&col.id, &org.uuid, conn).await {
                None => err!("Collection not found in Organization"),
                Some(collection) => {
                    CollectionUser::save(&user.uuid, &collection.uuid, col.read_only, col.hide_passwords, conn).await?;
                }
            }
        }
    }

    new_uo.save(conn).await?;

    for group in groups {
        let mut group_entry = GroupUser::new(group.clone(), user.uuid.clone());
        group_entry.save(conn).await?;
    }

    log_event(
        EventType::OrganizationUserInvited as i32,
        &new_uo.uuid,
        &org.uuid,
        &user.uuid,
        device.atype,
        &ip.ip,
        conn,
    )
    .await;

    if CONFIG.mail_enabled() {
        match user_org_status {
            UserOrgStatus::Invited => {
                mail::send_invite(
                    user,
                    Some(org.uuid.clone()),
                    Some(new_uo.uuid),
                    &org.name,
                    new_uo.invited_by_email.clone(),
                )
                .await?
            }
            UserOrgStatus::Accepted => mail::send_invite_accepted(&user.email, &invited_by_email, &org.name).await?,
            UserOrgStatus::Revoked | UserOrgStatus::Confirmed => (),
        }
    }

    Ok(())
}
