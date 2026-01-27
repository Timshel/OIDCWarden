import { expect, type Browser,Page } from '@playwright/test';

import * as utils from '../../global-utils';

export async function create(test, page: Page, name: string) {
    await test.step(`Create Org ${name}`, async () => {
        await page.locator('a').filter({ hasText: 'Password Manager' }).first().click();
        await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();
        await page.getByRole('link', { name: 'New organisation' }).click();
        await page.getByLabel('Organisation name (required)').fill(name);
        await page.getByRole('button', { name: 'Submit' }).click();

        await utils.checkNotification(page, 'Organisation created');
    });
}

export async function infos(test, page: Page, name: string) {
    await test.step(`Navigate to ${name} org infos`, async () => {
        await page.locator('a').filter({ hasText: 'Admin Console' }).first().click();
        await page.locator('org-switcher').getByLabel(/Toggle collapse/).click();
        await page.locator('org-switcher').getByRole('link', { name: `${name}` }).first().click();
        await expect(page.getByRole('heading', { name: `${name} collections` })).toBeVisible();
        await page.getByRole('button', { name: 'Toggle collapse Settings' }).click();
        await page.getByRole('link', { name: 'Organisation info' }).click();
        await expect(page.getByRole('heading', { name: 'Organisation info' })).toBeVisible();
    });
}

export async function externalID(test, page: Page, name: string, externalID: string) {
    await test.step(`Set ${name} externalID ${externalID}`, async () => {
        await expect(page.getByRole('heading', { name: 'Organisation info' })).toBeVisible();
        await page.getByRole('textbox', { name: 'External ID' }).fill(externalID);
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'Organisation saved');
    });
}

export async function policies(test, page: Page, name: string) {
    await test.step(`Navigate to ${name} policies`, async () => {
        await page.locator('a').filter({ hasText: 'Admin Console' }).first().click();
        await page.locator('org-switcher').getByLabel(/Toggle collapse/).click();
        await page.locator('org-switcher').getByRole('link', { name: `${name}` }).first().click();
        await expect(page.getByRole('heading', { name: `${name} collections` })).toBeVisible();
        await page.getByRole('button', { name: 'Toggle collapse Settings' }).click();
        await page.getByRole('link', { name: 'Policies' }).click();
        await expect(page.getByRole('heading', { name: 'Policies' })).toBeVisible();
    });
}

export async function members(test, page: Page, name: string) {
    await test.step(`Navigate to ${name} members`, async () => {
        await page.locator('a').filter({ hasText: 'Admin Console' }).first().click();
        await page.locator('org-switcher').getByLabel(/Toggle collapse/).click();
        await page.locator('org-switcher').getByRole('link', { name: `${name}` }).first().click();
        await expect(page.getByRole('heading', { name: `${name} collections` })).toBeVisible();
        await page.getByRole('link', { name: 'Members' }).click();
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await expect(page.getByRole('cell', { name: 'All' })).toBeVisible();
    });
}

export async function invite(test, page: Page, name: string, email: string) {
    await test.step(`Invite ${email}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await page.getByRole('button', { name: 'Invite member' }).click();
        await page.getByLabel('Email (required)').fill(email);
        await page.getByRole('tab', { name: 'Collections' }).click();
        await page.getByRole('combobox', { name: 'Permission' }).click();
        await page.getByText('Edit items', { exact: true }).click();
        await page.getByLabel('Select collections').click();
        await page.getByText('Default collection').click();
        await page.getByRole('cell', { name: 'Collection', exact: true }).click();
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'User(s) invited');
    });
}

export async function confirm(test, page: Page, name: string, user_email: string) {
    await test.step(`Confirm ${user_email}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await page.getByRole('row').filter({hasText: user_email}).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Confirm' }).click();
        await expect(page.getByRole('heading', { name: 'Confirm user' })).toBeVisible();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await utils.checkNotification(page, 'confirmed');
    });
}

export async function revoke(test, page: Page, name: string, user_email: string) {
    await test.step(`Revoke ${user_email}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await page.getByRole('row').filter({hasText: user_email}).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Revoke access' }).click();
        await expect(page.getByRole('heading', { name: 'Revoke access' })).toBeVisible();
        await page.getByRole('button', { name: 'Revoke access' }).click();
        await utils.checkNotification(page, 'Revoked organisation access');
    });
}

export async function checkRole(test, page: Page, name: string, user_email: string, role: string) {
    await test.step(`Check ${user_email} role ${role}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await expect(page.getByRole('row').filter({hasText: user_email}).getByRole('cell', { name: role })).toBeVisible();
    });
}

export async function checkGroup(test, page: Page, name: string, user_email: string, group_name: string, isVisible: boolean = true) {
    await test.step(`Check ${user_email} group ${group_name}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await expect(page.getByRole('row').filter({hasText: user_email}).getByRole('cell', { name: group_name })).toHaveCount(isVisible === true ? 1 : 0);
    });
}

export async function setRole(test, page: Page, name: string, user_email: string, role: string) {
    await test.step(`SetRole ${user_email}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await page.getByRole('row').filter({hasText: user_email}).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Member role' }).click();
        await expect(page.getByRole('heading', { name: 'Edit Member' })).toBeVisible();
        await page.getByRole('radio', { name: role }).click();

        if( role === 'Custom' ){
            await page.getByRole('checkbox', { name: 'Manage all collections' }).click();
        }

        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'Edited user');
    });
}

export async function groups(test, page: Page, name: string) {
    await test.step(`Navigate to ${name} groups`, async () => {
        await page.locator('a').filter({ hasText: 'Admin Console' }).first().click();
        await page.locator('org-switcher').getByLabel(/Toggle collapse/).click();
        await page.locator('org-switcher').getByRole('link', { name: `${name}` }).first().click();
        await expect(page.getByRole('heading', { name: `${name} collections` })).toBeVisible();
        await page.getByRole('link', { name: 'Groups' }).click();
        await expect(page.getByRole('heading', { name: 'Groups' })).toBeVisible();
    });
}

export async function createGroup(test, page: Page, name: string, group_name: string, group_id?: string) {
    await test.step(`Create group ${name}/${group_name} `, async () => {
        await page.getByRole('button', { name: 'New group' }).click();
        await page.getByRole('textbox', { name: 'Name (required)' }).fill(group_name);

        if( group_id !== undefined ) {
            await page.getByRole('textbox', { name: 'External ID' }).fill(group_id);
        }

        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, `Created group ${group_name}`);
    });
}

export async function addToGroup(test, page: Page, name: string, group_name: string, email: string) {
    await test.step(`add ${email} to group ${group_name}`, async () => {
        await expect(page.getByRole('heading', { name: 'Groups' })).toBeVisible();

        await page.getByRole('row').filter({hasText: group_name}).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Members' }).click();

        await page.getByRole('combobox', { name: 'Select members' }).click();
        await page.getByText(email).click();
        await page.locator('.ng-arrow-wrapper').click();

        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, `Edited group ${group_name}`);
    });
}
