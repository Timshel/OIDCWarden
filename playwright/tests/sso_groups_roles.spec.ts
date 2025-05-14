import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from '../global-utils';
import * as orgs from './setups/orgs';
import { logNewUser, logUser } from './setups/sso';

let users = utils.loadEnv();

let mailServer;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailServer = new MailDev({
        port: process.env.MAILDEV_SMTP_PORT,
        web: { port: process.env.MAILDEV_HTTP_PORT },
    })

    await mailServer.listen();

    await utils.startVault(browser, testInfo, {
        ORGANIZATION_INVITE_AUTO_ACCEPT: true,
        SMTP_FROM: process.env.PW_SMTP_FROM,
        SMTP_HOST: process.env.MAILDEV_HOST,
        SSO_ENABLED: true,
        SSO_ONLY: true,
        SSO_ORGANIZATIONS_INVITE: true,
        SSO_ORGANIZATIONS_ALL_COLLECTIONS: false,
        SSO_SCOPES: "email profile groups roles",
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    mailServer?.close();
});

test('Roles', async ({ context, page }, testInfo: TestInfo) => {
    await test.step('Setup', async () => {
        await logNewUser(test, page, users.user1);
        await orgs.create(test, page, '/All');
    });

    await test.step('Log users', async () => {
        await logNewUser(test, page, users.user2);
        await logNewUser(test, page, users.user3);
        await logNewUser(test, page, users.user4);
        await logNewUser(test, page, users.user5);
    });

    await test.step('Check', async () => {
        await logUser(test, page, users.user1);
        await orgs.members(test, page, '/All');
        await orgs.checkRole(test, page, '/All', users.user1.email, 'Owner');

        await orgs.checkRole(test, page, '/All', users.user2.email, 'Owner');
        await orgs.checkRole(test, page, '/All', users.user3.email, 'Admin');
        await orgs.checkRole(test, page, '/All', users.user4.email, 'Custom');
        await orgs.checkRole(test, page, '/All', users.user5.email, 'User');
    });

    await test.step('Confirm', async () => {
        await orgs.confirm(test, page, '/All', users.user2.email);
        await orgs.confirm(test, page, '/All', users.user3.email);
        await orgs.confirm(test, page, '/All', users.user4.email);
        await orgs.confirm(test, page, '/All', users.user5.email);
    });

    await test.step('Change role', async () => {
        await orgs.setRole(test, page, '/All', users.user2.email, 'User');
        await orgs.setRole(test, page, '/All', users.user3.email, 'Custom');
        await orgs.setRole(test, page, '/All', users.user4.email, 'Admin');
        await orgs.setRole(test, page, '/All', users.user5.email, 'Owner');
    });

    await test.step('Check User2', async () => {
        await logUser(test, page, users.user2);
        await page.getByRole('button', { name: 'vault: /All', exact: true }).click();
        await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
    });

    await test.step('Check User3', async () => {
        await logUser(test, page, users.user3);
        await page.getByRole('button', { name: 'vault: /All', exact: true }).click();
        await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
    });

    await test.step('Check User4', async () => {
        await logUser(test, page, users.user4);
        await page.getByRole('button', { name: 'vault: /All', exact: true }).click();
        await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
    });

    await test.step('Check User5', async () => {
        await logUser(test, page, users.user5);
        await page.getByRole('button', { name: 'vault: /All', exact: true }).click();
        await expect(page.getByLabel('Filter: Default collection')).toHaveCount(0);
    });

    await test.step('Check again', async () => {
        await logUser(test, page, users.user1);
        await orgs.members(test, page, '/All');
        await orgs.checkRole(test, page, '/All', users.user2.email, 'Owner');
        await orgs.checkRole(test, page, '/All', users.user3.email, 'Admin');
        await orgs.checkRole(test, page, '/All', users.user4.email, 'Custom');
        await orgs.checkRole(test, page, '/All', users.user5.email, 'User');
    });
});
