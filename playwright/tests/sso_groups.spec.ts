import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import { logNewUser, logUser } from './setups/sso';

let users = utils.loadEnv();

let mailServer;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailServer = new MailDev({
        port: process.env.MAILDEV_SMTP_PORT,
        web: { port: process.env.MAILDEV_HTTP_PORT },
    })

    await mailServer.listen();

    await utils.startVaultwarden(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: true,
        SSO_ORGANIZATIONS_INVITE: true,
        SSO_SCOPES: "email profile groups",
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.VAULTWARDEN_SMTP_FROM,
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVaultwarden();
    mailServer?.close();
});

test('User auto invite', async ({ context, page }) => {
    let mail2Buffer = mailServer.buffer(users.user2.email);
    try {
        await logNewUser(test, page, users.user1);

        await test.step('Create Org', async () => {
            await page.getByRole('link', { name: 'New organisation' }).click();
            await page.getByLabel('Organisation name (required)').fill('Test');
            await page.getByRole('button', { name: 'Submit' }).click();
            await page.locator('div').filter({ hasText: 'Members' }).nth(2).click();
        });

        await test.step('Log user2 and receive invite', async () => {
            await context.clearCookies();
            await logNewUser(test, page, users.user2, { mailBuffer: mail2Buffer });
            await expect(mail2Buffer.next((m) => m.subject === "Join Test")).resolves.toBeDefined();
        });
    } finally {
        mail2Buffer.close();
    }
});

test('Org invite auto accept', async ({ context, page }, testInfo: TestInfo) => {
    test.setTimeout(40000);
    let mail1Buffer = mailServer.buffer(users.user1.email);
    let mail2Buffer = mailServer.buffer(users.user2.email);
    try {
        await utils.restartVaultwarden(page, testInfo, {
            ORGANIZATION_INVITE_AUTO_ACCEPT: true,
            SMTP_FROM: process.env.VAULTWARDEN_SMTP_FROM,
            SMTP_HOST: process.env.MAILDEV_HOST,
            SSO_ENABLED: true,
            SSO_FRONTEND: "override",
            SSO_ONLY: true,
            SSO_ORGANIZATIONS_INVITE: true,
            SSO_SCOPES: "email profile groups",
        }, true);

        await logNewUser(test, page, users.user1, { mailBuffer: mail1Buffer, override: true });

        await test.step('Create Org', async () => {
            await page.getByRole('link', { name: 'New organisation' }).click();
            await page.getByLabel('Organisation name (required)').fill('Test');
            await page.getByRole('button', { name: 'Submit' }).click();
            await page.locator('div').filter({ hasText: 'Members' }).nth(2).click();
        });

        await test.step('Invite user2', async () => {
            await context.clearCookies();
            await logNewUser(test, page, users.user2, { mailBuffer: mail2Buffer, override: true });

            await expect(mail2Buffer.next((m) => m.subject === "Enrolled in Test")).resolves.toBeDefined();
            await expect(mail1Buffer.next((m) => m.subject === "Invitation to Test accepted")).resolves.toBeDefined();
        });
    } finally {
        mail1Buffer.close();
        mail2Buffer.close();
    }
});
