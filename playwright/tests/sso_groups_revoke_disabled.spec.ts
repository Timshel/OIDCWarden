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
        SSO_AUTH_ONLY_NOT_SESSION: true,
        SSO_ORGANIZATIONS_ENABLED: true,
        SSO_ORGANIZATIONS_REVOCATION: true,
        SSO_SCOPES: "email profile groups",
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    mailServer?.close();
});

test('No revocation', async ({ context, page }, testInfo: TestInfo) => {
    await test.step('Setup', async () => {
        await logNewUser(test, page, users.user2);
        await logNewUser(test, page, users.user1);

        await orgs.create(test, page, 'Toto');
        await orgs.members(test, page, 'Toto');
        await orgs.invite(test, page, 'Toto', users.user2.email);
        await orgs.confirm(test, page, 'Toto', users.user2.email);
    });

    await test.step('Check user2', async () => {
        await logUser(test, page, users.user2);
        await expect(page.getByRole('button', { name: 'vault: Toto', exact: true })).toBeVisible();
    });
});
