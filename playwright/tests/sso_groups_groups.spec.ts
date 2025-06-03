import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
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
        ORG_GROUPS_ENABLED: true,
        SSO_ENABLED: true,
        SSO_ONLY: true,
        SSO_ORGANIZATIONS_ENABLED: true,
        SSO_ORGANIZATIONS_GROUPS_ENABLED: true,
        SSO_SCOPES: "email profile groups",
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.PW_SMTP_FROM,
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    mailServer?.close();
});

test('User auto invite', async ({ context, page }) => {
    await logNewUser(test, page, users.user2);
});
