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
        SSO_ORGANIZATIONS_REVOCATION: true,
        SSO_SCOPES: "email profile groups",
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.PW_SMTP_FROM,
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    mailServer?.close();
});

test('Groups', async ({ context, page }, testInfo: TestInfo) => {
    await test.step('Setup', async () => {
        await logNewUser(test, page, users.user1);

        await orgs.create(test, page, 'Test');
        await orgs.infos(test, page, 'Test');
        await orgs.externalID(test, page, 'Test', 'All');

        await orgs.groups(test, page, 'Test');
        await orgs.createGroup(test, page, 'Test', 'Group1');
        await orgs.createGroup(test, page, 'Test', 'GroupExtId', 'SubGroup1');
    });

    await test.step('Log users', async () => {
        await logNewUser(test, page, users.user2);
        await logNewUser(test, page, users.user3);
        await logNewUser(test, page, users.user4);
        await logNewUser(test, page, users.user5);
    });

    await test.step('Check', async () => {
        await logUser(test, page, users.user1);
        await orgs.members(test, page, 'Test');
        await orgs.checkGroup(test, page, 'Test', users.user2.email, 'Group1');
        await orgs.checkGroup(test, page, 'Test', users.user3.email, 'Group1');
        await orgs.checkGroup(test, page, 'Test', users.user4.email, 'GroupExtId');
    });

    await test.step('Manually add user', async () => {
        await logUser(test, page, users.user1);
        await orgs.groups(test, page, 'Test');
        await orgs.addToGroup(test, page, 'Test', 'Group1', users.user5.email);

        await orgs.members(test, page, 'Test');
        await orgs.checkGroup(test, page, 'Test', users.user5.email, 'Group1');
    });

    await test.step('Log users', async () => {
        await logUser(test, page, users.user5);
    });

    await test.step('Revoked', async () => {
        await logUser(test, page, users.user1);
        await orgs.members(test, page, 'Test');
        await orgs.checkGroup(test, page, 'Test', users.user5.email, 'Group1', false);
    });
});

