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
        ORGANIZATION_INVITE_AUTO_ACCEPT: true,
        SMTP_FROM: process.env.PW_SMTP_FROM,
        SMTP_HOST: process.env.MAILDEV_HOST,
        SSO_ENABLED: true,
        SSO_FRONTEND: "override",
        SSO_ONLY: true,
        SSO_ORGANIZATIONS_ENABLED: true,
        SSO_SCOPES: "email profile groups",
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    mailServer?.close();
});

test('Org invite auto accept', async ({ context, page }, testInfo: TestInfo) => {
    let mail1Buffer = mailServer.buffer(users.user1.email);
    let mail2Buffer = mailServer.buffer(users.user2.email);
    let mail3Buffer = mailServer.buffer(users.user3.email);

    try {
        await logNewUser(test, page, users.user2, { mailBuffer: mail2Buffer, override: true });
        await logNewUser(test, page, users.user1, { mailBuffer: mail1Buffer, override: true });
        await orgs.create(test, page, '/All');

        await test.step('Invited existing user2', async () => {
            await logUser(test, page, users.user2, { mailBuffer: mail2Buffer, override: true, notNewDevice: true });

            await mail2Buffer.expect((m) => m.subject === "Enrolled in /All");
            expect(mail2Buffer.find((m) => m.subject === "Join /All")).toBeUndefined();
            await mail1Buffer.expect((m) => m.subject === "Invitation to /All accepted");
        });

        await test.step('Invited new user3', async () => {
            await logNewUser(test, page, users.user3, { mailBuffer: mail3Buffer, override: true });

            await mail3Buffer.expect((m) => m.subject === "Enrolled in /All");
            expect(mail3Buffer.find((m) => m.subject === "Join /All")).toBeUndefined();
            await mail1Buffer.expect((m) => m.subject === "Invitation to /All accepted");
        });
    } finally {
        mail1Buffer.close();
        mail2Buffer.close();
        mail3Buffer.close();
    }
});
