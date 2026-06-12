import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import * as orgs from './setups/orgs';
import { logNewUser, logUser } from './setups/sso';

let users = utils.loadEnv();

let mailServer, mail1Buffer, mail2Buffer, mail3Buffer;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailServer = new MailDev({
        port: process.env.MAILDEV_SMTP_PORT,
        web: { port: process.env.MAILDEV_HTTP_PORT },
    })

    await mailServer.listen();

    await utils.startVault(browser, testInfo, {
        ORGANIZATION_INVITE_AUTO_ACCEPT: true,
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.PW_SMTP_FROM,
        SSO_ENABLED: true,
        SSO_ONLY: true,
        SSO_FRONTEND: "override",
    });

    mail1Buffer = mailServer.buffer(users.user1.email);
    mail2Buffer = mailServer.buffer(users.user2.email);
    mail3Buffer = mailServer.buffer(users.user3.email);
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    [mail1Buffer, mail2Buffer, mail3Buffer, mailServer].map((m) => m?.close());
});

test('Org invite auto accept', async ({ page }, testInfo: TestInfo) => {
    await logNewUser(test, page, users.user2, { mailBuffer: mail2Buffer, override: true });
    await logNewUser(test, page, users.user1, { mailBuffer: mail1Buffer, override: true });

    await orgs.create(test, page, '/Test');
    await orgs.members(test, page, '/Test');

    await test.step('Invite existing user', async () => {
        await orgs.invite(test, page, '/Test', users.user2.email);
        await expect(page.getByRole('row', { name: users.user2.email })).toHaveText(/Needs confirmation/);
        await  mail2Buffer.expect((m) => m.subject === "Enrolled in /Test");
    });

    await test.step('Confirm user', async () => {
        await orgs.confirm(test, page, '/Test', users.user2.name, users.user2.email);
    });

    await test.step('Invite existing user', async () => {
        await orgs.invite(test, page, '/Test', users.user3.email);
        await expect(page.getByRole('row', { name: users.user3.email })).toHaveText(/Invited/);
        await  mail3Buffer.expect((m) => m.subject === "Join /Test");
    });
});
