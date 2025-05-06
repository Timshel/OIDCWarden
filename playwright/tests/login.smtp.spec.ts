import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

const utils = require('../global-utils');
import { createAccount, logUser } from './setups/user';

let users = utils.loadEnv();

let mailserver;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailserver = new MailDev({
        port: process.env.MAILDEV_SMTP_PORT,
        web: { port: process.env.MAILDEV_HTTP_PORT },
    })

    await mailserver.listen();

    await utils.startVault(browser, testInfo, {
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.PW_SMTP_FROM,
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    if( mailserver ){
        await mailserver.close();
    }
});

test('Account creation', async ({ page }) => {
    const mailBuffer = mailserver.buffer(users.user1.email);

    await createAccount(test, page, users.user1, mailBuffer);

    mailBuffer.close();
});

test('Login', async ({ context, page }) => {
    const mailBuffer = mailserver.buffer(users.user1.email);

    await logUser(test, page, users.user1, mailBuffer);

    await test.step('verify email', async () => {
        await page.getByRole('button', { name: "Send email" }).click();
        await utils.checkNotification(page, 'Check your email inbox for a verification link');

        const verify = await mailBuffer.next((m) => m.subject === "Verify Your Email");
        expect(verify.from[0]?.address).toBe(process.env.PW_SMTP_FROM);

        const page2 = await context.newPage();
        await page2.setContent(verify.html);
        const link = await page2.getByTestId("verify").getAttribute("href");
        await page2.close();

        await page.goto(link);
        await utils.checkNotification(page, 'Account email verified');
    });

    mailBuffer.close();
});

test('Activaite 2fa', async ({ context, page }) => {
    const emails = mailserver.buffer(users.user1.email);

    await logUser(test, page, users.user1);

    await test.step('activate', async () => {
        await page.getByRole('button', { name: users.user1.name }).click();
        await page.getByRole('menuitem', { name: 'Account settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Two-step login' }).click();
        await page.locator('bit-item').filter({ hasText: 'Email Email Enter a code sent' }).getByRole('button').click();
        await page.getByLabel('Master password (required)').fill(users.user1.password);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByRole('button', { name: 'Send email' }).click();
    });

    const code = await test.step('retrieve code', async () => {
        const codeMail = await emails.next((mail) => mail.subject.includes("Login Verification Code"));
        const page2 = await context.newPage();
        await page2.setContent(codeMail.html);
        const code = await page2.getByTestId("2fa").innerText();
        await page2.close();
        return code;
    });

    await test.step('input code', async () => {
        await page.getByLabel('2. Enter the resulting 6').fill(code);
        await page.getByRole('button', { name: 'Turn on' }).click();
        await page.getByRole('heading', { name: 'Turned on', exact: true });
    });

    emails.close();
});

test('2fa', async ({ context, page }) => {
    const emails = mailserver.buffer(users.user1.email);

    await test.step('login', async () => {
        await page.goto('/');

        await page.getByLabel(/Email address/).fill(users.user1.email);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByLabel('Master password').fill(users.user1.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        const codeMail = await emails.next((mail) => mail.subject.includes("Login Verification Code"));
        const page2 = await context.newPage();
        await page2.setContent(codeMail.html);
        const code = await page2.getByTestId("2fa").innerText();
        await page2.close();

        await page.getByLabel(/Verification code/).fill(code);
        await page.getByRole('button', { name: 'Continue' }).click();

        await expect(page).toHaveTitle(/Vaults/);
    })

    await test.step('disable', async () => {
        await page.getByRole('button', { name: 'Test' }).click();
        await page.getByRole('menuitem', { name: 'Account settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Two-step login' }).click();
        await page.locator('bit-item').filter({ hasText: 'Email' }).getByRole('button').click();
        await page.getByLabel('Master password (required)').click();
        await page.getByLabel('Master password (required)').fill(users.user1.password);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByRole('button', { name: 'Turn off' }).click();
        await page.getByRole('button', { name: 'Yes' }).click();

        await utils.checkNotification(page, 'Two-step login provider turned off');
    });

    emails.close();
});
