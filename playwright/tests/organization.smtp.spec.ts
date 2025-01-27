import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import * as orgs from './setups/orgs';
import { createAccount, logUser } from './setups/user';

let users = utils.loadEnv();

let mailserver, user1Mails, user2Mails, user3Mails;

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

    user1Mails = mailserver.iterator(users.user1.email);
    user2Mails = mailserver.iterator(users.user2.email);
    user3Mails = mailserver.iterator(users.user3.email);
});

test.afterAll('Teardown', async ({}, testInfo: TestInfo) => {
    utils.stopVault(testInfo);
    utils.closeMails(mailserver, [user1Mails, user2Mails, user3Mails]);
});

test('Create user3', async ({ page }) => {
    await createAccount(test, page, users.user3, user3Mails);
});

test('Invite users', async ({ page }) => {
    await createAccount(test, page, users.user1, user1Mails);
    await logUser(test, page, users.user1, user1Mails);

    await orgs.create(test, page, "Test");
    await orgs.members(test, page, "Test");
    await orgs.invite(test, page, "Test", users.user2.email);
    await orgs.invite(test, page, "Test", users.user3.email, {
        navigate: false,
    });
});

test('invited with new account', async ({ page }) => {
    const { value: invited } = await user2Mails.next();
    expect(invited.subject).toContain("Join Test")

    await test.step('Create account', async () => {
        await page.setContent(invited.html);
        const link = await page.getByTestId("invite").getAttribute("href");
        await page.goto(link);
        await expect(page).toHaveTitle(/Create account | OIDCWarden Web/);

        await page.getByLabel('Name').fill(users.user2.name);
        await page.getByLabel('Master password\n   (required)', { exact: true }).fill(users.user2.password);
        await page.getByLabel('Re-type master password').fill(users.user2.password);
        await page.getByRole('button', { name: 'Create account' }).click();

        // Back to the login page
        await expect(page).toHaveTitle('OIDCWarden Web');
        await expect(page.getByTestId("toast-message")).toHaveText(/Your new account has been created/);
        await page.locator('#toast-container').getByRole('button').click();

        const { value: welcome } = await user2Mails.next();
        expect(welcome.subject).toContain("Welcome")
    });

    await test.step('Login', async () => {
        await page.getByLabel(/Email address/).fill(users.user2.email);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Unlock page
        await page.getByLabel('Master password').fill(users.user2.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        // We are now in the default vault page
        await expect(page).toHaveTitle(/Vaults/);
        await expect(page.getByTestId("toast-title")).toHaveText("Invitation accepted");
        await page.locator('#toast-container').getByRole('button').click();

        const { value: logged } = await user2Mails.next();
        expect(logged.subject).toContain("New Device Logged");
    });

    const { value: accepted } = await user1Mails.next();
    expect(accepted.subject).toContain("Invitation to Test accepted")
});

test('invited with existing account', async ({ page }) => {
    const { value: invited } = await user3Mails.next();
    expect(invited.subject).toContain("Join Test")

    await page.setContent(invited.html);
    const link = await page.getByTestId("invite").getAttribute("href");

    await page.goto(link);

    // We should be on login page with email prefilled
    await expect(page).toHaveTitle(/OIDCWarden Web/);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill(users.user3.password);
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/OIDCWarden Web/);
    await expect(page.getByTestId("toast-title")).toHaveText("Invitation accepted");
    await page.locator('#toast-container').getByRole('button').click();

    const { value: logged } = await user3Mails.next();
    expect(logged.subject).toContain("New Device Logged")

    const { value: accepted } = await user1Mails.next();
    expect(accepted.subject).toContain("Invitation to Test accepted")
});

test('Confirm invited user', async ({ page }) => {
    await logUser(test, page, users.user1, user1Mails);

    await orgs.members(test, page, "Test");
    await orgs.confirm(test, page, "Test", users.user2.name);

    await test.step('Check user2 mail', async () => {
        const { value: logged } = await user2Mails.next();
        expect(logged.subject).toContain("Invitation to Test confirmed");
    });
});

test('Organization is visible', async ({ page }) => {
    await logUser(test, page, users.user2, user2Mails);
    await page.getByLabel('vault: Test').click();
    await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
});
