import { test, expect, type TestInfo } from '@playwright/test';
import { logNewUser, logUser } from './setups/sso';
import * as utils from "../global-utils";

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: false
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Account creation using SSO', async ({ page }) => {
    // Landing page
    await logNewUser(test, page, users.user1);
});

test('SSO login', async ({ page }) => {
    await logUser(test, page, users.user1);
});

test('Non SSO login', async ({ page }) => {
    // Landing page
    await page.goto('/');
    await page.getByLabel(/Email address/).fill(users.user1.email);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill(users.user1.password);
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaults/);
});


test('Non SSO login Failure', async ({ page, browser }, testInfo: TestInfo) => {
    await utils.restartVault(page, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: true
    }, false);

    // Landing page
    await page.goto('/');
    await page.getByLabel(/Email address/).fill(users.user1.email);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill(users.user1.password);
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // An error should appear
    await page.getByLabel('SSO sign-in is required')
});

test('SSO login Failure', async ({ page }, testInfo: TestInfo) => {
    await utils.restartVault(page, testInfo, {
        SSO_ENABLED: false,
    }, false);

    // Landing page
    await page.goto('/');
    await page.getByLabel(/Email address/).fill(users.user1.email);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByRole('link', { name: /Enterprise single sign-on/ }).click();

    // SSO identifier page
    await page.getByRole('button', { name: 'Log in' }).click();

    // An error should appear
    await page.getByLabel('SSO sign-in is not available')
});
