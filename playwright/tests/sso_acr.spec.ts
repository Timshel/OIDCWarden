import { test, expect, type TestInfo } from '@playwright/test';

import { logNewUser, logUser } from './setups/sso';
import { activateTOTP, disableTOTP } from './setups/2fa';
import * as utils from "../global-utils";

let users = utils.loadEnv();

test.afterEach(async ({}) => {
    utils.stopVault();
});

test('SSO login', async ({ browser, page }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: false,
        SSO_ACR_MIN: "3,2,1"
    });

    await logNewUser(test, page, users.user1);
});


test('Insuficient ACR', async ({ browser, page }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: false,
        SSO_ACR_MIN: "3,2"
    }, false);

    await test.step('Landing page', async () => {
        await utils.cleanLanding(page);
        await page.getByLabel(/Email address/).fill(users.user1.email);
        await page.getByRole('button', { name: /Use single sign-on/ }).click();
    });

    await test.step('Keycloak login', async () => {
        await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
        await page.getByLabel(/Username/).fill(users.user1.name);
        await page.getByLabel('Password', { exact: true }).fill(users.user1.password);
        await page.getByRole('button', { name: 'Sign In' }).click();
    });

    await utils.checkNotification(page, 'Invalid authentication.');
    await expect(page.getByRole('heading', { name: 'Log in' })).toBeVisible();
});

test('ACR disable 2FA', async ({ browser, page }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: false,
        SSO_ACR_MIN: "3,2,1",
        SSO_ACR_NO_2FA: "1"
    }, false);

    await logNewUser(test, page, users.user1);
    await activateTOTP(test, page, users.user1);
    await logUser(test, page, users.user1);
});
