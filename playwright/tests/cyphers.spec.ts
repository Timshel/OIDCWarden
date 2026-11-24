import { test, expect, type Page, type TestInfo } from '@playwright/test';
import * as OTPAuth from "otpauth";

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';
import { activateTOTP, disableTOTP } from './setups/2fa';

let users = utils.loadEnv();
let totp;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {});
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Change Key settings', async ({ page }) => {
    await createAccount(test, page, users.user1);

    await test.step('Change SHA-256 Iterations', async () => {
        await page.getByRole('button', { name: 'Toggle collapse Settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Keys' }).click();

        // V2 accounts (pm-27278-v2-password-registration) register with Argon2id, V1 ones with PBKDF2
        await page.locator('.ng-arrow-wrapper').click();
        await page.getByRole('option', { name: 'PBKDF2 SHA-256' }).click();

        await page.getByRole('spinbutton', { name: 'KDF iterations * (required)'}).fill('700000');

        await page.getByRole('button', { name: 'Update encryption settings' }).click();
        await page.getByRole('textbox', { name: 'Master password * (required)' }).fill(users.user1.password);
        await page.getByRole('button', { name: 'Update settings' }).click();
        await utils.checkNotification(page, 'Encryption key settings changed');
    });

    await logUser(test, page, users.user1);

    await test.step('Switch to Argon2', async () => {
        await page.getByRole('button', { name: 'Toggle collapse Settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Keys' }).click();

        await page.locator('.ng-arrow-wrapper').click();
        await page.getByText('Argon2id').click();

        await page.getByRole('spinbutton', { name: 'KDF memory (MB) * (required)'}).fill('16');
        await page.getByRole('spinbutton', { name: 'KDF iterations * (required)'}).fill('2');
        await page.getByRole('spinbutton', { name: 'KDF parallelism * (required)'}).fill('1');

        await page.getByRole('button', { name: 'Update encryption settings' }).click();
        await page.getByRole('textbox', { name: 'Master password * (required)' }).fill(users.user1.password);
        await page.getByRole('button', { name: 'Update settings' }).click();
        await utils.checkNotification(page, 'Encryption key settings changed');
    });

    await logUser(test, page, users.user1);
});
