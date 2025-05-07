import { expect, type Browser,Page } from '@playwright/test';

import { type MailBuffer } from 'maildev';

import * as utils from '../../global-utils';

export async function createAccount(test, page: Page, user: { email: string, name: string, password: string }, mailBuffer?: MailBuffer) {
    await test.step('Create user', async () => {
        await page.context().clearCookies();

        // Landing page
        await page.goto('/');
        await page.getByRole('link', { name: 'Create account' }).click();

        // Vault create account
        await expect(page).toHaveTitle(/Create account | OIDCWarden Web/);
        await page.getByLabel(/Email address/).fill(user.email);
        await page.getByLabel('Name').fill(user.name);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Vault finish Creation
        await page.getByLabel('New master password (required)', { exact: true }).fill(user.password);
        await page.getByLabel('Confirm master password (').fill(user.password);
        await page.getByRole('button', { name: 'Create account' }).click();

        await utils.checkNotification(page, 'Your new account has been created')

        // Redirected to the vault
        await expect(page).toHaveTitle('Vaults | OIDCWarden Web');
        await utils.checkNotification(page, 'You have been logged in!');

        if( mailBuffer ){
            await expect(mailBuffer.next((m) => m.subject === "Welcome")).resolves.toBeDefined();
            await expect(mailBuffer.next((m) => m.subject === "New Device Logged In From Firefox")).resolves.toBeDefined();
        }
    });
}

export async function logUser(test, page: Page, user: { email: string, password: string }, mailBuffer?: MailBuffer) {
    await test.step('Log user', async () => {
        await page.context().clearCookies();

        // Landing page
        await page.goto('/');
        await page.getByLabel(/Email address/).fill(user.email);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Unlock page
        await page.getByLabel('Master password').fill(user.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        // We are now in the default vault page
        await expect(page).toHaveTitle(/Vaults/);

        if( mailBuffer ){
            await expect(mailBuffer.next((m) => m.subject === "New Device Logged In From Firefox")).resolves.toBeDefined();
        }
    });
}
