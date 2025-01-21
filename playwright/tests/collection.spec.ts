import { test, expect, type TestInfo } from '@playwright/test';

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo);
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Create', async ({ page }) => {
    await createAccount(test, page, users.user1);
    await logUser(test, page, users.user1);

    await test.step('Create Org', async () => {
        await page.getByRole('link', { name: 'New organisation' }).click();
        await page.getByLabel('Organisation name (required)').fill('Test');
        await page.getByRole('button', { name: 'Submit' }).click();
        await page.locator('div').filter({ hasText: 'Members' }).nth(2).click();
        await expect(page.getByTestId("toast-title")).toHaveText('Organisation created');
        await page.locator('#toast-container').getByRole('button').click();
    });

    await test.step('Create Collection', async () => {
        await page.getByRole('link', { name: 'Collections' }).click();
        await page.getByRole('button', { name: 'New' }).click();
        await page.getByRole('menuitem', { name: 'Collection' }).click();
        await page.getByLabel('Name (required)').fill('RandomCollec');
        await page.getByRole('button', { name: 'Save' }).click();
        await expect(page.getByTestId("toast-message")).toHaveText("Created collection RandomCollec.");
        await page.locator('#toast-container').getByRole('button').click();
        await expect(page.getByRole('button', { name: 'RandomCollec' })).toBeVisible();
    });
});
