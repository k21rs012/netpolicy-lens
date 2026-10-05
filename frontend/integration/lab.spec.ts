import { expect, test } from '@playwright/test';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = new URL('../../lab/scenarios/', import.meta.url);
const labels: Record<string, string> = { ALLOW: '許可', DENY: '拒否', PARTIAL: '部分的・未確定', UNKNOWN: '不明' };
for (const scenario of readdirSync(root)) {
  const directory = new URL(`${scenario}/`, root);
  const contract = JSON.parse(readFileSync(new URL('expected.json', directory), 'utf8'));
  test(`検証config: ${scenario} のImport・変更前後のPath`, async ({ page }) => {
    test.setTimeout(60000);
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('/');
    for (const version of ['before', 'after'] as const) {
      const source = new URL(`${version}/`, directory);
      const files = readdirSync(source).map(name => fileURLToPath(new URL(name, source)));
      await page.getByRole('button', { name: 'Config Import', exact: true }).click();
      await page.getByLabel('Snapshot名').fill(`lab-${scenario}-${version}`);
      await page.getByLabel('設定ファイルを選択').setInputFiles(files);
      await page.getByRole('button', { name: '検出プレビュー' }).click();
      for (const name of readdirSync(source))
        await expect(page.getByLabel(`${name} のNetwork OS`)).toBeVisible();
      const imported = page.waitForResponse(r => r.url().includes('/api/configs/import'));
      await page.getByRole('button', { name: 'Import', exact: true }).click();
      expect((await imported).status()).toBe(200);
      await expect(page.getByRole('dialog', { name: '機器設定を解析' })).toBeHidden();
      await page.getByRole('button', { name: 'Topology / Path' }).click();
      for (const c of contract.cases) {
        await page.getByLabel('Source', { exact: true }).selectOption(c.query.src);
        await page.getByLabel('Destination', { exact: true }).selectOption(c.query.dst);
        await page.getByLabel('Source IP', { exact: true }).fill(c.query.source_ip || '');
        await page.getByLabel('Destination IP', { exact: true }).fill(c.query.destination_ip || '');
        await page.getByRole('combobox', { name: 'IP family', exact: true }).selectOption(String(c.query.ip_version || 4));
        await page.getByLabel('Port', { exact: true }).fill(String(c.query.port));
        const response = page.waitForResponse(r => r.url().includes('/api/reachability?'));
        await page.getByRole('button', { name: '経路を解析' }).click();
        const expected = c[version === 'before' ? 'expected' : 'after'];
        expect((await (await response).json()).result).toBe(expected);
        await expect(page.locator('.path-verdict .status')).toHaveText(labels[expected]);
      }
    }
    expect(errors).toEqual([]);
  });
}
