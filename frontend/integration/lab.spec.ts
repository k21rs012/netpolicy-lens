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

test('dual-stack Matrix・Diffは選択したfamilyでPathと一致する', async ({ page }) => {
  const ids: Record<string, string> = {};
  for (const version of ['before', 'after']) {
    const raw = readFileSync(new URL(`cisco/${version}/cisco.conf`, root));
    const response = await page.request.post('/api/configs/import', { multipart: {
      files: { name: 'cisco.conf', mimeType: 'text/plain', buffer: raw }, snapshot_name: `family-${version}`,
    } });
    expect(response.ok()).toBe(true);
    ids[version] = (await response.json()).snapshot_id;
  }
  await page.goto('/');
  await page.getByLabel('解析対象Snapshot').selectOption(ids.after);
  await page.getByLabel('プロトコル', { exact: true }).selectOption('tcp');
  await page.getByLabel('ポート', { exact: true }).fill('443');
  const cell = page.locator('button[title="OFFICE (cisco-lab) → SERVER (cisco-lab)"]');
  await expect(cell).toHaveClass(/unknown/);
  for (const [family, verdict] of [['4', 'deny'], ['6', 'allow']]) {
    await page.getByLabel('Matrix IP family').selectOption(family);
    await expect(cell).toHaveClass(new RegExp(verdict));
    await expect(page.locator('.matrix-scope')).toContainText(`IPv${family}`);
    await cell.click();
    await expect(page.getByRole('dialog', { name: '通信判定の詳細' })).toContainText(`IPv${family} / TCP/443`);
    await page.getByRole('button', { name: '詳細を閉じる' }).click();
  }
  await page.setViewportSize({ width: 390, height: 1000 });
  await page.getByRole('button', { name: 'メニューを畳む' }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: '/tmp/netpolicy-family-matrix.png', fullPage: true, animations: 'disabled' });
  await page.getByRole('button', { name: 'メニューを開く' }).click();
  await page.getByRole('button', { name: 'Snapshot Diff' }).click();
  await page.getByRole('button', { name: 'メニューを畳む' }).click();
  await page.getByLabel('比較元Snapshot').selectOption(ids.before);
  await page.getByLabel('比較先Snapshot').selectOption(ids.after);
  await page.getByLabel('比較Protocol').selectOption('tcp');
  await page.getByLabel('比較Port').fill('443');
  await page.getByLabel('比較IP family').selectOption('4');
  await page.getByRole('button', { name: '条件を適用' }).click();
  await expect(page.locator('.diff-query-scope')).toHaveText('経路評価: TCP / 443 / IPv4');
  const row = page.locator('.comm-change').filter({ hasText: 'OFFICE' }).filter({ hasText: 'SERVER' });
  await expect(row).toHaveCount(1);
  await expect(row).toContainText('DENY TCP/443');
  await page.getByLabel('比較IP family').selectOption('6');
  await page.getByRole('button', { name: '条件を適用' }).click();
  await expect(page.locator('.diff-query-scope')).toHaveText('経路評価: TCP / 443 / IPv6');
  await expect(row).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: '/tmp/netpolicy-family-diff.png', fullPage: true, animations: 'disabled' });
});
