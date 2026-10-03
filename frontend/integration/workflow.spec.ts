import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";

const original = readFileSync(new URL("./fixtures/audit.conf", import.meta.url), "utf8");
async function importConfig(page: Page, raw: string, name: string) {
  await page.getByRole("button", { name: "Config Import", exact: true }).click();
  await page.getByLabel("Snapshot名").fill(name);
  await page.getByLabel("設定ファイルを選択").setInputFiles({ name: "audit.conf", mimeType: "text/plain", buffer: Buffer.from(raw) });
  await page.getByRole("button", { name: "検出プレビュー" }).click();
  await expect(page.getByLabel("audit.conf のNetwork OS")).toBeVisible();
  await page.getByLabel("audit.conf のSite").fill("Integration Lab");
  const response = page.waitForResponse(r => r.url().includes("/api/configs/import"));
  await page.getByRole("button", { name: "Import", exact: true }).click();
  expect((await response).status()).toBe(200);
  await expect(page.getByRole("dialog", { name: "機器設定を解析" })).toBeHidden();
}

test("実API: Import・保存・Matrix・Path・再Import・Diff・Exportを通して確認する", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/");
  await importConfig(page, original, "before");
  await page.reload();
  await expect(page.locator(".matrix")).toContainText("USERS");
  const cells = await (await page.request.get("/api/matrix?protocol=tcp&port=443")).json();
  expect(cells.cells.find((cell: any) => cell.source === "audit-vlan-10" && cell.destination === "audit-vlan-20").result).toBe("ALLOW");
  await page.getByRole("button", { name: "Topology / Path" }).click();
  await page.getByLabel("Source", { exact: true }).selectOption("audit-vlan-10");
  await page.getByLabel("Destination", { exact: true }).selectOption("audit-vlan-20");
  await page.getByRole("button", { name: "経路を解析" }).click();
  await expect(page.locator(".path-verdict .status")).toHaveText("許可");
  await expect(page.locator(".hop-list")).toContainText("CHECK / Rule 10");
  // Import while Path remains mounted: the view must refresh its topology.
  const changed = original.replace("10 permit tcp", "10 deny tcp").replace("name SERVERS", "name UPDATED-SERVERS");
  await importConfig(page, changed, "after");
  await expect(page.getByLabel("Destination", { exact: true })).toContainText("UPDATED-SERVERS");
  await expect(page.locator(".path-result")).toHaveCount(0);
  await page.getByRole("button", { name: "経路を解析" }).click();
  await expect(page.locator(".path-verdict .status")).toHaveText("拒否");
  await page.getByRole("button", { name: "Snapshot Diff" }).click();
  await expect(page.locator(".diff-summary")).toBeVisible();
  await expect(page.locator(".diff-summary")).toContainText("変更ルール");
  const diff = await (await page.request.get("/api/diff")).json();
  expect(diff.summary.changed_rules).toBe(1);
  await page.getByRole("button", { name: "Parser Debug" }).click();
  const downloading = page.waitForEvent("download");
  await page.getByRole("button", { name: "JSON Export" }).click();
  const download = await downloading;
  expect(download.suggestedFilename()).toBe("audit-canonical.json");
  const exported = readFileSync((await download.path())!, "utf8");
  expect(JSON.parse(exported).device.site).toBe("Integration Lab");
  expect(exported).not.toContain("synthetic-test-community");
  // A more-specific route with an unreachable gateway partitions the subnet end to end.
  await importConfig(page, original + "\nip route 10.0.9.128 255.255.255.128 192.0.2.99\n", "ranges");
  await page.getByRole("button", { name: "Topology / Path" }).click();
  await page.getByLabel("Source", { exact: true }).selectOption("audit-vlan-10");
  await page.getByLabel("Destination", { exact: true }).selectOption("audit-vlan-20");
  await page.getByRole("button", { name: "経路を解析" }).click();
  await expect(page.getByRole("button", { name: "経路 1: ALLOW", exact: true })).toContainText("10.0.9.0/25");
  await page.getByRole("button", { name: "経路 2: NO_ROUTE", exact: true }).click();
  await expect(page.locator(".path-options")).toContainText("10.0.9.128/25");
  await page.getByRole("button", { name: "ポリシーマトリクス", exact: true }).click();
  await page.getByLabel("ポート", { exact: true }).fill("443");
  const rangeCell = page.locator('button[title^="USERS (audit) → SERVERS"]');
  await expect(rangeCell).toHaveClass(/partial/);
  await rangeCell.click();
  await expect(page.getByLabel("宛先範囲別の判定")).toContainText("10.0.9.128/25");
  await expect(page.getByLabel("宛先範囲別の判定")).toContainText("10.0.9.0/25");
  expect(errors).toEqual([]);
});


test("実API: FortiOS VIPの取り込み・変換後Policy・NAT表示を確認する", async ({ page }) => {
  const raw = readFileSync(new URL("./fixtures/fortios-vip.conf", import.meta.url), "utf8");
  await page.goto("/");
  await importConfig(page, raw, "fortios-vip");
  await page.reload();
  await page.getByRole("button", { name: "Topology / Path" }).click();
  await page.getByLabel("Source", { exact: true }).selectOption("fg-if-wan");
  await page.getByLabel("Destination", { exact: true }).selectOption("fg-if-wan");
  await page.getByLabel("Source IP", { exact: true }).fill("198.51.100.55");
  await page.getByLabel("Destination IP", { exact: true }).fill("198.51.100.10");
  await page.getByLabel("Port", { exact: true }).fill("8443");
  await page.getByRole("button", { name: "経路を解析" }).click();
  await expect(page.locator(".path-verdict .status")).toHaveText("許可");
  await expect(page.locator(".hop-list")).toContainText("NAT: WEB");
  await expect(page.locator(".hop-list")).toContainText("10.0.9.20/32 (port 443)");
  await expect(page.locator(".path-chain")).toContainText("LAN");
  // The VIP policy must not permit direct access to the mapped host.
  await page.getByLabel("Destination", { exact: true }).selectOption("fg-if-lan");
  await page.getByLabel("Destination IP", { exact: true }).fill("10.0.9.20");
  await page.getByLabel("Port", { exact: true }).fill("443");
  await page.getByRole("button", { name: "経路を解析" }).click();
  await expect(page.locator(".path-verdict .status")).toHaveText("拒否");
});
