import { expect, test, type Page } from "@playwright/test";

const devices = [
  { id: "core", hostname: "core", vendor: "cisco", network_os: "ios-xe", source_file: "core.conf", site: "Tokyo-DC", confidence: 0.98, counts: { interfaces: 1, segments: 1, policies: 1, nat: 0, warnings: 0, unsupported: 0 } },
  { id: "fw", hostname: "fw", vendor: "juniper", network_os: "srx", source_file: "fw.conf", site: "Osaka-DC", confidence: 0.96, counts: { interfaces: 1, segments: 1, policies: 1, nat: 1, warnings: 0, unsupported: 0 } },
];
const segments = [
  { id: "core-user", name: "USER", type: "vlan", device: "core", vlan_id: 10, networks: ["10.10.0.0/24"] },
  { id: "fw-server", name: "SERVER", type: "zone", device: "fw", networks: ["10.20.0.0/24"] },
];
const cells = [
  { source: "core-user", destination: "core-user", result: "SAME_SEGMENT", allowed: [], denied: [], policy_ids: [], traces: [] },
  { source: "fw-server", destination: "fw-server", result: "SAME_SEGMENT", allowed: [], denied: [], policy_ids: [], traces: [] },
  { source: "core-user", destination: "fw-server", result: "ALLOW", allowed: ["TCP/443"], denied: [], policy_ids: ["core:WEB"], traces: [{ device: "core", interface: "Vlan10", policy: "WEB", sequence: 10, action: "permit", service: "TCP/443", trace: { source_file: "core.conf", line_start: 12, raw_config: "permit tcp any any eq 443" } }] },
  { source: "fw-server", destination: "core-user", result: "DENY", allowed: [], denied: ["IP/ANY"], policy_ids: ["fw:DENY"], traces: [] },
];
const policies = [
  { id: "core:WEB", device: "core", name: "WEB", sequence: 10, src: ["10.10.0.0/24"], dst: ["10.20.0.0/24"], protocol: ["tcp"], dst_ports: ["443"], action: "permit", interface: "Vlan10", trace: { source_file: "core.conf", line_start: 12, raw_config: "permit tcp any any eq 443" } },
  { id: "fw:DENY", device: "fw", name: "DENY", sequence: 20, src: ["any"], dst: ["any"], protocol: ["ip"], dst_ports: ["any"], action: "deny", trace: { source_file: "fw.conf", line_start: 20, raw_config: "deny ip any any" } },
];

async function mockApi(page: Page) {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path === "/api/matrix" ? { snapshot_id: "snap-1", segments, cells }
      : path === "/api/devices" ? { snapshot_id: "snap-1", items: devices }
      : path === "/api/policies" ? { snapshot_id: "snap-1", items: policies }
      : path === "/api/parser/capabilities" ? [{ parser_id: "cisco_iosxe", label: "Cisco IOS-XE", interfaces: true, vlans: true, zones: false, routes: true, acl: true, firewall_policy: false, nat: true, ipv6: true, status: "available" }]
      : path === "/api/parser/debug" ? { snapshot_id: "snap-1", items: [] }
      : path === "/api/snapshots" ? []
      : path === "/api/topology" ? { snapshot_id: "snap-1", nodes: [
        { id: "segment:core-user", entity_id: "core-user", type: "segment", label: "USER", subtitle: "10.10.0.0/24", device: "core" },
        { id: "segment:fw-server", entity_id: "fw-server", type: "segment", label: "SERVER", subtitle: "10.20.0.0/24", device: "fw" },
      ], edges: [], summary: { devices: 0, segments: 2, adjacencies: 0 } }
      : path === "/api/reachability" ? { snapshot_id: "snap-1", source: "core-user", destination: "fw-server", protocol: "udp", port: 50000, source_port: 53, ip_version: 6, state: "new", assume_session: false, result: "NO_ROUTE", path: [], steps: [], topology: { nodes: [], edges: [], summary: {} } }
      : { items: [] };
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(json) });
  });
}

test.beforeEach(async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "ポリシーマトリクス" })).toBeVisible();
});

test("SiteでMatrixを絞り込み、セル詳細を表示できる", async ({ page }) => {
  await page.locator('button[title^="USER (core) → SERVER"]').click();
  await expect(page.getByRole("dialog", { name: "通信判定の詳細" })).toContainText("TCP/443");
  await page.getByRole("button", { name: "詳細を閉じる" }).click();
  await page.getByLabel("Siteで絞り込み").selectOption("Tokyo-DC");
  await expect(page.getByText("1 / 2 segments")).toBeVisible();
  await expect(page.locator(".matrix thead")).toContainText("USER");
  await expect(page.locator(".matrix thead")).not.toContainText("SERVER");
});

test("Policy一覧をDeviceとProtocolで絞り込める", async ({ page }) => {
  await page.getByRole("button", { name: "ポリシー", exact: true }).click();
  await page.getByLabel("ポリシーのデバイス").selectOption("core");
  await page.getByLabel("ポリシーのプロトコル").selectOption("tcp");
  await expect(page.locator(".result-count")).toHaveText("1 / 2 件");
  await expect(page.locator(".data-table tbody")).toContainText("WEB");
  await expect(page.locator(".data-table tbody")).not.toContainText("DENY");
});

test("ImportプレビューでSiteを指定して送信できる", async ({ page }) => {
  let importBody = "";
  await page.route("**/api/configs/preview", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [{ source_file: "device-1.conf", detected: { parser_id: "cisco_iosxe", confidence: 0.97 }, candidates: [], needs_confirmation: false }] }) }));
  await page.route("**/api/configs/import", async (route) => {
    importBody = route.request().postData() || "";
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ snapshot_id: "snap-2", imported: [{ hostname: "edge" }], errors: [], results: [] }) });
  });
  await page.getByRole("button", { name: /Config Import/ }).click();
  await page.getByRole("tab", { name: "機器ごとに貼り付け" }).click();
  await page.getByLabel("機器 1 のconfig").fill("version 17.12\nhostname edge\ninterface GigabitEthernet0/0");
  await page.getByRole("button", { name: "検出プレビュー" }).click();
  await page.getByLabel("device-1.conf のSite").fill("Tokyo-DC");
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "機器設定を解析" })).toBeHidden();
  expect(importBody).toContain("Tokyo-DC");
});

test("モバイルでサイドバーを開閉できる", async ({ page }) => {
  await page.setViewportSize({ width: 480, height: 800 });
  await page.evaluate(() =>
    localStorage.removeItem("netpolicy-sidebar-collapsed"),
  );
  await page.reload();
  await page.getByRole("button", { name: "メニューを開く" }).click();
  await expect(page.locator(".app")).not.toHaveClass(/sidebar-collapsed/);
  await page.getByRole("button", { name: "メニューを畳む" }).click();
  await expect(page.locator(".app")).toHaveClass(/sidebar-collapsed/);
});

test("stateful解析は既存セッションの仮定を明示できる", async ({ page }) => {
  await page.getByRole("button", { name: "Topology / Path" }).click();
  await page.getByLabel("State").selectOption("established");
  const assumption = page.getByLabel("既存セッションを仮定");
  await expect(assumption).toBeVisible();
  await assumption.check();
  await expect(assumption).toBeChecked();
});

test("Path traceでIP familyとSource portを送信できる", async ({ page }) => {
  await page.getByRole("button", { name: "Topology / Path" }).click();
  await page.getByLabel("IP family").selectOption("6");
  await page.getByLabel("Source port").fill("53");
  await page.getByLabel("Port", { exact: true }).fill("50000");
  const request = page.waitForRequest((item) => item.url().includes("/api/reachability"));
  await page.getByRole("button", { name: "経路を解析" }).click();
  const url = new URL((await request).url());
  expect(url.searchParams.get("ip_version")).toBe("6");
  expect(url.searchParams.get("source_port")).toBe("53");
});

test("Path traceで特定IPを送信し各hopの通信範囲を表示する", async ({ page }) => {
  const packet = {
    source_addresses: ["10.0.1.10/32"], destination_addresses: ["10.0.9.20/32"],
    protocol: "tcp", source_port: 12345, destination_port: null, ip_version: 4, state: "new",
  };
  const flow = { original: packet, current: packet };
  await page.route("**/api/reachability?**", (route) => route.fulfill({ json: {
    snapshot_id: "snap-1", source: "core-user", destination: "fw-server", protocol: "tcp",
    port: null, source_port: 12345, ip_version: 4, state: "new", assume_session: false,
    result: "ALLOW", path: ["segment:core-user", "device:core", "segment:fw-server"],
    flow, steps: [{ device: "core", ingress: "core-user", egress: "fw-server",
      result: "ALLOW", reason: "Rule 10", policy: "rule-10", flow }],
    topology: { nodes: [], edges: [], summary: {} },
  } }));
  await page.getByRole("button", { name: "Topology / Path" }).click();
  await page.getByLabel("Source IP", { exact: true }).fill("10.0.1.10");
  await page.getByLabel("Destination IP", { exact: true }).fill("10.0.9.20");
  await page.getByLabel("Source port").fill("12345");
  await page.getByLabel("Port", { exact: true }).fill("");
  const request = page.waitForRequest((item) => item.url().includes("/api/reachability"));
  await page.getByRole("button", { name: "経路を解析" }).click();
  const url = new URL((await request).url());
  expect(url.searchParams.get("source_ip")).toBe("10.0.1.10");
  expect(url.searchParams.get("destination_ip")).toBe("10.0.9.20");
  expect(url.searchParams.has("port")).toBe(false);
  await expect(page.getByText("通信範囲: 10.0.1.10/32 → 10.0.9.20/32")).toBeVisible();
  await expect(page.getByText("評価アドレス: 10.0.1.10/32 → 10.0.9.20/32")).toBeVisible();
});

for (const icmpType of ["0", "8"]) {
  test(`Path traceでICMP type ${icmpType}を指定できる`, async ({ page }) => {
    await page.getByRole("button", { name: "Topology / Path" }).click();
    await page.getByLabel("Protocol").selectOption("icmp");
    await page.getByLabel("ICMP type", { exact: true }).fill(icmpType);
    await expect(page.getByLabel("Source port")).toBeDisabled();
    await expect(page.getByLabel("Port", { exact: true })).toBeDisabled();
    const request = page.waitForRequest(item => item.url().includes("/api/reachability"));
    await page.getByRole("button", { name: "経路を解析" }).click();
    const url = new URL((await request).url());
    expect(url.searchParams.get("protocol")).toBe("icmp");
    expect(url.searchParams.get("icmp_type")).toBe(icmpType);
    expect(url.searchParams.has("port")).toBe(false);
    expect(url.searchParams.has("source_port")).toBe(false);
  });
}

for (const width of [390, 1280]) {
  test(`NATの変換前後と適用状態を表示する（${width}px）`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.evaluate(() => localStorage.removeItem("netpolicy-sidebar-collapsed"));
    await page.reload();
    const before = { source_addresses: ["10.0.1.10/32"], destination_addresses: ["203.0.113.10/32"], protocol: "tcp", source_port: 12345, destination_port: 8443, ip_version: 4, state: "new" };
    const after = { ...before, destination_addresses: ["10.0.9.20/32"], destination_port: 443 };
    await page.route("**/api/reachability?**", route => route.fulfill({ json: {
      snapshot_id: "nat", source: "core-user", destination: "fw-server", protocol: "tcp", port: 8443,
      state: "new", result: "ALLOW", path: ["segment:core-user", "device:core", "segment:fw-server"],
      flow: { original: before, current: after },
      steps: [{ device: "core", ingress: "core-user", egress: "fw-server", result: "ALLOW", reason: "translated permit",
        flow: { original: before, current: after }, packet_in: before, packet_out: after,
        nat: [{ name: "DNAT-WEB", type: "destination", stage: "destination", confidence: "EXACT", applied: true,
          before, after, evaluation_order: "destination NAT → routing → policy → source NAT" }],
      }], topology: { nodes: [], edges: [], summary: {} },
    } }));
    if (width < 768) await page.getByRole("button", { name: "メニューを開く" }).click();
    await page.getByRole("button", { name: "Topology / Path" }).click();
    if (width < 768) await page.getByRole("button", { name: "メニューを畳む" }).click();
    await page.getByRole("button", { name: "経路を解析" }).click();
    await expect(page.getByText(/NAT: DNAT-WEB/)).toContainText("適用済み");
    await expect(page.getByText(/NAT: DNAT-WEB/)).toContainText("変換前: 10.0.1.10/32 (port 12345) → 203.0.113.10/32 (port 8443)");
    await expect(page.getByText(/NAT: DNAT-WEB/)).toContainText("変換後: 10.0.1.10/32 (port 12345) → 10.0.9.20/32 (port 443)");
    await expect(page.getByText(/最終通信:/)).toContainText("10.0.9.20/32 (port 443)");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.getByText(/NAT: DNAT-WEB/).scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath("nat-flow.png"), animations: "disabled" });
  });
}

test("テーマはOS設定に追従し、手動切替を保存・別タブへ反映する", async ({ page, context }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(page.getByRole("switch", { name: "ダークモード" })).toBeChecked();
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(16, 24, 21)");
  await page.emulateMedia({ colorScheme: "light" });
  const toggle = page.getByRole("switch", { name: "ダークモード" });
  await expect(toggle).not.toBeChecked();
  await toggle.focus();
  await page.keyboard.press("Space");
  await expect(toggle).toBeChecked();
  await page.reload();
  await expect(toggle).toBeChecked();
  const other = await context.newPage();
  await mockApi(other);
  await other.goto("/");
  await expect(other.getByRole("switch", { name: "ダークモード" })).toBeChecked();
  await other.getByRole("switch", { name: "ダークモード" }).click();
  await expect(toggle).not.toBeChecked();
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(244, 246, 243)");
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(toggle).not.toBeChecked();
  await page.reload();
  await expect(toggle).not.toBeChecked();
  await other.close();
});

test("ダークモードで全ページと詳細・Importを表示する", async ({ page }, testInfo) => {
  const snapshots = ["after", "before"].map(id => ({ id, name: id, created_at: "2026-09-25T00:00:00Z", parser_version: "1", device_count: 2 }));
  await page.route("**/api/snapshots", route => route.fulfill({ json: snapshots }));
  await page.route("**/api/diff?**", route => route.fulfill({ json: {
    before: snapshots[1], after: snapshots[0],
    summary: { new_allow: 1, new_deny: 0, removed_allow: 0, added_rules: 1, removed_rules: 0, changed_rules: 0, network_changes: 0 },
    communications: [{ source: "core-user", destination: "fw-server", source_label: "USER", destination_label: "SERVER", source_device: "core", destination_device: "fw", before_result: "DENY", after_result: "ALLOW", new_allow: ["TCP/443"], new_deny: [], removed_allow: [], removed_deny: [], after_traces: [] }],
    policies: [], network: [],
  } }));
  await page.reload();
  await page.getByRole("switch", { name: "ダークモード" }).click();
  await expect(page.locator(".matrix-tools select")).toHaveCSS("background-repeat", "no-repeat");
  await expect(page.locator(".matrix-wrap")).toHaveCSS("background-color", "rgb(24, 35, 30)");
  await expect(page.locator(".cell.allow").first()).toHaveCSS("background-color", "rgb(23, 60, 44)");
  await page.screenshot({ path: testInfo.outputPath("dark-matrix.png"), animations: "disabled" });
  await page.locator('button[title^="USER (core) → SERVER"]').click();
  await expect(page.locator(".drawer")).toHaveCSS("background-color", "rgb(24, 35, 30)");
  await page.screenshot({ path: testInfo.outputPath("dark-detail.png"), animations: "disabled" });
  await page.getByRole("button", { name: "詳細を閉じる" }).click();
  for (const [name, selector] of [
    ["Topology / Path", ".path-panel"], ["Snapshot Diff", ".diff-page"],
    ["ポリシー", ".panel"], ["デバイス", ".cards"], ["Parser Debug", ".debug"], ["対応状況", ".panel"],
  ]) {
    await page.getByRole("button", { name, exact: name !== "Parser Debug" }).click();
    await expect(page.locator(selector)).toBeVisible();
    await expect(page.getByRole("switch", { name: "ダークモード" })).toBeChecked();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`dark-${name.replaceAll("/", "-")}.png`), animations: "disabled" });
  }
  await page.getByRole("button", { name: "Config Import" }).click();
  await expect(page.getByRole("dialog")).toHaveCSS("background-color", "rgb(24, 35, 30)");
  await page.getByRole("tab", { name: "機器ごとに貼り付け" }).click();
  await page.getByLabel("機器 1 のconfig").fill("hostname example\ninterface eth0");
  await page.screenshot({ path: testInfo.outputPath("dark-import.png"), animations: "disabled" });
});

for (const width of [320, 390]) {
  test(`モバイルでテーマ切替とダーク表示が収まる（${width}px）`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 850 });
    await page.evaluate(() => localStorage.removeItem("netpolicy-sidebar-collapsed"));
    await page.reload();
    const toggle = page.getByRole("switch", { name: "ダークモード" });
    await toggle.click();
    await expect(toggle).toBeChecked();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const title = await page.locator("h1").boundingBox();
    const actions = await page.locator(".header-actions").boundingBox();
    expect(title!.x + title!.width <= actions!.x || title!.y + title!.height <= actions!.y).toBe(true);
    await page.screenshot({ path: testInfo.outputPath("dark-mobile.png"), animations: "disabled" });
    await toggle.click();
    await expect(toggle).not.toBeChecked();
    await page.screenshot({ path: testInfo.outputPath("light-mobile.png"), animations: "disabled" });
  });
}

test("保存領域が使えなくてもテーマを切り替えられる", async ({ page }) => {
  await page.addInitScript(() => {
    Storage.prototype.getItem = () => { throw new DOMException("blocked", "SecurityError"); };
    Storage.prototype.setItem = () => { throw new DOMException("blocked", "SecurityError"); };
  });
  await page.reload();
  await expect(page.getByRole("heading", { name: "ポリシーマトリクス" })).toBeVisible();
  await page.getByRole("switch", { name: "ダークモード" }).click();
  await expect(page.locator("body")).toHaveCSS("background-color", "rgb(16, 24, 21)");
});

for (const width of [390, 1280]) {
  test(`サイドバー開閉ボタンがヘッダー内に収まり操作できる（${width}px）`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 850 });
    await page.evaluate(() => localStorage.removeItem("netpolicy-sidebar-collapsed"));
    await page.reload();
    const toggle = page.locator(".sidebar-toggle");
    for (let i = 0; i < 3; i++) {
      await expect(toggle).toBeVisible();
      const header = await page.locator(".app-header").boundingBox();
      const button = await toggle.boundingBox();
      expect(button!.x).toBeGreaterThanOrEqual(header!.x);
      expect(button!.y).toBeGreaterThanOrEqual(header!.y);
      expect(button!.x + button!.width).toBeLessThanOrEqual(header!.x + header!.width);
      expect(button!.y + button!.height).toBeLessThanOrEqual(header!.y + header!.height);
      expect(await toggle.evaluate(el => {
        const rect = el.getBoundingClientRect();
        return el.contains(document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2));
      })).toBe(true);
      const expanded = await toggle.getAttribute("aria-expanded");
      await toggle.click();
      await expect(toggle).toHaveAttribute("aria-expanded", expanded === "true" ? "false" : "true");
    }
    if (width < 900) {
      await expect(toggle).toHaveAttribute("aria-expanded", "true");
      const header = await page.locator(".app-header").boundingBox();
      const sidebar = await page.locator(".sidebar").boundingBox();
      expect(sidebar!.y).toBeGreaterThanOrEqual(header!.y + header!.height);
    }
    await page.screenshot({ path: testInfo.outputPath("sidebar-control.png"), animations: "disabled" });
    await page.getByRole("switch", { name: "ダークモード" }).click();
    await page.screenshot({ path: testInfo.outputPath("sidebar-control-dark.png"), animations: "disabled" });
  });
}
