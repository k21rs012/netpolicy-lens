# NetPolicy Lens

マルチベンダー機器の設定をNetwork OS別Parserで読み込み、ベンダー非依存のCanonical Modelを経由して、Segment間の設定上の通信可否を可視化するローカルWebアプリです。

> **MVPの解析結果は静的なConfiguration Analysisです。** 完全なPacket Flow Simulationではありません。根拠を確認できない通信は推測で許可せず、`UNKNOWN` と表示します。

## すぐ試す

```bash
docker compose up -d --build
```

[http://localhost:8080](http://localhost:8080) を開き、「サンプルで始める」を選択します。単一・複数configまたはZIPは右上の **Config Import** から読み込めます。「機器ごとに貼り付け」を選ぶと、機器単位の入力欄を追加してconfigを直接貼り付け、一括で1つのSnapshotとして解析できます。設定はローカルのSQLiteにのみ保存されます。

## 実装済み

- Cisco IOS / IOS-XE: Interface、VLAN、IPv4/IPv6 address、ACL、ACL binding、static route
- Juniper Junos / SRX: Interface、Zone、Address Book、Security Policy、定義済みapplication解決
- Yamaha RTX: Interface、VLAN、Filter、Filter binding、static route
- Fortinet FortiOS / FortiGate: Interface、VLAN、Zone、Address/Service Object・Group、Firewall Policy、static route、Policy NAT
- Palo Alto PAN-OS: Interface、Zone、Address/Service Object・Group、Security Policy、Application解決、static route、NAT Policy
- HPE Aruba AOS-CX: Interface、VLAN/SVI、IPv4/IPv6 ACL、`apply access-list` binding、static route
- Arista EOS: Interface、VLAN/SVI、IPv4/IPv6 ACL、`ip access-group` binding、static route
- AlliedWare Plus: Interface、VLAN/IP interface、software/hardware ACL、`access-group` / traffic-filter認識、static route
- VyOS: Interface/VIF、Zone、IPv4/IPv6 Firewall、Zone Policy、Firewall Group、static route、source/destination NAT
- Network OS自動検出（複数特徴のスコアリング）
- Canonical Modelとraw config / line trace
- `ALLOW` / `DENY` / `PARTIAL` / `UNKNOWN` / `SAME_SEGMENT` Matrix
- Matrixセル詳細とRule trace
- Device / Policy / Parser Debug / Capability画面
- Device詳細（Interface、VLAN、Zone、Route、Policy、NAT、Warning、Unsupported）
- Password / Secret / SNMP Communityの保存・表示時マスク
- Snapshot単位のSQLite保存
- Snapshot間の通信可否／Policy／Interface・VLAN・Zone Diff（新規ALLOW優先表示）
- Device・SegmentのTopology Graph（同一サブネット接続は `INFERRED` と明示）
- Source / Destination / Protocol / Port指定の複数機器Path探索とhop単位Policy trace
- 経路なしを `NO_ROUTE`、Policy根拠不足を `UNKNOWN` として分離
- 複数ファイル・ZIP import、機器ごとのconfig貼り付けImport
- Docker Compose、Parser unit test、Golden Test、API end-to-end test

NX-OS / ASA / ExtremeXOSなどの追加Parser、物理・動的経路情報の取込、Batfish連携は拡張対象です。UIのCapability Matrixでは予定機能を「予定」と区別します。

## Architecture

```text
Config files
   ↓
Parser Registry ── detect(): 0.0 .. 1.0
   ↓
Network OS Parser Plugin
   ↓
CanonicalConfig
   ├── Device / Interface / VLAN / Zone / Segment
   ├── Route / Policy / NAT
   └── Trace / Warning / Unsupported
   ↓
Static Policy Analyzer
   ├── Segment Matrix / Snapshot Diff
   └── Topology Graph / Multi-hop Path Trace
   ↓
FastAPI ── SQLite snapshots ── React UI
```

AnalyzerとUIはベンダー固有構文を参照しません。ZoneがないOSもSegmentへ正規化されます。

## ローカル開発

Backend:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cd backend
uvicorn app.main:app --reload
```

Frontend（別ターミナル）:

```bash
cd frontend
npm install
npm run dev
```

Vite: [http://localhost:5173](http://localhost:5173)、API docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## API

| Method | Endpoint | 用途 |
|---|---|---|
| POST | `/api/configs/import` | Config / ZIP import |
| POST | `/api/configs/detect` | Network OS検出候補 |
| GET | `/api/devices` | Device一覧 |
| GET | `/api/devices/{id}` | Canonical device detail |
| GET | `/api/policies` | 共通Policy一覧 |
| GET | `/api/matrix` | Segment Matrix |
| GET | `/api/matrix/{src}/{dst}` | セル根拠 |
| GET | `/api/parser/debug` | Canonical JSON |
| GET | `/api/parser/warnings` | Parser Warning / Unsupported一覧 |
| GET | `/api/parser/capabilities` | 対応機能一覧 |
| GET | `/api/snapshots` | Import履歴 |
| GET | `/api/diff?before={id}&after={id}` | Snapshot間Diff |
| GET | `/api/topology` | Device / Segment Topology |
| GET | `/api/reachability?src={id}&dst={id}&protocol=tcp&port=443` | 複数機器Path解析 |

`/api/matrix?protocol=tcp&port=22` のようにプロトコルとポートで絞り込めます。

## Parser Plugin追加

1. `backend/app/parsers/` に `BaseConfigParser` の実装を追加
2. `parser_id` と `ParserCapabilities` を宣言
3. `detect()` と `parse()` を実装
4. `@ParserRegistry.register` を付与
5. `backend/app/parsers/__init__.py` でmoduleをimport
6. fixtureとGolden Testを追加

Canonical Model、Analyzer、UIの変更は原則不要です。

## Test

```bash
cd backend
PYTHONPATH=. pytest -q

cd ../frontend
npm run build
```

## Security / limitations

- 実機接続、Config Push、自動修正は行いません。
- configは外部サービスへ送信しません。
- Topologyの機器間リンクは設定内サブネットの重複から推定し、物理配線を保証しません。
- 現MVPはstateful behavior、dynamic routing、NAT後の完全な到達性を再現しません。
- 未解決オブジェクトや適用関係が曖昧な場合は `UNKNOWN` を優先します。
- Password / Secret / SNMP CommunityはSnapshot保存前にマスクします。未登録の独自資格情報構文には対応しないため、本番ではホスト側のvolume権限も制限してください。
- RBACと元configへのアクセス権分離は次の実装対象です。

License: Apache-2.0を想定（公開時に`LICENSE`を追加してください）。
