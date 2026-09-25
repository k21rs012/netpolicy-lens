# NetPolicy Lens

マルチベンダー機器の設定をNetwork OS別Parserで読み込み、ベンダー非依存のCanonical Modelを経由して、Segment間の設定上の通信可否を可視化するローカルWebアプリです。

> **MVPの解析結果は静的なConfiguration Analysisです。** 完全なPacket Flow Simulationではありません。根拠を確認できない通信は推測で許可せず、`UNKNOWN` と表示します。

## すぐ試す

```bash
docker compose up -d --build
```

[http://localhost:8080](http://localhost:8080) を開き、「サンプルで始める」を選択します。単一・複数config、フォルダ、ZIPは右上の **Config Import** から読み込めます。「機器ごとに貼り付け」を選ぶと、機器単位の入力欄を追加してconfigを直接貼り付けられます。Import前にNetwork OSと検出信頼度を確認でき、信頼度が低いconfigは機器ごとにOSを指定します。設定はローカルのSQLiteにのみ保存されます。

## 対応状況

| Network OS | IF | VLAN | Route | ACL | Zone | Policy | NAT | IPv6 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Cisco IOS / IOS-XE | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | ✓ |
| Cisco NX-OS | ✓ | ✓ | ✓ | ✓ | — | — | — | ✓ |
| Cisco ASA / FTD | ✓ | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Juniper Junos / SRX | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Yamaha RTX | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| Fortinet FortiOS | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Palo Alto PAN-OS | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| HPE Aruba AOS-CX | ✓ | ✓ | ✓ | ✓ | — | — | — | ✓ |
| Arista EOS | ✓ | ✓ | ✓ | ✓ | — | — | — | ✓ |
| AlliedWare Plus | ✓ | ✓ | ✓ | ✓ | — | — | — | ✓ |
| VyOS | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ExtremeXOS / VOSS | ✓ | ✓ | ✓ | ✓ | — | — | — | ✓ |
| MikroTik RouterOS | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |

## 実装済み

- Cisco IOS / IOS-XE: Interface、VLAN、IPv4/IPv6 address、IPv4/IPv6 ACL、ACL binding、static route、static/PAT NAT
- Cisco NX-OS: Ethernet/SVI、VLAN、IPv4/IPv6 ACL、ACL binding、prefix形式のstatic route
- Cisco ASA / FTD: Interface/nameif、Zone Segment、Network Object、extended ACL、access-group binding、static route、object/manual NAT
- Juniper Junos / SRX: set形式・階層形式、Interface、VLAN、Zone、Address Book/Set、Security Policy、静的Route、source/destination/static NAT、定義済み/独自application解決
- Yamaha RTX: Interface、802.1Q VLAN、IPv4/IPv6 Filter、Filter binding、static route、NAT descriptor
- Fortinet FortiOS / FortiGate: Interface、VLAN、Zone、Address/Service Object・Group、Firewall Policy、static route、Policy NAT
- Palo Alto PAN-OS: set形式（vsys scope対応）、Interface、Zone、Address/Service Object・Group、Security Policy、Application解決、static route、NAT Policy
- HPE Aruba AOS-CX: Interface、VLAN/SVI、IPv4/IPv6 ACL、`apply access-list` binding、static route
- Arista EOS: Interface、VLAN/SVI、IPv4/IPv6 ACL、`ip access-group` binding、static route
- AlliedWare Plus: Interface、VLAN/IP interface、software/hardware ACL、`access-group` / traffic-filter認識、static route
- VyOS: set形式・1.4.x階層形式、Interface/VIF、local/通常Zone、IPv4/IPv6 base/custom chain、jump/default-jump、Firewall Group、state、ECMP/static/terminal route、条件付きsource/destination NAT
- VyOS Firewallの未解決address/network/port/interface groupは、参照名・設定行をWarningに残し、該当する通信をPARTIALとして評価します。否定付きport/interface groupも未評価条件として扱います。既存SnapshotへParser修正を反映するにはconfigを再importしてください。
- ExtremeXOS / VOSS: VLAN/SVI、IPv4 address、static route、基本ACL
- MikroTik RouterOS: VLAN/Interface、Address List、Firewall Filter、static route、source/destination NAT
- Network OS自動検出（複数特徴のスコアリング）
- Canonical Modelとraw config / line trace
- `ALLOW` / `DENY` / `PARTIAL` / `UNKNOWN` / `SAME_SEGMENT` Matrix
- Path traceは元・現在の通信アドレス範囲、protocol、送信元/宛先port、IP family、stateを保持し、各hopのinterface/zoneとは分離してPolicyを評価します。Source IP / Destination IPは任意で指定でき、省略時は選択Segmentの範囲を評価します。指定IPは選択Segment内・同一familyに限ります。APIの追加引数は`source_ip` / `destination_ip`、結果と各stepの`flow.original` / `flow.current`に通信情報を返します。
- 対応するNATは宛先変換→経路検索→Policy評価→送信元変換の順に適用し、変換後の通信情報を次の機器へ渡します。NATがある経路で宛先範囲が経路条件をまたぐ場合やECMPがある場合はPARTIALとし、1経路の結果を全体の保証にはしません。詳細は下記「NATを含むPath trace」を参照してください。
- Matrixセル詳細とRule trace
- Device / Policy / Parser Debug / Capability画面
- Device詳細（Interface、VLAN、Zone、Route、Policy、NAT、Warning、Unsupported）
- Password / Secret / SNMP Communityの保存・表示時マスク
- Snapshot単位のSQLite保存
- Snapshot間の通信可否／Policy／Interface・VLAN・Zone Diff（新規ALLOW優先表示）
- Device・SegmentのTopology Graph（同一サブネット接続は `INFERRED` と明示）
- Source / Destination / IP family / Protocol / Source Port / Destination Port指定の複数機器Path探索とhop単位Policy trace
- 経路なしを `NO_ROUTE`、Policy根拠不足を `UNKNOWN` として分離
- 複数ファイル・フォルダ・ZIP import、機器ごとのconfig貼り付け、検出プレビュー、OS手動補正、部分失敗表示
- Site/Device/Vendor/OS/Zone/VLAN/Segment/Protocol/Port Matrix filterとPolicy filter
- Secretマスク済みCanonical JSON Export
- Docker Compose、Parser契約/Golden Test、API end-to-end test、Playwright実ブラウザE2E、GitHub Actions CI

物理・動的経路情報の取込、Batfish連携、各OSの高度な独自構文は拡張対象です。未解釈のセキュリティ構文はParser Debugで確認できます。

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
   ├── Policy utilities ── Segment Matrix / Snapshot Diff
   └── Topology Graph
       └── Routing → Policy Engine → NAT → typed ReachabilityResult
   ↓
FastAPI ── SQLite snapshots ── React UI
```

AnalyzerとUIはベンダー固有構文を参照しません。ZoneがないOSもSegmentへ正規化されます。Path Traceは`routing.py`、`policy_engine.py`、`nat.py`、`reachability.py`へ責務を分離し、API結果はPydantic modelで検証します。React UIもMatrix、Topology、Diff、Device、Policy、Importを独立componentとして構成します。

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
| POST | `/api/configs/preview` | 複数Configの検出プレビュー |
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
python -m pytest -q

cd ../frontend
npm run build
npm run test:e2e
```

## Security / limitations

- 実機接続、Config Push、自動修正は行いません。
- configは外部サービスへ送信しません。
- Topologyの機器間リンクは設定内サブネットの重複から推定し、物理配線を保証しません。
- Path Traceはconnected/static routeの最長一致、recursive next-hop、blackhole/reject、IPv6 scoped next-hop、VRF、ACL/zone/global chain、指定したconnection stateとIP familyを評価します。ECMPの全経路集約は未対応です。PBRのmatchや動的ルーティングの実RIBが必要な場合は推測でALLOWにせず `UNKNOWN` を返します。
- 一致したNAT ruleと変換値、評価順、条件評価の確度はPath Traceに表示します。Rule順序、Interface、IP family、Protocol、Source/Destination Portを評価しますが、実セッションテーブルや時刻・ユーザー・URL categoryなどconfig外のランタイム条件は再現しません。`established` / `related` は実セッションの存在を確認できないため通常は `UNKNOWN` とし、画面で「既存セッションを仮定」を明示した場合だけstateful sessionとして評価します。
- 未解決オブジェクトや適用関係が曖昧な場合は `UNKNOWN` を優先します。
- Password / Secret / SNMP CommunityはSnapshot保存前とJSON Export時にマスクします。未登録の独自資格情報構文には対応しないため、本番ではホスト側のvolume権限も制限してください。
- 認証・RBACは未実装です。Composeは`127.0.0.1:8080`だけにbindします。リモート公開時は認証付きReverse Proxyを必須としてください。詳細は[SECURITY.md](SECURITY.md)を参照してください。
- Uploadは1ファイル20 MiB、1回500ファイル、ZIP展開後50 MiBに制限しています。

Apache License 2.0。詳細は[LICENSE](LICENSE)を参照してください。


### AlliedWare Plus VLAN hardware filter

- `access-list hardware` → `vlan access-map` / `match access-group` → `vlan filter ... vlan-list ... input` の関連付けを解析します。VLAN一覧の範囲・カンマ指定、同じACLの複数VLANへの適用を保持します。
- ハードウェアACLは設定順（明示sequenceがある場合はsequence順）に評価し、未一致時は通常転送として扱います。`access-list 10`等の管理用standard ACLは中継VLANへ自動適用しません。
- Path traceのICMP選択時にtypeを指定できます。IPv4のping要求は8、応答は0です。type未指定でtype条件付きルールに一致する可能性がある場合はPARTIALです。APIは`icmp_type`（0〜255）を受け取ります。
- Matrixはセグメント全体・全サービスの概要です。DNS、DHCP、ICMP typeなどの例外と拒否が混在すればPARTIALになります。特定通信はPath traceでIP・port・ICMP typeを指定してください。
- 未定義access-map/ACL、未対応map条件、port/global/QoSフィルターとの併用は警告とPARTIALで扱います。VLAN ACLが適用されていない方向、同一VLAN内のL2経路、管理プレーンのアクセス制御は今回の判定対象外です。既存Snapshotにはconfigの再importが必要です。
- 検証根拠：[x540L 5.5.5公式リファレンス：ハードウェアパケットフィルター](https://www.allied-telesis.co.jp/support/list/awp/rel/5.5.5-2.1/613-003277_L/docs/overview-30.html)。実機の稼働状態・OSバージョン固有の差異は別途確認が必要です。


### NATを含むPath trace

- **入力はNAT前**の送信元・宛先です。公開VIPを含むSegmentをDestinationに選び、そのVIPをDestination IPに指定します。DNAT後は実際の宛先ネットワークまで探索するため、表示する到達Segmentは選択したSegmentと異なる場合があります。
- 対応する処理順: VyOS / RouterOSのDNAT→routing→forward policy→SNAT、SRXのstatic/destination NAT→routing→policy→reverse static/source NAT、FortiOSの選択されたPolicyに付随するSNAT。
- 単一IP・portへの変換、NAT除外、順序・interface・protocol・port条件、SRXの同じprefix長のstatic NATと逆方向マッピングを扱います。DNATとSNATを別ルールで併用した通信にも対応します。SNATはローカルPolicy評価後に適用します。
- `flow.original`は入力を保持します。結果の`flow.current`は最終通信、各hopの`flow.current`はPolicy評価時の通信です。各hopの`packet_in` / `packet_out`、NAT効果の`before` / `after` / `applied`に受信・転送・実適用の根拠を返します。Policyで拒否した通信にSNATは適用しません。
- 複数pool・範囲割り当て、未解決object、部分一致、未対応条件はPARTIALで停止し、後続の許可ルールへ落としません。動的PATは送信元portを未確定（null）として伝搬し、全体をPARTIALとします。DHCP等で外側interfaceのIPが不明なmasqueradeも断定しません。
- **未対応**: PAN-OS、Cisco IOS/ASA/FTD、YamahaのNAT処理順、FortiOS VIP/central NAT/IP pool、単一ルールでのtwice NAT、複数SRX rule-setの優先関係、条件付きstatic NAT逆変換、NAT64、poolごとの候補分岐、実セッションに基づく戻り通信。NAT処理順が未対応の機器は、NATルールがある経路をPARTIALとします。
- 既存Snapshotの旧NATモデルは再取り込みが必要です。旧モデルから失われた条件を推測して実行しません。Matrixは従来の静的概要であり、このNATパイプラインはPath traceに適用されます。
- 処理順の根拠: [VyOS NAT44](https://docs.vyos.io/en/1.4/configuration/nat/nat44.html)、[SRX NAT overview](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-overview.html)、[RouterOS packet flow](https://help.mikrotik.com/docs/spaces/ROS/pages/328227/Packet%2BFlow%2Bin%2BRouterOS)、[FortiOS fixed port](https://docs.fortinet.com/document/fortigate/6.2.1/technical-note-fixed-port-on-firewall-policy/12/fd40732)。[PAN-OSはPolicyにNAT前アドレス・NAT後zoneを用いる](https://docs.paloaltonetworks.com/ngfw/networking/nat/nat-policy-rules)ため、他OSの処理順を流用しません。
