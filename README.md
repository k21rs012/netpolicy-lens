# NetPolicy Lens

複数ベンダーのネットワーク機器configを読み込み、セグメント間の通信可否とその根拠を確認するローカルWebアプリです。設定を共通モデルへ変換し、ポリシーマトリクス、複数機器の経路解析、NAT変換、ECMP候補、Snapshot間の差分を表示します。

解析は**設定に基づく静的評価**です。実機への接続や設定変更は行いません。実際の配線・経路表・セッション・サービスの稼働状態を確認するものではなく、根拠が不足する場合は `PARTIAL` / `UNKNOWN` として残します。

## 起動する

DockerとDocker Composeを利用できる環境で、リポジトリのルートから実行します。

```bash
docker compose up -d --build
```

[http://localhost:8080](http://localhost:8080) を開き、**サンプルで始める**、または **Config Import** を選びます。Composeは `127.0.0.1:8080` に公開し、APIへはフロントエンドのnginxを経由してアクセスします。

取り込んだ設定と解析モデルはSQLiteに保存します。Composeでは `netpolicy-data` 名前付きvolume内の `/app/data/netpolicy.db` を使用します。通常の停止ではデータを保持します。

```bash
docker compose down
```

更新を反映する場合は、再び `docker compose up -d --build` を実行します。**Parserの修正を既存Snapshotへ反映するには、元のconfigを再Importしてください。** 保存済みモデルは起動時に自動で再解析されません。

## 使い方

### 1. Configを取り込む

**Config Import** では、単一・複数ファイル、フォルダ、ZIP、機器ごとのテキスト貼り付けに対応しています。

1. configを選択し、検出プレビューを確認します。
2. 機器ごとのNetwork OSを確認します。自動検出が不確かな場合は手動で指定できます。
3. 必要に応じてSiteを入力し、Importします。
4. デバイス詳細や **Parser Debug** でWarning・Unsupportedと設定行を確認します。複数ファイルの一部が失敗した場合も、結果を個別に表示します。

1回のImportをSnapshotとして保存します。通常の一覧・解析画面は最新Snapshotを使用し、過去のSnapshotは **Snapshot Diff** や `snapshot_id` を指定したAPIで参照できます。

### 2. ポリシーマトリクスで全体を見る

送信元・宛先Segmentの組み合わせを一覧表示します。Site、Device、Vendor、OS、Zone、VLAN、Segmentで絞り込み、セルを選ぶと判定理由とRule traceを確認できます。

| 通信条件 | 評価内容 |
|---|---|
| Protocol・Portとも未指定 | 設定ルールの概要。表示サービスは経路全体の通信保証ではありません |
| ProtocolまたはPortを指定 | Path traceと同じ経路・Policy・NAT・ECMP評価で再計算 |
| Portだけ指定 | TCP・UDP・SCTPを個別に評価し、結果が異なる場合はPARTIAL |

条件指定時はSegment全体のアドレス範囲を対象に、新規通信・送信元port未指定で評価します。ポート範囲、`any`、ルール順序、暗黙deny、jump、未解決条件を扱い、単なる文字列検索は行いません。Snapshot Diffの通信差分は、条件未指定の設定概要に基づきます。

### 3. Topology / Pathで特定通信を調べる

Source / DestinationのSegmentを選び、IP family、Protocol、Portなどを指定して **経路を解析** を実行します。

- Source IP / Destination IPを省略すると、選択Segmentのアドレス範囲を評価します。指定するIPは選択Segment内・同一IP familyに限ります。
- Source port、connection state、ICMP typeも指定できます。IPv4のping要求はtype 8、応答はtype 0です。
- `established` / `related` は実セッションを取得できないため通常UNKNOWNです。既存セッションがある前提で調べる場合は **既存セッションを仮定** を選びます。
- 各hopの入口・出口、適用Policy、next-hop、NAT変換前後、根拠となる設定行を表示します。
- 複数経路がある場合は、候補ごとの判定を表示します。経路を選ぶと、経路図の強調とhop・NAT結果が切り替わります。

Topologyの機器間リンクは、config内のサブネット重複から推定した `INFERRED` 接続です。物理配線を表すものではありません。

### その他の画面

| 画面・操作 | 内容 |
|---|---|
| デバイス | Interface、VLAN、Zone、Route、Policy、NAT、Warning、Unsupportedの詳細 |
| ポリシー | 共通モデルへ変換したルールの一覧と絞り込み |
| Snapshot Diff | 通信判定・Policy・Interface・VLAN・Zoneの差分。新規ALLOWを優先表示 |
| Parser Debug | 解析モデルと診断情報の確認、マスク済みCanonical JSONのExport |
| 対応状況 | Parserごとの対応機能 |
| ヘッダーのテーマ切替 | ライト／ダーク切替。初回はOS設定に追従し、手動選択はブラウザに保存 |

サイドバーは開閉でき、狭い画面でも操作できます。

## 判定の意味

| 判定 | 意味 |
|---|---|
| `ALLOW` | 指定条件が、評価した経路・ルールで許可される |
| `DENY` | 適用Policyで拒否される |
| `PARTIAL` | 範囲や経路によって結果が異なる、未評価条件が残る、または探索を打ち切った |
| `UNKNOWN` | 経路・Policy・セッションなどの根拠が不足し、判定できない |
| `NO_ROUTE` | 設定と推定Topologyから宛先への経路を構成できない。Policyの拒否とは区別する |
| `SAME_SEGMENT` | 同一Segment。L2での到達性や実サービスの稼働を保証するものではない |

条件未指定のMatrixでは設定ルールの概要として読み、特定通信の確認には条件付きMatrixまたはPath traceを使ってください。未解決オブジェクトや未対応条件を、無条件の許可として扱いません。

## 解析の対応範囲

### 経路・ECMP

connected/static routeの最長プレフィックス一致とmetricを使い、同順位の候補を個別に評価します。同じ出口の複数next-hop、複数出口、recursive next-hop、IPv6 scoped next-hop、VRF、blackhole / reject / unreachableを扱います。

経路が途中で合流しても、各経路のPolicy履歴とNAT後の通信情報は独立して保持します。待機経路は同順位のECMP候補に混ぜません。VyOSではnext-hop／Interfaceごとのdistance、disable、distance 255を反映します。distance未指定の比較値は通常1、FortiOSでは10です。

全候補の判定が同じならその判定を返し、異なる場合はPARTIALに集約します。ループや未解決next-hopも結果に残します。探索は128経路・2,048状態・32 hopを上限とし、再帰next-hopにも回数・深さの上限を設けています。上限到達時はPARTIALとし、未評価候補があることを表示します。

宛先範囲内で有効なstatic route・connected subnetの条件が変わる場合は、IPv4/IPv6のCIDRに自動分割し、各範囲を送信元から再評価します。Pathの候補経路と条件付きMatrixの詳細に、NAT前の宛先範囲と判定を表示します。ECMPも範囲ごとに評価し、結果が混在する場合は全体をPARTIALにします。同一prefix長のstatic DNATは変換後の経路境界を変換前に戻して分割します。最大128回の再評価・128候補経路で打ち切り、残った範囲をPARTIALとして表示します。Policy・NATの部分一致条件そのものの自動分割は対象外です。動的ルーティングの実RIB、PBRの未対応match、SD-WAN固有の選択条件、実機のECMPハッシュ・分配率は再現しません。

### NAT

**入力するIP・portはNAT前の値です。** DNATでは公開VIPを含むSegmentとDestination IPを指定します。変換後の宛先へ経路を引き直すため、結果の到達Segmentが選択したSegmentと異なる場合があります。

| Network OS | 経路評価で対応する処理順 |
|---|---|
| VyOS / RouterOS | DNAT → 経路検索 → forward Policy → SNAT |
| Junos SRX | static/destination NAT → 経路検索 → Policy → reverse static/source NAT |
| FortiOS | 選択されたPolicyに付随するSNAT |

単一IP・portへの変換、NAT除外、ルール順序、Interface・IP family・Protocol・port条件、SRXの同じprefix長のstatic NATと逆方向マッピングを扱います。Policyで拒否した通信にSNATは適用しません。ECMPでも経路ごとに変換結果を保持します。

複数pool、範囲割り当て、部分一致、未解決object、未対応条件はPARTIALとして扱います。動的PATでは送信元portを未確定として引き継ぎ、PARTIALにします。外側InterfaceのIPが不明なmasqueradeも断定しません。

PAN-OS、Cisco IOS/ASA/FTD、YamahaのNAT処理順、FortiOS VIP/central NAT/IP pool、単一ルールのtwice NAT、複数SRX rule-setの優先関係、条件付きstatic NAT逆変換、NAT64、poolごとの分岐、実セッションに基づく戻り通信は未対応です。**NAT設定を読み取れることと、その変換を経路上で実行評価できることは別です。** 処理順が未対応の機器でNATを含む経路はPARTIALになります。

### VyOSの機器自身宛て・機器発通信

Interface・loopbackのIPから、VRFごとに「LOCAL · 機器自身」（local-zoneがあればその名前）を作ります。機器自身宛てはDestination、機器発通信はSourceで選択し、必要に応じてIPを絞ります。通常のSegmentを選んでも、Destination IPがその機器自身のIPならinputとして評価します。

input / output / forward、base/custom chain、jump/default-jump、local-zone、IPv4/IPv6ごとのzone既定動作を分けて評価します。同じrulesetの複数zone pairへの適用も保持します。未定義rulesetや未解決Firewall GroupはPARTIALとし、参照名と設定行を診断情報に残します。

DNAT後の機器自身宛てはinputで評価します。機器発通信はprerouting DNATを通さず、outputの後にSNATを適用します。実サービスの待受、実セッション、機器内ループバック通信は確認しません。IP不明のlocal endpointはUNKNOWNです。

### AlliedWare PlusのVLAN hardware filter

`access-list hardware` → `vlan access-map` / `match access-group` → `vlan filter ... vlan-list ... input` の適用関係を解析します。VLANの範囲・カンマ指定、同じACLの複数VLANへの適用、ルール順序、ICMP typeを保持します。未一致時は通常転送として扱い、管理用standard ACLを中継VLANへ自動適用しません。

未定義access-map/ACL、未対応map条件、port/global/QoSフィルターとの併用は警告とPARTIALで扱います。VLAN ACLが適用されていない方向、同一VLAN内のL2経路、管理プレーンのアクセス制御は対象外です。

### Configを読み込めるNetwork OS

以下は主な**読み取り対象**です。すべての構文・OSバージョンや実機動作を網羅するものではありません。通信判定の範囲は上記の説明と、画面のWarning・Unsupportedを併せて確認してください。

| Network OS | 主な読み取り対象 |
|---|---|
| Cisco IOS / IOS-XE | Interface、VLAN、IPv4/IPv6 ACLとbinding、static route、static/PAT NAT |
| Cisco NX-OS | Ethernet/SVI、VLAN、IPv4/IPv6 ACLとbinding、static route |
| Cisco ASA / FTD | Interface/nameif、Zone、Network Object、extended ACL、access-group、static route、object/manual NAT |
| Juniper Junos / SRX | set・階層形式、Interface、VLAN、Zone、Address Book/Set、Policy、application、static route、NAT |
| Yamaha RTX | Interface、802.1Q VLAN、IPv4/IPv6 Filterとbinding、static route、NAT descriptor |
| Fortinet FortiOS | Interface、VLAN、Zone、Address/Service Object・Group、Policy、static route、Policy NAT |
| Palo Alto PAN-OS | set形式・vsys scope、Interface、Zone、Address/Service Object・Group、Policy、Application、static route、NAT Policy |
| HPE Aruba AOS-CX | Interface、VLAN/SVI、IPv4/IPv6 ACL、apply access-list、static route |
| Arista EOS | Interface、VLAN/SVI、IPv4/IPv6 ACL、ip access-group、static route |
| AlliedWare Plus | Interface、VLAN/IP interface、software/hardware ACL、VLAN hardware filter、static route |
| VyOS | set・1.4.x階層形式、Interface/VIF、Zone/local、Firewall chain・Group・state、static/ECMP/terminal route、NAT |
| ExtremeXOS / VOSS | VLAN/SVI、IPv4 address、static route、基本ACL |
| MikroTik RouterOS | VLAN/Interface、Address List、Firewall Filter、static route、source/destination NAT |

## 保存・セキュリティ

configの解析と保存はローカルで行い、configを外部の解析サービスへ送信しません。Password・Secret・SNMP Communityの既知パターンはSnapshot保存前とCanonical JSON Export時にマスクします。独自の資格情報構文は検出できない場合があります。なお、UIのWebフォントはGoogle Fontsを参照します。

認証・RBACは未実装です。リモートで利用する場合は認証付きReverse Proxyを配置し、SQLite volumeへのアクセスを制限してください。Importの上限は1ファイル20 MiB、1回500ファイル、ZIP展開後50 MiBです。Composeのnginx経由では、multipart全体を1リクエスト64 MiBまで受け付けます。詳細と脆弱性の報告方針は [SECURITY.md](SECURITY.md) を参照してください。

## ローカル開発

CI・コンテナで使用しているバージョンはPython 3.12、Node.js 22です。以下の各手順は、リポジトリのルートから開始します。

Backend:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Frontend（別ターミナル）:

```bash
cd frontend
npm ci
npm run dev -- --host 127.0.0.1
```

UIは [http://localhost:5173](http://localhost:5173)、API仕様は [http://localhost:8000/docs](http://localhost:8000/docs) で確認できます。Viteは `/api` をポート8000へ転送します。Backendの保存先は `DATABASE_PATH` で変更でき、省略時は起動ディレクトリからの `./data/netpolicy.db`（上記手順では `backend/data/netpolicy.db`）です。

### テスト

Backendは仮想環境を有効にしたターミナルで、リポジトリのルートから実行します。

```bash
cd backend
python -m pytest -q
```

Frontendもリポジトリのルートから実行します。Playwrightのブラウザを初回にインストールします。

```bash
cd frontend
npm ci
npx playwright install chromium
npm run build
npm run test:e2e
```

LinuxでブラウザのOS依存ライブラリも必要な場合は、CIと同じ `npx playwright install --with-deps chromium` を使用します。実APIとの統合テストは、Backendの依存関係が入ったPythonを使用します。Frontendディレクトリで実行してください。

```bash
NETPOLICY_TEST_PYTHON=../.venv/bin/python npm run test:integration
```

上のPython指定はBackendディレクトリから解決されます。仮想環境を有効化済みなら `npm run test:integration` のみでも実行できます。統合テストはポート18000 / 15173と一時SQLiteを使い、既存サーバーを再利用しません。Import、再読込、Matrix、Path、再Import、Diff、JSON ExportをAPIのモックなしで確認します。

GitHub ActionsではBackendテスト、Frontendビルド・画面E2E・実API統合テスト、Compose起動後のnginx経由ImportとBackend再起動後の保存確認を実行します。`scripts/container_smoke.py` は合成Snapshotを作るため、検証専用環境だけで使用してください。今回の検証内容は [検証記録](docs/verification-2026-10-03.md) にまとめています。

## API

Snapshotに対する読み取りAPIは、`snapshot_id` を省略すると最新Snapshotを使います。実際のIDは一覧APIで取得してください。完全な引数・スキーマは開発用APIの `/docs` で確認できます。

| Method | Endpoint | 用途 |
|---|---|---|
| GET | `/api/health` | ヘルスチェック |
| POST | `/api/sample/load` | サンプルSnapshot作成 |
| POST | `/api/configs/detect` | 単一configのNetwork OS候補 |
| POST | `/api/configs/preview` | 複数configの検出プレビュー |
| POST | `/api/configs/import` | config / ZIPのImportとSnapshot作成 |
| GET | `/api/snapshots` | Snapshot一覧 |
| GET | `/api/devices`、`/api/devices/{device_id}` | 機器一覧・詳細 |
| GET | `/api/policies` | 共通Policy一覧 |
| GET | `/api/matrix`、`/api/matrix/{src}/{dst}` | Matrix・セル根拠 |
| GET | `/api/topology` | Device / SegmentのTopology |
| GET | `/api/reachability` | 経路・Policy・NAT・ECMP解析 |
| GET | `/api/diff?before={id}&after={id}` | Snapshot間Diff |
| GET | `/api/parser/debug` | Canonical Model |
| GET | `/api/parser/warnings` | Warning / Unsupported |
| GET | `/api/parser/capabilities` | Parser対応機能 |

Matrixは `/api/matrix?protocol=tcp&port=443` のように条件を指定します。レスポンスの `evaluation` は条件指定時に `path`、未指定時に `policy_summary` です。Portは0〜65535で、ICMPなどportを使わないProtocolとの併用はできません。

Path解析は `src` / `dst` にSegment IDを指定し、`protocol`、`port`、`source_port`、`ip_version`、`source_ip`、`destination_ip`、`state`、`assume_session`、`icmp_type` を必要に応じて渡します。

| Pathレスポンス | 内容 |
|---|---|
| `result` | 候補経路を集約した判定 |
| `paths` | 経路ごとの判定、path、steps、flow、理由 |
| `paths_complete` | 探索上限による打ち切りがないか。実ネットワーク全体の把握を意味しない |
| `path` / `steps` / `flow` | 互換用の先頭経路。複数候補全体を表さない |
| `flow.original` / `flow.current` | 元の通信情報／当該経路の最終通信情報。各hopのflow.currentはPolicy評価時点 |
| hopの `packet_in` / `packet_out` | 受信時／処理後の通信情報 |
| NAT効果の `before` / `after` / `applied` | 変換前後と適用の有無 |

Importはmultipartの `files`（複数可）、任意の `snapshot_name`、ファイル名をキーにしたJSON文字列の `parser_ids` / `sites` を受け取ります。検出APIのみ単一の `file` を使用します。

## 内部構成とParser追加

```text
Config → Parser Registry → Network OS Parser → CanonicalConfig
                                                 ├─ 設定概要Matrix / Snapshot Diff
                                                 └─ Topology / 経路別探索
                                                     DNAT → routing → Policy → SNAT
                                                          ↓
                                                  ReachabilityResult
                                                          ↓
                                                FastAPI → React UI

SnapshotStore → マスク済みconfig・Canonical ModelをSQLiteへ保存
```

| 場所 | 役割 |
|---|---|
| `backend/app/parsers/` | Network OS検出・構文解析・設定行のTrace |
| `backend/app/models.py` | Device、Segment、Route、Policy、NATなどの共通モデル |
| `backend/app/analyzer.py` / `matrix_query.py` | 設定概要／通信条件付きMatrix |
| `backend/app/reachability.py` / `path_traversal.py` | 入力の解決と、NAT有無に共通の経路探索・集約 |
| `backend/app/path_topology.py` / `path_results.py` | 接続候補の照合・経路とMatrixの判定集約 |
| `backend/app/routing.py` / `policy_engine.py` / `nat_pipeline.py` | 経路候補、Policy、NATの評価 |
| `backend/app/reachability_models.py` | APIに返す経路・通信情報の型 |
| `backend/app/storage.py` / `main.py` | SQLite保存・API |
| `frontend/src/` | React画面・APIクライアント・テーマ |

Parserを追加する場合は、`BaseConfigParser` を実装し、`parser_id`、`ParserCapabilities`、`detect()`、`parse()` を定義します。`@ParserRegistry.register` を付け、`parsers/__init__.py` でimportし、fixture・契約テスト・Golden Testを追加してください。共通モデルに既存の意味を表現できる場合は、AnalyzerやUIの変更は原則不要です。新たな処理順や条件を扱う場合は評価側の対応も必要です。

## 仕様確認に使った資料

- [VyOS 1.4 Firewall](https://docs.vyos.io/en/1.4/configuration/firewall/)、[Zone](https://docs.vyos.io/en/1.4/configuration/firewall/zone.html)、[Static routing](https://docs.vyos.io/en/1.4/configuration/protocols/static.html)、[NAT44](https://docs.vyos.io/en/1.4/configuration/nat/nat44.html)
- [SRX NAT overview](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/security-nat-overview.html)、[RouterOS packet flow](https://help.mikrotik.com/docs/spaces/ROS/pages/328227/Packet%2BFlow%2Bin%2BRouterOS)
- [FortiOS fixed port](https://docs.fortinet.com/document/fortigate/6.2.1/technical-note-fixed-port-on-firewall-policy/12/fd40732)、[Routing concepts](https://docs.fortinet.com/document/fortigate/7.2.10/administration-guide/139692/routing-concepts)
- [Cisco administrative distance](https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/15986-admin-distance.html)、[PAN-OS NAT Policy](https://docs.paloaltonetworks.com/ngfw/networking/nat/nat-policy-rules)
- [AlliedWare Plus x540L 5.5.5 ハードウェアパケットフィルター](https://www.allied-telesis.co.jp/support/list/awp/rel/5.5.5-2.1/613-003277_L/docs/overview-30.html)

## ライセンス

[Apache License 2.0](LICENSE)
