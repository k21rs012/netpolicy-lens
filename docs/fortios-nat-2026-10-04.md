# FortiOS NAT拡張（2026-10-04）

## 実装

- IPv4・単一IPのVIP、単一TCP/UDP port forwarding、VIP groupを正規化。
- DNAT後にrouting・Policyを評価。VIP名の一致をmapped IPの一致から分離し、VIP用Policyで内部IPへの直接通信を許可しない。
- Interface subnet外の公開VIPは論理Segmentとして選択できる。
- 単一IPのoverload/one-to-one IP poolをPolicy SNATに適用。選ばれたPolicyだけがSNATを起動する。
- central NAT有効時はPolicy SNATを無視し、central-snat-mapの順序、move、Interface、アドレス、protocol、port条件を評価。NAT除外も後続ルールへのfall-throughを止める。
- fixedportと明示的な単一port変換を扱い、動的PATはsource portを未確定にしてPARTIALを保持する。
- VIP→Policy→SNAT後のpacketを後続機器へ引き継ぐ。既存のPath表示・条件付きMatrixから利用できる。

新しいフィールドは既定値付きで旧Snapshotを読み取り可能。旧Snapshotの解析結果自体は変更しないため、VIP/IP pool/central NATを含むconfigは再取り込みが必要。

## 制約

複数pool・pool範囲・VIP範囲・負荷分散・port範囲変換・重複VIP・未参照VIPのlocal処理・VIP逆方向SNATの優先順位・NGFW policy-basedモードは理由付きPARTIAL。非VIP denyルールのmatch-vip省略やVIPの否定・通常addressとの混在なども断定しない。IPv6 NAT、複数VDOMの分離、PAN-OS/Cisco/YamahaのNAT処理順は今回の実装対象外。

## 検証

- backend: 365 tests passed（今回追加27件）
- frontend build: passed
- 実API/browser: 2 scenarios passed。FortiOSの自動検出・取り込み・再読込・VIPのIP/port変換表示・内部IP直接通信の拒否を含む。
- backendではJSON保存・復元、central NATの除外・無効化・move・条件不一致、pool未定義、動的PAT、後続機器のPolicy、条件付きMatrix、不確定設定を確認。
- 実機通信・本番反映は未実施。

## 参照仕様

- [Static virtual IPs](https://docs.fortinet.com/document/fortigate/7.6.2/administration-guide/510402/static-virtual-ips)
- [Central SNAT](https://docs.fortinet.com/document/fortigate/7.0.0/administration-guide/421028/central-snat)
- [central-snat-map CLI](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/135632652/config-firewall-central-snat-map)
- [VIPとPolicyの優先順位](https://docs.fortinet.com/document/fortigate/7.2.0/best-practices/862226/policies)
