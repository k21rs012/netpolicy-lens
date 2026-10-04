# Policy・NAT宛先範囲分割（2026-10-05）

## 実装

既存の経路境界による再評価をPolicy・NATの宛先条件へ拡張した。実際に評価したルールの部分一致を検出し、既知の境界で元の宛先CIDRを分割して送信元から再実行する。ルール順序、jump/return、NAT除外、ECMP各候補を維持する。同サイズのstatic DNATでは変換後の境界をNAT前へ投影する。多対一DNAT後の宛先はhostなので追加分割を行わない。

PolicyはIPv4/IPv6 CIDR・host・IP範囲・ネストしたアドレスグループ・否定条件、NATは解決可能な宛先CIDR・host・object・否定・除外条件が対象。FortiOS VIPは宛先分割後に重複一致を判定する。実際の重複は引き続きPARTIAL。

Path・条件付きMatrixには既存の宛先範囲表示を利用する。条件付きDiffは範囲ごとの判定も比較し、PARTIAL→PARTIALでも許可範囲が変われば表示する。単なるCIDR分割形状・経路順序の変化は通信差分に数えない。Diffには変更前後の範囲一覧を追加した。

## 検証

- Backend 399件成功。IPv4/IPv6・group・否定・ルール順序・jump/return・IP範囲・未解決送信元・DNAT投影・NAT除外・宛先条件付きSNAT・ECMP・探索上限・VIP重複・DiffのPARTIAL同士の変化を含む。
- 画面E2E36件成功。
- 実API統合5件成功。合成configを専用一時DBへImportし、Path・Matrix・Diffで上下半分の許可/拒否を確認。追加ケースは最終調整後も単独で成功。
- Frontendビルド成功。モバイル390pxで変更前後の範囲表示を画像確認。

## 制約・反映

送信元IP・portの分割、未解決object、動的pool/PATの確定、未対応OSのNAT処理順は対象外。範囲分割でそれらを確定扱いにはしない。再評価128回・候補128件の既存上限を維持し、未評価範囲はPARTIALとして残す。新規許可・拒否集計はSegment全体で確定したサービスの件数であり、部分範囲の件数ではない。

既存Canonical Modelにも適用できる評価処理の変更。Parser自体の対応範囲は変えていない。検証はローカル・一時DBで行い、実データ変更や稼働環境へのデプロイは行っていない。
