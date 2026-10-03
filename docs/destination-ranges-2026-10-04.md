# 宛先範囲分割の実装・検証（2026-10-04）

宛先Segmentを有効なstatic route・connected subnetの境界でCIDR分割し、範囲ごとに送信元からPolicy・NAT・ECMPを再評価する。後続機器で初めて境界が見つかった場合も再評価するため、手前のPolicyに大きな範囲の評価結果を流用しない。

Pathの各候補は `destination_ranges` にNAT前の宛先を持つ。各pathのflow.originalもその範囲、レスポンス全体のflow.originalは入力範囲を保持する。条件付きMatrixは、経路のない範囲も含めてprotocol・経路番号・範囲・判定を返し、詳細画面に表示する。

IPv4/IPv6、nested prefix、無効経路・別VRFの除外、connected境界、重複範囲、ECMP、SNAT、同一prefix長static DNAT、IPv6 /64内のhost route、上限時の未評価範囲をテストした。128回の評価試行・128候補を上限とし、打切り理由付きPARTIALの範囲を追加する。実機の通信確認は実施していない。

- backend: 338 tests passed
- frontend build: passed
- mocked browser: 28 tests passed（Pathの明暗テーマ・390/1440px、Matrixの390/1280pxを含む）
- real API/browser: 1 scenario passed（config取り込み・永続化・Matrix・Path・再取り込み・Diff・Export・宛先分割表示）

Policy/NATの部分一致条件自体の自動分割、動的ルーティングの実RIBは対象外。NAT変換が未確定なら既存どおりPARTIALを返す。通常のsubnet解析では機器自身のhost IPを分割境界に加えず、機器自身宛ての選択方法を維持する。既存のCisco Null0経路はUNKNOWNとなるため、結合テストのNO_ROUTEケースには到達経路のないgatewayを使用した。
