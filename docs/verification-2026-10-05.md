# 合成config・ネイティブRouterOSによる検証（2026-10-05）

## 結果

- Backend: 427 tests passed（今回追加13件を含む）。
- Frontend: production build成功、画面E2E 37件、実API統合13件成功。
- API受入: 5ベンダー・7合成構成の変更前後、および実機形式のRouterOS exportの変更前後が期待値と一致。
- ネイティブ: MikroTik CHR 7.23.7、TCP許可/拒否・ゲスト隔離・DNAT・変更後拒否の6ケース成功。許可はTCP 3-way handshake、拒否は転送されないこととdropカウンタを確認。
- 使用したCHR raw image SHA-256: `d97f5b2bb93e84bc7f7a7043cc262c9d8e8a2395055b795a36fa4acd9bc9b240`。

## 証跡と再現方法

- [検証ラボの手順・仕様参照・制約](../lab/README.md)
- [受入チェック結果](../lab/evidence/acceptance.json)
- [ネイティブ通信結果・exportハッシュ](../lab/evidence/routeros/native.json)
- [CHRの変更前export](../lab/evidence/routeros/routeros-before.rsc)
- [CHRの変更後export](../lab/evidence/routeros/routeros-after.rsc)

合成configの期待値は仕様から記載し、実装の出力を正解として生成していない。実機exportでは、ヘッダー検出および値の途中の改行を含めて自動検出・取り込みを確認した。証跡のexportと投入用configはハッシュで対応を検証する。通常CIは保存済みexportを検証し、CHR起動は明示的なDockerコマンドで再実行する。

## 発見・修正した不具合

- CiscoのIPv4/IPv6 ACL混在時に別familyのchainまで評価する誤判定。
- VyOS / RouterOSのinterface条件不一致でchain自体を落とし、既定拒否を見失う問題。
- Diffで同名・同番号の別family chainが衝突する問題と、状態・未対応条件等の変更比較漏れ。
- RouterOSの日時付きexportヘッダーの検出不足、および `connection-state=` の後の改行連結による状態条件の欠落。

## 確認範囲

API受入はImport、機器・interface等の件数、Topology、Policies、Debug/Warnings、Path、条件付きMatrix、Diff、バックアップ・復元を対象にする。画面統合は7構成の変更前後の全Pathケースと、既存のMatrix・Diff・履歴・復元フローを確認した。

dual-stack同士の条件付きMatrixはfamily指定がなくUNKNOWNとなる既存制約を維持している。PathはIPv4/IPv6を別々に検証した。未対応のTCP flags条件はPARTIALを期待し、条件削除でALLOWとなることとDiffにその変更が出ることを確認した。

ネイティブ実通信はRouterOSのIPv4・単一機器が対象。他ベンダー実OS、IPv6・ECMPの実通信、実機ハードウェア、本番configの網羅性は確認していない。アプリの静的判定を実ネットワーク全体の動作保証とは扱わない。

既存アプリのDB・Snapshotを使わず、一時DBと専用ポートで検証した。CHRの実行は外部ネットワークなし・ホストポート公開なし・特権なしの検証コンテナに限定した。既存アプリの再起動・デプロイは行っていない。Parser修正は元configの通常Importで反映され、保存済みCanonical Modelを復元するだけでは再解析されない。
