# Matrix・DiffのIP family選択（2026-10-08）

MatrixとSnapshot Diffに自動／IPv4／IPv6の選択を追加した。Matrix一覧・詳細・表示範囲APIとDiffは `ip_version=4|6` を受け取り、Pathと同じfamily指定で評価する。レスポンス・表示条件・キャッシュ・ページ切り替え・検索にもfamilyを保持する。

Cisco / VyOSのdual-stack検証構成では、変更後のIPv4 HTTPSがDENY、IPv6 HTTPSがALLOWとなることをPath・Matrixで照合した。DiffはIPv4のALLOW→DENYを表示し、変更のないIPv6では通信差分を出さない。Policy・Network変更の一覧は通信条件による絞り込み対象外。

未指定時の互換動作を維持し、全条件未指定なら設定概要を表示する。familyのみ指定した経路評価はTCP・UDP・SCTPを集約する。family自動でIPv4/IPv6を確定できない場合や、選択familyのアドレスを持たないSegmentはUNKNOWN。後者はPathでも誤ってSAME_SEGMENT/ALLOWにしない。ICMPのfamily不一致と4/6以外の入力はMatrix・Diff APIで422となる。

確認結果:

- Backend 436 tests passed。追加9件でPath一致、一覧・詳細・範囲API、family別キャッシュ、Diff、入力検証、familyのみ指定、アドレス不在を確認。
- Frontend build成功、画面E2E 38件、実API統合14件成功。
- 実ブラウザでIPv4/IPv6の切替、詳細表示、Diff、390pxでのレイアウトを確認。
- 既存の7合成構成と保存済みRouterOS exportの受入検証成功。今回は仮想機器の再起動・実通信再検証は行っていない。

[ラボ](../lab/README.md) と [期待値の検証結果](../lab/evidence/acceptance.json) を更新した。2026-10-05時点の記録にあるfamily未指定Matrixの制約は、familyを選択することで回避できる。既存の稼働アプリへのデプロイ・再起動はこの作業には含めない。
