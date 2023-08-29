# セキュアメッセンジャー

セキュアメッセンジャー スマートコントラクトと暗号化
このリポジトリは、Solidity と暗号化技術を使用して Ethereum 上に構築されたセキュアメッセージングスマートコントラクトの例を提供します。このコントラクトにより、2人の参加者は暗号化されたメッセージを交換できますが、意図した受信者のみがメッセージの復号と読み取りができます。

SecureMessenger.sol - スマートコントラクト
SecureMessenger.sol スマートコントラクトは、セキュアなメッセージングシステムを定義しています。以下に主な特徴を示します：

- 参加者はコントラクトのデプロイ時に定義されます。
- メッセージはブロックチェーン上で暗号化された形式で保存されます。
- メッセージは AES-256-GCM 暗号化を使用して暗号化されます。
- 参加者のみがメッセージを送信および読み取りできます。
SecureMessenger.sol ファイルで完全な Solidity コードを見つけることができます。

### 暗号化と復号
暗号化および復号のプロセスは、SecureTool クラスで楕円曲線暗号（ECC）と AES-256-GCM 暗号化アルゴリズムを使用して処理されます。以下に関与する手順を示します：

- 参加者はシードフレーズから ECC キーペアを生成します。
- メッセージを送信する際、送信者は ECC キーペアから派生した共有秘密鍵を使用してメッセージを AES-256-GCM で暗号化します。
- 暗号化されたメッセージはその後ブロックチェーンに保存されます。
- 受信者は同じ共有秘密鍵を使用してメッセージを復号化できます。
SecureTool クラス内に暗号化および復号のメソッドがあることを確認してください。

### 注意事項

- この例は教育目的で提供されており、本格的なメッセージングシステムのすべての側面をカバーしているわけではありません。
- 参加者の秘密鍵とデータのセキュリティとプライバシーを確保するための注意が必要です。
- ブロックチェーン上でより洗練されたセキュアなコミュニケーションシステムを構築するために、この例を探求し、変更し、拡張することを自由に行ってください。

### 使い方

```shell
yarn install

yarn deploy

yarn test
