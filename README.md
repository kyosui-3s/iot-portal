# IoT Device Portal (sub.3sec-demo.com)

Securify DAST デモ用の脆弱性診断対象アプリケーション。

## 構成

- **フロントエンド**: Vue 3 SPA（Hash Router）
- **バックエンド**: Flask + GraphQL API
- **DB**: SQLite

## 機能（4画面）

| 画面 | 説明 |
|------|------|
| ログイン | 代理店コード（DLR-XXXX）入力必須 |
| ダッシュボード | KPIカード + デバイス稼働推移 |
| デバイス検索 | GraphQL経由のデバイス検索 |
| お問い合わせ | 問い合わせフォーム |

## 起動

```bash
pip install -r requirements.txt
python app.py
```

http://localhost:5000 でアクセス

## 注意

**このアプリには意図的に脆弱性が含まれています。本番環境では使用しないでください。**
