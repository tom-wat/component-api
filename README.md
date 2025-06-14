# Component Management API

Cloudflare Workers + D1を使用したコンポーネント管理APIです。

## 🚀 セットアップ

### 1. 依存関係のインストール

```bash
cd component-api
npm install
```

### 2. Cloudflare環境の設定

```bash
# Cloudflareにログイン
npx wrangler login

# D1データベースを作成
npx wrangler d1 create component-db
```

上記コマンドで表示されるdatabase_idをコピーして、`wrangler.toml`の該当箇所に貼り付けてください。

### 3. データベースの初期化

```bash
# スキーマとサンプルデータの適用
npx wrangler d1 execute component-db --file=./schema.sql
```

### 4. 開発サーバーの起動

```bash
npm run dev
```

### 5. 動作確認

```bash
# ヘルスチェック
curl http://localhost:8787/api/health

# コンポーネント一覧取得
curl http://localhost:8787/api/components

# 統計情報取得
curl http://localhost:8787/api/stats
```

## 📋 API エンドポイント

### コンポーネント管理

- `GET /api/components` - コンポーネント一覧取得
- `GET /api/components/:id` - 特定コンポーネント取得
- `POST /api/components` - 新規コンポーネント作成
- `PUT /api/components/:id` - コンポーネント更新
- `DELETE /api/components/:id` - コンポーネント削除（論理削除）

### その他

- `GET /api/stats` - 統計情報取得
- `GET /api/health` - ヘルスチェック

## 🔧 クエリパラメータ

### GET /api/components

- `category` - カテゴリでフィルタ
- `search` - 名前・タグで検索
- `limit` - 取得件数（最大100、デフォルト50）
- `offset` - オフセット（デフォルト0）

例:
```
/api/components?category=UI&search=ボタン&limit=20
```

## 📦 リクエスト/レスポンス例

### POST /api/components

```json
{
  "name": "プライマリボタン",
  "category": "UI",
  "html": "<button class=\"btn-primary\">Click me</button>",
  "css": ".btn-primary { background: blue; color: white; }",
  "js": "document.querySelector('.btn-primary').addEventListener('click', () => alert('clicked'));",
  "tags": "ボタン,プライマリ,UI"
}
```

### レスポンス

```json
{
  "id": "uuid-here",
  "message": "Component created successfully"
}
```

## 🚀 デプロイ

```bash
npm run deploy
```

## 🔒 セキュリティ

現在は認証なしの実装です。Phase 3で認証機能を追加予定。

## 📊 データベーススキーマ

```sql
CREATE TABLE components (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  html TEXT NOT NULL DEFAULT '',
  css TEXT NOT NULL DEFAULT '',
  js TEXT NOT NULL DEFAULT '',
  tags TEXT NOT NULL DEFAULT '',
  author TEXT NOT NULL DEFAULT 'Anonymous',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  is_deleted BOOLEAN DEFAULT FALSE
);
```

## 🐛 トラブルシューティング

### データベース接続エラー

1. `wrangler.toml`のdatabase_idが正しく設定されているか確認
2. `npx wrangler d1 list`でデータベースが作成されているか確認

### CORS エラー

APIはCORS設定済みです。`localhost:3000`からのアクセスが可能です。

## 📝 TODO

- [ ] 認証機能の追加
- [ ] バージョン管理機能
- [ ] リアルタイム同期
- [ ] ページネーション改善