#!/bin/bash

echo "🚀 Component API - Cloudflare Workersデプロイスクリプト"
echo "================================================="

# 現在のディレクトリを確認
if [ ! -f "wrangler.toml" ]; then
    echo "❌ エラー: component-apiディレクトリで実行してください"
    exit 1
fi

echo ""
echo "📋 デプロイ前チェック..."

# 1. 必要なファイルの存在確認
echo "   ✓ 必要ファイルの確認..."
if [ ! -f "src/index.ts" ]; then
    echo "   ❌ src/index.ts が見つかりません"
    exit 1
fi

if [ ! -f "src/admin-routes.ts" ]; then
    echo "   ❌ src/admin-routes.ts が見つかりません"
    exit 1
fi

echo "   ✓ 全ての必要ファイルが存在します"

# 2. TypeScriptの型チェック
echo "   ✓ TypeScript型チェック..."
npx tsc --noEmit
if [ $? -ne 0 ]; then
    echo "   ❌ TypeScriptエラーがあります。修正してからデプロイしてください"
    exit 1
fi

echo "   ✓ TypeScript型チェック完了"

echo ""
echo "🚀 Cloudflare Workersにデプロイ中..."

# 本番環境にデプロイ
npx wrangler deploy

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ デプロイ成功！"
    echo ""
    echo "📋 デプロイされた機能:"
    echo "   - 基本CRUD API (/api/components)"
    echo "   - 統計情報 API (/api/stats)"
    echo "   - 🆕 管理者API (/api/admin/*)"
    echo "     - GET /api/admin/stats"
    echo "     - GET /api/admin/deleted-components"
    echo "     - POST /api/admin/components/:id/restore"
    echo "     - DELETE /api/admin/components/:id/purge"
    echo "     - DELETE /api/admin/purge-old?days=30"
    echo ""
    echo "🧪 動作確認:"
    echo "   1. Cloudflareダッシュボードでworker URLを確認"
    echo "   2. https://your-worker.workers.dev/api/health でテスト"
    echo "   3. https://your-worker.workers.dev/api/admin/stats で管理者API確認"
else
    echo ""
    echo "❌ デプロイ失敗"
    echo "   エラーログを確認して問題を修正してください"
    exit 1
fi
