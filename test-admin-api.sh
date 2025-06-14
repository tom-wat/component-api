#!/bin/bash

# Component API - Admin Functions Test Script
echo "🔧 Component API - Admin Functions Test"
echo "======================================"

# ベースURL設定
BASE_URL="http://localhost:8787"
# 本番環境の場合は以下のようにセット
# BASE_URL="https://your-worker.your-subdomain.workers.dev"

echo ""
echo "📊 1. 管理者統計情報取得"
curl -s "$BASE_URL/api/admin/stats" | jq '.'

echo ""
echo "📝 2. 削除されたコンポーネント一覧取得"
curl -s "$BASE_URL/api/admin/deleted-components" | jq '.'

echo ""
echo "📋 3. 全コンポーネント一覧取得（削除済み含む）"
curl -s "$BASE_URL/api/admin/all-components?status=all&limit=5" | jq '.'

echo ""
echo "🗑️ 4. テスト用コンポーネント作成→削除→復元のテスト"

# テスト用コンポーネント作成
echo "   Creating test component..."
COMPONENT_ID=$(curl -s -X POST "$BASE_URL/api/components" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Component for Admin",
    "category": "Test",
    "html": "<div>Test</div>",
    "css": ".test { color: red; }",
    "js": "console.log(\"test\");",
    "tags": "test,admin"
  }' | jq -r '.id')

echo "   Created component with ID: $COMPONENT_ID"

# コンポーネント削除（論理削除）
echo "   Deleting component..."
curl -s -X DELETE "$BASE_URL/api/components/$COMPONENT_ID" | jq '.'

# 削除されたコンポーネントが表示されるか確認
echo "   Checking deleted components list..."
curl -s "$BASE_URL/api/admin/deleted-components" | jq '.components[] | select(.id == "'$COMPONENT_ID'") | {id, name, updatedAt}'

# コンポーネント復元
echo "   Restoring component..."
curl -s -X POST "$BASE_URL/api/admin/components/$COMPONENT_ID/restore" | jq '.'

# 復元されたか確認
echo "   Checking if component is restored..."
curl -s "$BASE_URL/api/components/$COMPONENT_ID" | jq '{id, name, createdAt, updatedAt}'

# 再度削除して完全削除のテスト
echo ""
echo "💀 5. 完全削除のテスト"
echo "   Deleting component again..."
curl -s -X DELETE "$BASE_URL/api/components/$COMPONENT_ID" | jq '.'

echo "   Permanently deleting component..."
curl -s -X DELETE "$BASE_URL/api/admin/components/$COMPONENT_ID/purge" | jq '.'

# 完全削除されたか確認
echo "   Checking if component is permanently deleted..."
RESULT=$(curl -s "$BASE_URL/api/components/$COMPONENT_ID")
echo "   Result: $RESULT"

echo ""
echo "🧹 6. 古いコンポーネント一括削除のテスト（dry run）"
curl -s "$BASE_URL/api/admin/purge-old?days=365" | jq '.'

echo ""
echo "✅ Admin API Test Complete!"
echo ""
echo "🚀 Available Admin Endpoints:"
echo "   GET    /api/admin/stats                     - 管理者統計情報"
echo "   GET    /api/admin/deleted-components        - 削除されたコンポーネント一覧"
echo "   GET    /api/admin/all-components            - 全コンポーネント一覧"
echo "   POST   /api/admin/components/:id/restore    - コンポーネント復元"
echo "   DELETE /api/admin/components/:id/purge      - コンポーネント完全削除"
echo "   DELETE /api/admin/purge-old?days=30         - 古いコンポーネント一括削除"
