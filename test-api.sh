#!/bin/bash

# Component API テストスクリプト
# 使用方法: ./test-api.sh [BASE_URL]
# 例: ./test-api.sh http://localhost:8787

BASE_URL=${1:-"http://localhost:8787"}

echo "🧪 Component API Test Suite"
echo "Base URL: $BASE_URL"
echo "=========================="

# ヘルスチェック
echo "1. ヘルスチェック"
curl -s "$BASE_URL/api/health" | jq '.'
echo ""

# 統計情報取得
echo "2. 統計情報取得"
curl -s "$BASE_URL/api/stats" | jq '.'
echo ""

# コンポーネント一覧取得
echo "3. コンポーネント一覧取得"
curl -s "$BASE_URL/api/components" | jq '.'
echo ""

# 新しいコンポーネント作成
echo "4. 新しいコンポーネント作成"
COMPONENT_ID=$(curl -s -X POST "$BASE_URL/api/components" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "テストボタン",
    "category": "UI",
    "html": "<button class=\"test-btn\">Test</button>",
    "css": ".test-btn { background: red; color: white; padding: 8px 16px; }",
    "js": "console.log(\"Test button loaded\");",
    "tags": "テスト,ボタン"
  }' | jq -r '.id')

echo "Created component ID: $COMPONENT_ID"
echo ""

# 作成したコンポーネントを取得
if [ "$COMPONENT_ID" != "null" ] && [ -n "$COMPONENT_ID" ]; then
  echo "5. 作成したコンポーネントを取得"
  curl -s "$BASE_URL/api/components/$COMPONENT_ID" | jq '.'
  echo ""

  # コンポーネント更新
  echo "6. コンポーネント更新"
  curl -s -X PUT "$BASE_URL/api/components/$COMPONENT_ID" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "更新されたテストボタン",
      "category": "UI",
      "html": "<button class=\"test-btn updated\">Updated Test</button>",
      "css": ".test-btn.updated { background: green; color: white; padding: 10px 20px; }",
      "js": "console.log(\"Updated test button loaded\");",
      "tags": "テスト,ボタン,更新済み"
    }' | jq '.'
  echo ""

  # 更新後のコンポーネント確認
  echo "7. 更新後のコンポーネント確認"
  curl -s "$BASE_URL/api/components/$COMPONENT_ID" | jq '.'
  echo ""

  # コンポーネント削除
  echo "8. コンポーネント削除"
  curl -s -X DELETE "$BASE_URL/api/components/$COMPONENT_ID" | jq '.'
  echo ""
else
  echo "❌ コンポーネントの作成に失敗しました"
fi

# 検索テスト
echo "9. 検索テスト (カテゴリ: UI)"
curl -s "$BASE_URL/api/components?category=UI" | jq '.'
echo ""

echo "10. 検索テスト (キーワード: ボタン)"
curl -s "$BASE_URL/api/components?search=ボタン" | jq '.'
echo ""

echo "✅ テスト完了"