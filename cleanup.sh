#!/bin/bash

echo "🗑️ 不要なスクリプトファイルを削除中..."

# 削除するファイルのリスト
files_to_delete=(
    "check-status.sh"
    "manual-check.sh" 
    "set-worker-url.sh"
    "update-frontend-env.sh"
)

for file in "${files_to_delete[@]}"; do
    if [ -f "$file" ]; then
        rm "$file"
        echo "   ✅ 削除: $file"
    else
        echo "   ⚠️  見つかりません: $file"
    fi
done

echo ""
echo "🧹 クリーンアップ完了!"
echo "📋 残されたファイル:"
echo "   - deploy.sh         (デプロイ用)"
echo "   - test-admin-api.sh (管理者APIテスト用)"
echo "   - test-api.sh       (基本APIテスト用)"
echo ""
echo "✅ component-apiディレクトリがシンプルになりました"

# このスクリプト自身も削除
rm -- "$0"
