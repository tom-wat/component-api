// src/admin-routes.ts - 管理者向けAPIエンドポイント（認証保護済み）
import { Router } from 'itty-router';
import { requireAdminAuthWithRateLimit, requireCSRFProtection } from './middleware/auth';

export interface Env {
  DB: D1Database;
  ENVIRONMENT?: string;
  ADMIN_PASSWORD?: string;
  SESSIONS?: KVNamespace;
}

const adminRouter = Router({ base: '/api/admin' });

// CORS設定関数 - 環境に応じて動的に設定
const getCorsHeaders = (env: Env, request?: Request) => {
  const isDevelopment = env.ENVIRONMENT === 'development';
  
  let allowedOrigin: string;
  
  if (request) {
    const origin = request.headers.get('Origin');
    console.log('Request origin:', origin, 'isDevelopment:', isDevelopment);
    
    if (isDevelopment && origin && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
      allowedOrigin = origin; // localhostからのリクエストは許可
      console.log('Using localhost origin:', allowedOrigin);
    } else {
      allowedOrigin = 'https://component-management.vercel.app'; // その他は本番ドメインのみ
      console.log('Using production origin:', allowedOrigin);
    }
  } else {
    allowedOrigin = 'https://component-management.vercel.app'; // 本番環境では特定のドメインのみ
    console.log('No request, using default origin:', allowedOrigin);
  }

  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };
};

// Admin認証ミドルウェア - OPTIONSリクエスト以外のすべてのadminルートに適用
adminRouter.all('*', async (request, env: Env) => {
  // OPTIONSリクエストはプリフライト用なので認証をスキップ
  if (request.method === 'OPTIONS') {
    return; // 次のハンドラー（options handler）に進む
  }
  
  const corsHeaders = getCorsHeaders(env, request);
  
  // CSRF保護チェック（状態変更操作のみ）
  const csrfResult = requireCSRFProtection(request, env);
  if (csrfResult) {
    const responseBody = await csrfResult.text();
    return new Response(responseBody, {
      status: csrfResult.status,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
  
  // 認証チェック
  const authResult = await requireAdminAuthWithRateLimit(request, env);
  if (authResult) {
    // 認証失敗時はエラーレスポンスを直接返す
    const responseBody = await authResult.text();
    return new Response(responseBody, {
      status: authResult.status,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
  // 認証成功時は次のハンドラーに進む
});

// プリフライトリクエスト対応 - 認証ミドルウェアの後に配置
adminRouter.options('*', (request, env: Env) => {
  const corsHeaders = getCorsHeaders(env, request);
  console.log('OPTIONS handler called with corsHeaders:', corsHeaders);
  return new Response(null, { headers: corsHeaders });
});

// 削除されたコンポーネント一覧取得
adminRouter.get('/deleted-components', async (request, env: Env) => {
  const corsHeaders = getCorsHeaders(env, request);
  try {
    const url = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
    const offset = parseInt(url.searchParams.get('offset') || '0');

    const result = await env.DB.prepare(`
      SELECT id, name, category, html, css, js, tags, author, 
             created_at, updated_at
      FROM components 
      WHERE is_deleted = TRUE
      ORDER BY updated_at DESC 
      LIMIT ? OFFSET ?
    `).bind(limit, offset).all();
    
    const components = result.results.map(row => ({
      ...row,
      tags: JSON.parse(row.tags as string || '[]'),
      createdAt: new Date(row.created_at as string),
      updatedAt: new Date(row.updated_at as string),
    }));

    return new Response(JSON.stringify({ 
      components,
      total: components.length,
      hasMore: components.length === limit
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error fetching deleted components:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch deleted components',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// コンポーネント復元
adminRouter.post('/components/:id/restore', async (request, env: Env) => {
  const corsHeaders = getCorsHeaders(env, request);
  try {
    const { id } = request.params;

    if (!id) {
      return new Response(JSON.stringify({ error: 'Component ID is required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // 削除されたコンポーネントの存在確認
    const existing = await env.DB.prepare(
      'SELECT id FROM components WHERE id = ? AND is_deleted = TRUE'
    ).bind(id).first();

    if (!existing) {
      return new Response(JSON.stringify({ error: 'Deleted component not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // 復元処理
    await env.DB.prepare(
      'UPDATE components SET is_deleted = FALSE, updated_at = ? WHERE id = ?'
    ).bind(new Date().toISOString(), id).run();

    return new Response(JSON.stringify({ 
      message: 'Component restored successfully' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error restoring component:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to restore component',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// コンポーネント完全削除
adminRouter.delete('/components/:id/purge', async (request, env: Env) => {
  const corsHeaders = getCorsHeaders(env, request);
  try {
    const { id } = request.params;

    if (!id) {
      return new Response(JSON.stringify({ error: 'Component ID is required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // 削除されたコンポーネントの存在確認
    const existing = await env.DB.prepare(
      'SELECT id FROM components WHERE id = ? AND is_deleted = TRUE'
    ).bind(id).first();

    if (!existing) {
      return new Response(JSON.stringify({ error: 'Deleted component not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // 完全削除処理
    await env.DB.prepare(
      'DELETE FROM components WHERE id = ?'
    ).bind(id).run();

    return new Response(JSON.stringify({ 
      message: 'Component permanently deleted' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error purging component:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to purge component',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// 古いコンポーネント一括完全削除
adminRouter.delete('/purge-old', async (request, env: Env) => {
  const corsHeaders = getCorsHeaders(env, request);
  try {
    const url = new URL(request.url);
    const days = parseInt(url.searchParams.get('days') || '30');

    if (days < 1) {
      return new Response(JSON.stringify({ error: 'Days must be at least 1' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // 指定日数以前に削除されたコンポーネントを取得
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    const cutoffISO = cutoffDate.toISOString();

    const toDelete = await env.DB.prepare(`
      SELECT id, name FROM components 
      WHERE is_deleted = TRUE AND updated_at < ?
    `).bind(cutoffISO).all();

    if (toDelete.results.length === 0) {
      return new Response(JSON.stringify({ 
        message: 'No old deleted components found',
        deleted: 0
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // 完全削除実行
    await env.DB.prepare(`
      DELETE FROM components 
      WHERE is_deleted = TRUE AND updated_at < ?
    `).bind(cutoffISO).run();

    return new Response(JSON.stringify({ 
      message: `${toDelete.results.length} old components permanently deleted`,
      deleted: toDelete.results.length,
      deletedComponents: toDelete.results.map(row => ({ id: row.id, name: row.name }))
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error purging old components:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to purge old components',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// 管理者統計情報
adminRouter.get('/stats', async (request, env: Env) => {
  const corsHeaders = getCorsHeaders(env, request);
  try {
    const totalComponents = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM components WHERE is_deleted = FALSE'
    ).first();

    const deletedComponents = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM components WHERE is_deleted = TRUE'
    ).first();

    const recentDeleted = await env.DB.prepare(`
      SELECT COUNT(*) as count FROM components 
      WHERE is_deleted = TRUE AND updated_at > datetime('now', '-7 days')
    `).first();

    const categoryCounts = await env.DB.prepare(`
      SELECT category, 
             COUNT(*) as total,
             SUM(CASE WHEN is_deleted = FALSE THEN 1 ELSE 0 END) as active,
             SUM(CASE WHEN is_deleted = TRUE THEN 1 ELSE 0 END) as deleted
      FROM components 
      GROUP BY category
      ORDER BY total DESC
    `).all();

    return new Response(JSON.stringify({
      totalComponents: totalComponents?.count || 0,
      deletedComponents: deletedComponents?.count || 0,
      recentDeleted: recentDeleted?.count || 0,
      categoriesStats: categoryCounts.results
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error fetching admin stats:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch admin stats',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// 全コンポーネント一覧（削除済み含む）
adminRouter.get('/all-components', async (request, env: Env) => {
  const corsHeaders = getCorsHeaders(env, request);
  try {
    const url = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const status = url.searchParams.get('status'); // 'active', 'deleted', 'all'

    let whereClause = '';
    if (status === 'active') {
      whereClause = 'WHERE is_deleted = FALSE';
    } else if (status === 'deleted') {
      whereClause = 'WHERE is_deleted = TRUE';
    }
    // status === 'all' または未指定の場合は条件なし

    const result = await env.DB.prepare(`
      SELECT id, name, category, author, created_at, updated_at, is_deleted
      FROM components 
      ${whereClause}
      ORDER BY updated_at DESC 
      LIMIT ? OFFSET ?
    `).bind(limit, offset).all();
    
    const components = result.results.map(row => ({
      ...row,
      createdAt: new Date(row.created_at as string),
      updatedAt: new Date(row.updated_at as string),
      isDeleted: Boolean(row.is_deleted)
    }));

    return new Response(JSON.stringify({ 
      components,
      total: components.length,
      hasMore: components.length === limit
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error fetching all components:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch all components',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

export { adminRouter };
