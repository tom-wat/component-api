// src/index.ts - Cloudflare Workers with Enhanced Security
export interface Env {
  DB: D1Database;
  ENVIRONMENT?: string;
  ADMIN_PASSWORD?: string; // 旧ADMIN_API_KEYから名称変更
  SESSIONS?: KVNamespace; // Cookieセッション用
  JWT_SECRET?: string;
  ACCESS_TOKEN_EXPIRY?: string;
  REFRESH_TOKEN_EXPIRY?: string;
}

import { Router } from 'itty-router';
import { adminRouter } from './admin-routes';
import { authRouter } from './auth-routes';
import { validateAndSanitizeComponent, validateAndSanitizeUpdate } from './utils/validation';
import { requireCSRFProtection } from './middleware/auth';

const router = Router();

// セキュリティヘッダー設定
const getSecurityHeaders = (env: Env) => {
  const isDevelopment = env.ENVIRONMENT === 'development';
  
  return {
    // Content Security Policy
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // Component実行用に制限的に許可
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self' https://component-management.vercel.app",
      isDevelopment ? "connect-src 'self' http://localhost:* ws://localhost:*" : "",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "upgrade-insecure-requests"
    ].filter(Boolean).join('; '),
    
    // XSS Protection
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    
    // HSTS (本番環境のみ)
    ...(isDevelopment ? {} : {
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
    }),
    
    // 参照元ポリシー
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    
    // Permissions Policy
    'Permissions-Policy': [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
      'usb=()',
      'bluetooth=()'
    ].join(', ')
  };
};

// CORS設定 - 環境に応じて動的に設定
const getCorsHeaders = (env: Env, request?: Request) => {
  const isDevelopment = env.ENVIRONMENT === 'development';
  
  let allowedOrigin: string;
  
  if (request) {
    const origin = request.headers.get('Origin');
    
    if (isDevelopment && origin && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
      allowedOrigin = origin; // localhostからのリクエストは許可
    } else {
      allowedOrigin = 'https://component-management.vercel.app'; // その他は本番ドメインのみ
    }
  } else {
    allowedOrigin = 'https://component-management.vercel.app'; // 本番環境では特定のドメインのみ
  }

  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-App-Name',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };
};

// 統合ヘッダー取得関数
const getAllHeaders = (env: Env, request?: Request) => {
  return {
    ...getCorsHeaders(env, request),
    ...getSecurityHeaders(env)
  };
};

// プリフライトリクエスト対応
router.options('*', (request, env: Env) => {
  return new Response(null, { headers: getAllHeaders(env, request) });
});

// ヘルスチェック
router.get('/api/health', (request, env: Env) => {
  const headers = getAllHeaders(env, request);
  return new Response(JSON.stringify({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: '3.0-enhanced-security',
    environment: env.ENVIRONMENT || 'development',
    security: {
      csrf: 'enabled',
      xss: 'enhanced',
      csp: 'strict',
      auth: 'jwt-hybrid'
    }
  }), {
    headers: { ...headers, 'Content-Type': 'application/json' }
  });
});

// コンポーネント一覧取得
router.get('/api/components', async (request, env: Env) => {
  const headers = getAllHeaders(env, request);
  try {
    const url = new URL(request.url);
    const category = url.searchParams.get('category');
    const search = url.searchParams.get('search');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100); // 最大100件
    const offset = parseInt(url.searchParams.get('offset') || '0');

    // 総件数を取得するクエリ（フィルタ条件は同じ）
    let countQuery = `
      SELECT COUNT(*) as total
      FROM components 
      WHERE is_deleted = FALSE
    `;
    let countParams: any[] = [];

    // データ取得用のクエリ
    let dataQuery = `
      SELECT id, name, category, html, css, js, tags, author, 
             created_at, updated_at
      FROM components 
      WHERE is_deleted = FALSE
    `;
    let dataParams: any[] = [];

    // フィルタ条件を両方のクエリに適用
    if (category && category.trim()) {
      countQuery += ' AND category = ?';
      dataQuery += ' AND category = ?';
      countParams.push(category.trim());
      dataParams.push(category.trim());
    }

    if (search && search.trim()) {
      countQuery += ' AND (name LIKE ? OR tags LIKE ?)';
      dataQuery += ' AND (name LIKE ? OR tags LIKE ?)';
      const searchTerm = `%${search.trim()}%`;
      countParams.push(searchTerm, searchTerm);
      dataParams.push(searchTerm, searchTerm);
    }

    dataQuery += ' ORDER BY updated_at DESC LIMIT ? OFFSET ?';
    dataParams.push(limit, offset);

    console.log('Count Query:', countQuery);
    console.log('Count Params:', countParams);
    console.log('Data Query:', dataQuery);
    console.log('Data Params:', dataParams);

    // 総件数とデータを並行取得
    const [countResult, dataResult] = await Promise.all([
      env.DB.prepare(countQuery).bind(...countParams).first(),
      env.DB.prepare(dataQuery).bind(...dataParams).all()
    ]);
    
    const totalCount = (countResult?.total as number) || 0;
    const components = dataResult.results.map(row => ({
      ...row,
      tags: JSON.parse(row.tags as string || '[]'),
      createdAt: new Date(row.created_at as string),
      updatedAt: new Date(row.updated_at as string),
    }));

    return new Response(JSON.stringify({ 
      components,
      total: totalCount,
      hasMore: (offset + components.length) < totalCount
    }), {
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error fetching components:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch components',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  }
});

// 特定コンポーネント取得
router.get('/api/components/:id', async (request, env: Env) => {
  const headers = getAllHeaders(env, request);
  try {
    const { id } = request.params;
    
    if (!id) {
      return new Response(JSON.stringify({ error: 'Component ID is required' }), {
        status: 400,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    const component = await env.DB.prepare(`
      SELECT id, name, category, html, css, js, tags, author, 
             created_at, updated_at
      FROM components 
      WHERE id = ? AND is_deleted = FALSE
    `).bind(id).first();

    if (!component) {
      return new Response(JSON.stringify({ error: 'Component not found' }), {
        status: 404,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    const result = {
      ...component,
      tags: JSON.parse(component.tags as string || '[]'),
      createdAt: new Date(component.created_at as string),
      updatedAt: new Date(component.updated_at as string),
    };

    return new Response(JSON.stringify(result), {
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error fetching component:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch component',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  }
});

// コンポーネント作成
router.post('/api/components', async (request, env: Env) => {
  const headers = getAllHeaders(env, request);
  try {
    // CSRF保護チェック
    const csrfResult = requireCSRFProtection(request, env);
    if (csrfResult) {
      const responseBody = await csrfResult.text();
      return new Response(responseBody, {
        status: csrfResult.status,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }
    const rawData = await request.json() as any;
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    // バリデーションとXSSサニタイゼーション
    const validationResult = validateAndSanitizeComponent(rawData);
    
    if (!validationResult.success) {
      return new Response(JSON.stringify({ 
        error: validationResult.error,
        details: validationResult.details
      }), {
        status: 400,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    const data = validationResult.data!;

    await env.DB.prepare(`
      INSERT INTO components (id, name, category, html, css, js, tags, author, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id, 
      data.name, 
      data.category, 
      data.html, 
      data.css, 
      data.js,
      JSON.stringify(data.tags), 
      'Anonymous', // 後で userId に変更予定
      now, 
      now
    ).run();

    return new Response(JSON.stringify({ 
      id, 
      message: 'Component created successfully' 
    }), {
      status: 201,
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error creating component:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to create component',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  }
});

// コンポーネント更新
router.put('/api/components/:id', async (request, env: Env) => {
  const headers = getAllHeaders(env, request);
  try {
    // CSRF保護チェック
    const csrfResult = requireCSRFProtection(request, env);
    if (csrfResult) {
      const responseBody = await csrfResult.text();
      return new Response(responseBody, {
        status: csrfResult.status,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }
    const { id } = request.params;
    const rawData = await request.json() as any;
    const now = new Date().toISOString();

    if (!id) {
      return new Response(JSON.stringify({ error: 'Component ID is required' }), {
        status: 400,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // コンポーネントの存在確認
    const existing = await env.DB.prepare(
      'SELECT id FROM components WHERE id = ? AND is_deleted = FALSE'
    ).bind(id).first();

    if (!existing) {
      return new Response(JSON.stringify({ error: 'Component not found' }), {
        status: 404,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // バリデーションとXSSサニタイゼーション
    const validationResult = validateAndSanitizeUpdate(rawData);
    
    if (!validationResult.success) {
      return new Response(JSON.stringify({ 
        error: validationResult.error,
        details: validationResult.details
      }), {
        status: 400,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    const data = validationResult.data!;

    // Build dynamic update query
    const updates: string[] = [];
    const params: any[] = [];
    
    if (data.name !== undefined) {
      updates.push('name = ?');
      params.push(data.name);
    }
    if (data.category !== undefined) {
      updates.push('category = ?');
      params.push(data.category);
    }
    if (data.html !== undefined) {
      updates.push('html = ?');
      params.push(data.html);
    }
    if (data.css !== undefined) {
      updates.push('css = ?');
      params.push(data.css);
    }
    if (data.js !== undefined) {
      updates.push('js = ?');
      params.push(data.js);
    }
    if (data.tags !== undefined) {
      updates.push('tags = ?');
      params.push(JSON.stringify(data.tags));
    }
    
    updates.push('updated_at = ?');
    params.push(now, id);
    
    await env.DB.prepare(`
      UPDATE components SET ${updates.join(', ')}
      WHERE id = ?
    `).bind(...params).run();

    return new Response(JSON.stringify({ 
      message: 'Component updated successfully'
    }), {
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error updating component:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to update component',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  }
});

// コンポーネント削除（論理削除）
router.delete('/api/components/:id', async (request, env: Env) => {
  const headers = getAllHeaders(env, request);
  try {
    // CSRF保護チェック
    const csrfResult = requireCSRFProtection(request, env);
    if (csrfResult) {
      const responseBody = await csrfResult.text();
      return new Response(responseBody, {
        status: csrfResult.status,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }
    const { id } = request.params;

    if (!id) {
      return new Response(JSON.stringify({ error: 'Component ID is required' }), {
        status: 400,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    // コンポーネントの存在確認
    const existing = await env.DB.prepare(
      'SELECT id FROM components WHERE id = ? AND is_deleted = FALSE'
    ).bind(id).first();

    if (!existing) {
      return new Response(JSON.stringify({ error: 'Component not found' }), {
        status: 404,
        headers: { ...headers, 'Content-Type': 'application/json' }
      });
    }

    await env.DB.prepare(
      'UPDATE components SET is_deleted = TRUE, updated_at = ? WHERE id = ?'
    ).bind(new Date().toISOString(), id).run();

    return new Response(JSON.stringify({ 
      message: 'Component deleted successfully' 
    }), {
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error deleting component:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to delete component',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  }
});

// 基本統計情報（認証なし）
router.get('/api/stats', async (request, env: Env) => {
  const headers = getAllHeaders(env, request);
  try {
    const totalComponents = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM components WHERE is_deleted = FALSE'
    ).first();

    const recentComponents = await env.DB.prepare(`
      SELECT COUNT(*) as count FROM components 
      WHERE is_deleted = FALSE AND created_at > datetime('now', '-7 days')
    `).first();

    const categoryCounts = await env.DB.prepare(`
      SELECT category, COUNT(*) as count
      FROM components 
      WHERE is_deleted = FALSE
      GROUP BY category
      ORDER BY count DESC
    `).all();

    return new Response(JSON.stringify({
      totalComponents: totalComponents?.count || 0,
      recentComponents: recentComponents?.count || 0,
      categories: categoryCounts.results
    }), {
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch stats',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { ...headers, 'Content-Type': 'application/json' }
    });
  }
});

// 認証ルートの統合
router.all('/api/auth/*', authRouter.handle);

// 管理者ルートの統合
router.all('/api/admin/*', adminRouter.handle);

// 404ハンドラー
router.all('*', (request, env: Env) => {
  const headers = getAllHeaders(env, request);
  return new Response(JSON.stringify({ error: 'Not Found' }), {
    status: 404,
    headers: { ...headers, 'Content-Type': 'application/json' }
  });
});

export default {
  fetch: router.handle,
};