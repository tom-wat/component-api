// src/auth-routes.ts - 認証関連エンドポイント
import { Router } from 'itty-router';
import { constantTimeEquals, requireCSRFProtection } from './middleware/auth';
import { JWTManager } from './jwt';

export interface Env {
  ADMIN_PASSWORD?: string;
  SESSIONS?: KVNamespace;
  ENVIRONMENT?: string;
  JWT_SECRET?: string;
  ACCESS_TOKEN_EXPIRY?: string;
  REFRESH_TOKEN_EXPIRY?: string;
}

const authRouter = Router({ base: '/api/auth' });

// CORS設定を統一
const corsHeaders = {
  'Access-Control-Allow-Origin': 'https://component-management.vercel.app',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
  'Access-Control-Allow-Credentials': 'true',
  'Access-Control-Max-Age': '86400',
};

// CORS設定関数を追加
function getCorsHeaders(origin: string | null): Record<string, string> {
  // 本番環境では特定のオリジンのみ許可
  const allowedOrigins = [
    'https://component-management.vercel.app',
    'http://localhost:3000', // 開発環境用
    'http://localhost:5173'  // Vite開発サーバー用
  ];
  
  const corsOrigin = origin && allowedOrigins.includes(origin) 
    ? origin 
    : 'https://component-management.vercel.app';
  
  return {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };
}

// プリフライトリクエスト対応
authRouter.options('*', () => {
  return new Response(null, { headers: corsHeaders });
});

// ログイン認証
authRouter.post('/login', async (request, env: Env) => {
  try {
    // CSRF保護チェック
    const csrfResult = requireCSRFProtection(request, env);
    if (csrfResult) {
      const responseBody = await csrfResult.text();
      return new Response(responseBody, {
        status: csrfResult.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    const body = await request.json() as { password?: string };
    const { password } = body;
    
    if (!password) {
      
      return new Response(JSON.stringify({
        error: 'Password required',
        message: 'Please provide admin password'
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const adminPassword = env.ADMIN_PASSWORD;
    
    if (!adminPassword) {
      console.error('ADMIN_PASSWORD not configured');
      
      return new Response(JSON.stringify({
        error: 'Authentication not configured',
        message: 'Please contact system administrator'
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // パスワード検証
    if (!constantTimeEquals(password, adminPassword)) {
      console.warn(`Invalid admin password attempt from ${request.headers.get('cf-connecting-ip') || 'unknown IP'}`);
      
      
      return new Response(JSON.stringify({
        error: 'Invalid password',
        message: 'Incorrect admin password'
      }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // セッション作成
    if (!env.SESSIONS) {
      console.error('SESSIONS KV not configured');
      
      return new Response(JSON.stringify({
        error: 'Session storage not configured',
        message: 'Please contact system administrator'
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const sessionId = crypto.randomUUID();
    const sessionData = {
      isAdmin: true,
      createdAt: Date.now(),
      ip: request.headers.get('cf-connecting-ip') || 'unknown'
    };

    // セッションをKVに保存（270日間）
    const sessionTTL = 270 * 24 * 60 * 60; // 270日を秒に変換
    await env.SESSIONS.put(sessionId, JSON.stringify(sessionData), {
      expirationTtl: sessionTTL
    });

    console.log(`Admin login successful from ${sessionData.ip}`);
    
    // JWT認証も併用
    let jwtTokens = null;
    if (env.JWT_SECRET) {
      try {
        const jwtManager = JWTManager.fromEnv(env);
        jwtTokens = await jwtManager.generateTokens('admin');
      } catch (error) {
        console.warn('JWT generation failed, falling back to cookie-only auth:', error);
      }
    }
    
    const responseBody = {
      success: true,
      message: 'Authentication successful',
      expiresIn: sessionTTL,
      ...(jwtTokens && {
        accessToken: jwtTokens.accessToken,
        refreshToken: jwtTokens.refreshToken,
        tokenExpiresIn: jwtTokens.expiresIn,
        user: { id: 'admin', role: 'admin' }
      })
    };
    
    return new Response(JSON.stringify(responseBody), {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'Set-Cookie': `adminSession=${sessionId}; HttpOnly; Secure; SameSite=None; Max-Age=${sessionTTL}; Path=/`
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    
    return new Response(JSON.stringify({
      error: 'Login failed',
      message: 'Internal server error during authentication'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// ログアウト
authRouter.post('/logout', async (request, env: Env) => {
  try {
    // CSRF保護チェック
    const csrfResult = requireCSRFProtection(request, env);
    if (csrfResult) {
      const responseBody = await csrfResult.text();
      return new Response(responseBody, {
        status: csrfResult.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    const cookieHeader = request.headers.get('Cookie');
    const sessionId = getCookieValue(cookieHeader, 'adminSession');

    if (sessionId && env.SESSIONS) {
      // セッションを削除
      await env.SESSIONS.delete(sessionId);
      console.log(`Admin logout: session ${sessionId} deleted`);
    }

    
    return new Response(JSON.stringify({
      success: true,
      message: 'Logged out successfully'
    }), {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'Set-Cookie': 'adminSession=; HttpOnly; Secure; SameSite=None; Max-Age=0; Path=/'
      }
    });

  } catch (error) {
    console.error('Logout error:', error);
    
    return new Response(JSON.stringify({
      error: 'Logout failed',
      message: 'Internal server error during logout'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// 認証状態確認
authRouter.get('/status', async (request, env: Env) => {
  try {
    const cookieHeader = request.headers.get('Cookie');
    const sessionId = getCookieValue(cookieHeader, 'adminSession');

    if (!sessionId || !env.SESSIONS) {
      return new Response(JSON.stringify({
        authenticated: false,
        message: 'No valid session'
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const sessionData = await env.SESSIONS.get(sessionId);
    
    if (!sessionData) {
      return new Response(JSON.stringify({
        authenticated: false,
        message: 'Session expired'
      }), {
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
          'Set-Cookie': 'adminSession=; HttpOnly; Secure; SameSite=None; Max-Age=0; Path=/'
        }
      });
    }

    const session = JSON.parse(sessionData);
    
    return new Response(JSON.stringify({
      authenticated: session.isAdmin === true,
      createdAt: session.createdAt,
      message: 'Valid session'
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Status check error:', error);
    
    return new Response(JSON.stringify({
      authenticated: false,
      message: 'Error checking authentication status'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// JWT トークンリフレッシュ
authRouter.post('/refresh', async (request, env: Env) => {
  try {
    if (!env.JWT_SECRET) {
      return new Response(JSON.stringify({
        error: 'JWT not configured',
        message: 'JWT authentication not available'
      }), {
        status: 501,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json() as { refreshToken?: string };
    const { refreshToken } = body;
    
    if (!refreshToken) {
      return new Response(JSON.stringify({
        error: 'Refresh token required',
        message: 'Please provide refresh token'
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    if (!env.JWT_SECRET) {
      return new Response(JSON.stringify({
        error: 'JWT not configured'
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const jwtManager = JWTManager.fromEnv(env);
    const newTokens = await jwtManager.refreshTokens(refreshToken);
    
    return new Response(JSON.stringify({
      success: true,
      accessToken: newTokens.accessToken,
      refreshToken: newTokens.refreshToken,
      expiresIn: newTokens.expiresIn,
      user: { id: 'admin', role: 'admin' }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    
    return new Response(JSON.stringify({
      error: 'Token refresh failed',
      message: error instanceof Error ? error.message : 'Invalid refresh token'
    }), {
      status: 401,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// Cookie値取得ヘルパー関数
function getCookieValue(cookieHeader: string | null, name: string): string | null {
  if (!cookieHeader) return null;
  
  const cookies = cookieHeader.split(';');
  for (const cookie of cookies) {
    const [key, value] = cookie.trim().split('=');
    if (key === name) {
      return value;
    }
  }
  return null;
}

export { authRouter };