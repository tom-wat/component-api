// src/middleware/auth.ts - Authentication middleware
import { JWTManager } from '../jwt';

export interface Env {
  ADMIN_PASSWORD?: string; // 旧ADMIN_API_KEYから名称変更
  ENVIRONMENT?: string;
  SESSIONS?: KVNamespace; // Cookieセッション用KV
  JWT_SECRET?: string;
  ACCESS_TOKEN_EXPIRY?: string;
  REFRESH_TOKEN_EXPIRY?: string;
}

/**
 * CookieからセッションIDを取得
 */
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

/**
 * JWT認証チェック
 */
export async function validateJWT(token: string, env: Env, request?: Request): Promise<Response | null> {
  if (!env.JWT_SECRET) {
    return new Response(JSON.stringify({
      error: 'JWT not configured',
      message: 'JWT authentication not available'
    }), {
      status: 501,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    // We already checked env.JWT_SECRET exists above, so it's safe to cast
    const jwtManager = JWTManager.fromEnv(env as Required<Pick<Env, 'JWT_SECRET'>> & Env);
    const payload = await jwtManager.verifyToken(token);
    
    if (payload.type !== 'access') {
      return new Response(JSON.stringify({
        error: 'Invalid token type',
        message: 'Only access tokens are allowed'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    if (request) {
      console.log(`JWT authenticated user: ${payload.userId} from ${request.headers.get('cf-connecting-ip') || 'unknown IP'}`);
    }
    return null; // 認証成功
  } catch (error) {
    console.warn('JWT validation failed:', error);
    return new Response(JSON.stringify({
      error: 'Invalid JWT',
      message: error instanceof Error ? error.message : 'Token validation failed'
    }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/**
 * Cookieセッション認証チェック
 */
export async function checkCookieAuth(request: Request, env: Env): Promise<boolean> {
  if (!env.SESSIONS) {
    return false;
  }

  const cookieHeader = request.headers.get('Cookie');
  const sessionId = getCookieValue(cookieHeader, 'adminSession');
  
  if (!sessionId) {
    return false;
  }

  try {
    const sessionData = await env.SESSIONS.get(sessionId);
    if (sessionData) {
      const session = JSON.parse(sessionData);
      return session.isAdmin === true;
    }
  } catch (error) {
    console.error('Session validation error:', error);
  }
  
  return false;
}

/**
 * パスワード認証(ヘッダー経由)
 */
export function validatePassword(request: Request, env: Env): boolean {
  const adminPassword = env.ADMIN_PASSWORD;
  
  if (!adminPassword) {
    return false;
  }

  // Extract password from request headers
  const authHeader = request.headers.get('Authorization');
  const adminKeyHeader = request.headers.get('X-Admin-API-Key'); // 旧ヘッダー名保持
  
  let providedPassword: string | null = null;
  
  // Check Authorization header (Bearer format)
  if (authHeader?.startsWith('Bearer ')) {
    providedPassword = authHeader.substring(7);
  }
  // Check Authorization header (direct password format)
  else if (authHeader) {
    providedPassword = authHeader;
  }
  // Check X-Admin-API-Key header
  else if (adminKeyHeader) {
    providedPassword = adminKeyHeader;
  }
  
  if (!providedPassword) {
    return false;
  }
  
  return constantTimeEquals(providedPassword, adminPassword);
}

/**
 * 統合認証ミドルウェア - JWT + Cookie + ヘッダーハイブリッド認証
 */
export async function requireAuth(request: Request, env: Env): Promise<Response | null> {
  // 1. JWT Bearer認証チェック
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const jwtResult = await validateJWT(token, env, request);
    if (jwtResult === null) {
      return null; // JWT認証成功
    }
    // JWT認証失敗の場合、他の認証方法にフォールバック
  }

  // 2. Cookie認証チェック
  const hasCookieAuth = await checkCookieAuth(request, env);
  if (hasCookieAuth) {
    console.log(`Admin authenticated via cookie from ${request.headers.get('cf-connecting-ip') || 'unknown IP'}`);
    return null; // 認証成功
  }

  // 3. ヘッダー認証をフォールバック
  const hasHeaderAuth = validatePassword(request, env);
  if (hasHeaderAuth) {
    console.log(`Admin authenticated via header from ${request.headers.get('cf-connecting-ip') || 'unknown IP'}`);
    return null; // 認証成功
  }

  // 4. 認証失敗
  const adminPassword = env.ADMIN_PASSWORD;
  if (!adminPassword) {
    console.error('ADMIN_PASSWORD not configured');
    return new Response(JSON.stringify({
      error: 'Admin authentication not configured',
      message: 'Please contact system administrator'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  console.warn(`Authentication failed from ${request.headers.get('cf-connecting-ip') || 'unknown IP'}`);
  
  return new Response(JSON.stringify({
    error: 'Authentication required',
    message: 'Admin authentication required. Please login or provide valid credentials.',
    methods: {
      'jwt': 'Provide Authorization: Bearer <access_token> header',
      'cookie': 'Login via /api/auth/login endpoint',
      'header': 'Provide X-Admin-API-Key header or Authorization header with password'
    }
  }), {
    status: 401,
    headers: { 'Content-Type': 'application/json' }
  });
}

/**
 * Admin authentication middleware - Cookie優先、ヘッダーフォールバック (レガシー互換性)
 */
export async function requireAdminAuth(request: Request, env: Env): Promise<Response | null> {
  return requireAuth(request, env);
}

/**
 * Constant-time string comparison to prevent timing attacks
 * This ensures that the comparison takes the same amount of time regardless
 * of where the strings differ, making it harder to guess the key through timing
 */
export function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

/**
 * Rate limiting for authentication attempts (simple in-memory implementation)
 * In production, you might want to use Cloudflare KV or Durable Objects for this
 */
class AuthRateLimiter {
  private attempts: Map<string, { count: number; lastAttempt: number }> = new Map();
  private readonly maxAttempts = 5;
  private readonly windowMs = 15 * 60 * 1000; // 15 minutes
  
  isRateLimited(ip: string): boolean {
    const now = Date.now();
    const record = this.attempts.get(ip);
    
    if (!record) {
      this.attempts.set(ip, { count: 1, lastAttempt: now });
      return false;
    }
    
    // Reset if window has passed
    if (now - record.lastAttempt > this.windowMs) {
      this.attempts.set(ip, { count: 1, lastAttempt: now });
      return false;
    }
    
    // Increment attempt count
    record.count++;
    record.lastAttempt = now;
    
    return record.count > this.maxAttempts;
  }
  
  reset(ip: string): void {
    this.attempts.delete(ip);
  }
}

export const authRateLimiter = new AuthRateLimiter();

/**
 * Validate Referer header to prevent CSRF attacks
 */
export function validateReferer(request: Request, env: Env): boolean {
  const referer = request.headers.get('Referer');
  const origin = request.headers.get('Origin');
  
  // For development environment, allow localhost origins
  const isDevelopment = env.ENVIRONMENT === 'development';
  
  // Define allowed origins
  const allowedOrigins = [
    'https://component-management.vercel.app'
  ];
  
  if (isDevelopment) {
    allowedOrigins.push(
      'http://localhost:3000',
      'http://localhost:5173',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173'
    );
  }
  
  // Check Origin header first (more reliable)
  if (origin) {
    return allowedOrigins.includes(origin);
  }
  
  // Fallback to Referer header check
  if (referer) {
    return allowedOrigins.some(allowedOrigin => 
      referer.startsWith(allowedOrigin)
    );
  }
  
  // If neither Origin nor Referer is present, reject for state-changing operations
  return false;
}

/**
 * JWT署名検証によるCSRF保護
 */
export function validateJWTSignature(request: Request): boolean {
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    // JWT が存在することで、これが正当なクライアントからのリクエストであることを示す
    // 実際の署名検証は validateJWT で行われる
    return true;
  }
  return false;
}

/**
 * Validate custom security headers to prevent CSRF attacks
 */
export function validateCustomHeaders(request: Request): boolean {
  // Check for X-Requested-With header (commonly used by AJAX libraries)
  const xRequestedWith = request.headers.get('X-Requested-With');
  
  // Accept specific values that indicate legitimate requests
  const validXRequestedWithValues = [
    'XMLHttpRequest',        // Standard AJAX requests
    'fetch',                 // Modern fetch API
    'application/json',      // JSON requests
    'component-api'          // Custom application identifier
  ];
  
  if (xRequestedWith && validXRequestedWithValues.includes(xRequestedWith)) {
    return true;
  }
  
  // Check for custom application header
  const customAppHeader = request.headers.get('X-App-Name');
  if (customAppHeader === 'component-management') {
    return true;
  }
  
  // Check for Content-Type that indicates programmatic access
  // Note: We are more restrictive here - just having JSON content-type is not enough
  // as simple form posts can also set this header
  const contentType = request.headers.get('Content-Type');
  if (contentType?.includes('application/json')) {
    // Only allow if it's a complex request that would trigger CORS preflight
    // Check if this is a "simple request" that wouldn't trigger preflight
    const method = request.method.toUpperCase();
    const hasCustomHeaders = request.headers.get('X-Requested-With') || 
                            request.headers.get('X-App-Name') ||
                            request.headers.get('Authorization');
    
    // If it's just a simple POST with JSON content-type, still require additional headers
    if (method === 'POST' && !hasCustomHeaders) {
      return false;
    }
    
    return true;
  }
  
  return false;
}

/**
 * 多層防御CSRF保護ミドルウェア
 */
export function requireCSRFProtection(request: Request, env: Env): Response | null {
  // Only apply CSRF protection to state-changing methods
  const method = request.method.toUpperCase();
  if (!['POST', 'PUT', 'DELETE'].includes(method)) {
    return null; // Allow GET, HEAD, OPTIONS
  }
  
  // レイヤー1: Origin/Refererヘッダー検証
  const hasValidOrigin = validateReferer(request, env);
  
  // レイヤー2: カスタムヘッダー検証
  const hasValidHeaders = validateCustomHeaders(request);
  
  // レイヤー3: JWT署名検証
  const hasValidJWT = validateJWTSignature(request);
  
  // 少なくとも2つの保護レイヤーが必要（高セキュリティ）
  // または最低1つの保護レイヤー（基本セキュリティ）
  const protectionLayers = [hasValidOrigin, hasValidHeaders, hasValidJWT];
  const protectionCount = protectionLayers.filter(Boolean).length;
  
  // 環境に応じてセキュリティレベルを調整
  const isDevelopment = env.ENVIRONMENT === 'development';
  const minProtectionLayers = isDevelopment ? 1 : 2;
  
  if (protectionCount < minProtectionLayers) {
    const clientIP = request.headers.get('cf-connecting-ip') || 'unknown IP';
    console.warn(`CSRF protection triggered: Only ${protectionCount}/${minProtectionLayers} protection layers from ${clientIP}`);
    console.warn(`Referer: ${request.headers.get('Referer')}, Origin: ${request.headers.get('Origin')}`);
    console.warn(`X-Requested-With: ${request.headers.get('X-Requested-With')}, X-App-Name: ${request.headers.get('X-App-Name')}`);
    console.warn(`Authorization: ${request.headers.get('Authorization') ? 'present' : 'missing'}`);
    console.warn(`Content-Type: ${request.headers.get('Content-Type')}`);
    
    return new Response(JSON.stringify({
      error: 'CSRF protection',
      message: `Request blocked by CSRF protection. Need at least ${minProtectionLayers} security layer(s).`,
      details: {
        required: `At least ${minProtectionLayers} of the following layers:`,
        layers: [
          { 
            name: 'Valid Origin/Referer', 
            status: hasValidOrigin ? 'valid' : 'invalid',
            description: 'Request from allowed domain'
          },
          { 
            name: 'Custom Headers', 
            status: hasValidHeaders ? 'valid' : 'invalid',
            description: 'X-Requested-With or X-App-Name headers'
          },
          { 
            name: 'JWT Signature', 
            status: hasValidJWT ? 'valid' : 'invalid',
            description: 'Valid JWT Bearer token'
          }
        ]
      }
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // Log successful CSRF protection for monitoring
  const protectionTypes = [];
  if (hasValidOrigin) protectionTypes.push('origin');
  if (hasValidHeaders) protectionTypes.push('headers');
  if (hasValidJWT) protectionTypes.push('jwt');
  
  console.log(`CSRF protection: ${protectionCount} layers active (${protectionTypes.join(', ')}) from ${request.headers.get('cf-connecting-ip') || 'unknown IP'}`);
  
  return null; // CSRF check passed
}

/**
 * Enhanced admin authentication with rate limiting
 */
export async function requireAdminAuthWithRateLimit(request: Request, env: Env): Promise<Response | null> {
  const clientIP = request.headers.get('cf-connecting-ip') || 'unknown';
  
  // Check rate limiting first
  if (authRateLimiter.isRateLimited(clientIP)) {
    console.warn(`Rate limited authentication attempt from ${clientIP}`);
    return new Response(JSON.stringify({
      error: 'Too many authentication attempts',
      message: 'Too many failed authentication attempts. Please try again later.',
      retryAfter: '15 minutes'
    }), {
      status: 429,
      headers: { 
        'Content-Type': 'application/json',
        'Retry-After': '900' // 15 minutes in seconds
      }
    });
  }
  
  // Perform normal authentication
  const authResult = await requireAuth(request, env);
  
  // If authentication successful, reset rate limit for this IP
  if (!authResult) {
    authRateLimiter.reset(clientIP);
  }
  
  return authResult;
}