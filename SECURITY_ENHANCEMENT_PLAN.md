# セキュリティ強化実装計画書

## 📋 概要

現在のCookie認証からJWT認証への移行と、CSRF保護・XSS対策の強化を行う包括的なセキュリティアップグレード計画。

**目標**: クロスドメイン対応、モダンなセキュリティ対策、優れたUXの実現

---

## 🏗️ システム構成

```
[Vercel Frontend] ←→ [Cloudflare Workers API]
      ↓                    ↓
[React/Next.js]        [D1 Database]
[In-Memory Auth]       [KV Storage]
```

---

## 🔐 認証システム移行計画

### フェーズ1: JWT認証実装

#### Backend (Cloudflare Workers)

**1. JWT管理モジュール実装**

```typescript
// src/jwt.ts
interface TokenConfig {
  accessTokenExpiry: string;   // "1h"
  refreshTokenExpiry: string;  // "30d" 
}

interface JWTPayload {
  userId: string;
  type: 'access' | 'refresh';
  iat: number;
  exp: number;
}

export class JWTManager {
  constructor(private secret: string) {}
  
  async generateTokens(userId: string, config: TokenConfig): Promise<AuthTokens>
  async verifyToken(token: string): Promise<JWTPayload>
  async refreshTokens(refreshToken: string): Promise<AuthTokens>
}
```

**2. 認証エンドポイント拡張**

```typescript
// src/auth-routes.ts の更新

// 新規エンドポイント
POST /api/auth/login    // JWT + Cookie ハイブリッド
POST /api/auth/refresh  // トークンリフレッシュ
GET  /api/auth/status   // 認証状態確認
POST /api/auth/logout   // ログアウト

// レスポンス例
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "expiresIn": 3600,
  "user": { "id": "123", "role": "admin" }
}
```

**3. 認証ミドルウェア更新**

```typescript
// src/middleware/auth.ts の更新
export async function requireAuth(request: Request, env: Env): Promise<Response | null> {
  // 1. JWT Bearer認証チェック
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    return await validateJWT(authHeader.substring(7), env);
  }
  
  // 2. Cookie認証フォールバック（互換性）
  return await checkCookieAuth(request, env);
}
```

#### Frontend (Vercel/React)

**1. In-Memory認証サービス**

```typescript
// services/authService.ts
class InMemoryAuthService {
  private tokens: AuthTokens | null = null;
  private refreshPromise: Promise<void> | null = null;

  async login(credentials: LoginData): Promise<void>
  async makeRequest(url: string, options?: RequestInit): Promise<Response>
  async refreshTokens(): Promise<void>
  logout(): void
  isAuthenticated(): boolean
}
```

**2. React Context & Hooks**

```typescript
// contexts/AuthContext.tsx
export function AuthProvider({ children }: { children: ReactNode })
export function useAuth(): AuthContextValue

// hooks/useSecureAPI.ts  
export function useSecureAPI(): {
  apiCall: (url: string, options?: RequestInit) => Promise<Response>;
  loading: boolean;
  error: string | null;
}
```

**3. 自動トークン管理**

```typescript
// utils/tokenManager.ts
class TokenManager {
  private checkTokenValidity(): boolean
  private scheduleRefresh(): void
  private handleTokenExpiry(): void
  private syncAcrossTabs(): void // BroadcastChannel
}
```

---

## 🛡️ CSRF保護強化

### 多層防御システム

**1. 現在の実装強化**

```typescript
// src/middleware/auth.ts の更新
export function requireCSRFProtection(request: Request, env: Env): Response | null {
  const method = request.method.toUpperCase();
  if (!['POST', 'PUT', 'DELETE'].includes(method)) return null;

  // レイヤー1: Origin/Refererヘッダー検証
  const hasValidOrigin = validateReferer(request, env);
  
  // レイヤー2: カスタムヘッダー検証
  const hasValidHeaders = validateCustomHeaders(request);
  
  // レイヤー3: JWT署名検証
  const hasValidJWT = validateJWTSignature(request);
  
  // 少なくとも2つの保護レイヤーが必要
  const protectionCount = [hasValidOrigin, hasValidHeaders, hasValidJWT]
    .filter(Boolean).length;
    
  if (protectionCount < 2) {
    return createCSRFErrorResponse();
  }
  
  return null;
}
```

**2. CSRFトークン実装（オプション）**

```typescript
// src/csrf.ts（高セキュリティ要件時）
export class CSRFManager {
  constructor(private kv: KVNamespace) {}
  
  async generateToken(sessionId: string): Promise<string>
  async validateToken(sessionId: string, token: string): Promise<boolean>
  async rotateToken(sessionId: string): Promise<string>
}

// フロントエンド
// hooks/useCSRF.ts
export function useCSRF(): {
  token: string | null;
  loading: boolean;
  refreshToken: () => Promise<void>;
}
```

---

## 🚫 XSS保護強化

### 入力サニタイゼーション

**1. バリデーション強化**

```typescript
// src/utils/validation.ts の更新
import DOMPurify from 'isomorphic-dompurify';

export function validateAndSanitizeComponent(data: any): ValidationResult {
  const result = baseValidation(data);
  if (!result.success) return result;
  
  // DOMPurifyでサニタイゼーション
  const sanitized = {
    ...result.data,
    html: DOMPurify.sanitize(result.data.html, {
      ALLOWED_TAGS: ['div', 'span', 'p', 'h1', 'h2', 'h3', 'button', 'input'],
      ALLOWED_ATTR: ['class', 'id', 'data-*']
    }),
    css: sanitizeCSS(result.data.css),
    js: sanitizeJS(result.data.js)
  };
  
  return { success: true, data: sanitized };
}
```

**2. Content Security Policy**

```typescript
// src/index.ts の更新
const securityHeaders = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'", 
    "img-src 'self' data: https:",
    "connect-src 'self' https://component-management.vercel.app"
  ].join('; '),
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block'
};
```

---

## 📱 フロントエンド実装詳細

### セキュアAPIクライアント

```typescript
// services/apiClient.ts
class SecureAPIClient {
  private authService: InMemoryAuthService;
  private baseURL: string;
  
  constructor() {
    this.authService = new InMemoryAuthService();
    this.baseURL = process.env.NEXT_PUBLIC_API_URL!;
  }
  
  async request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    
    // CSRF保護ヘッダー自動付与
    const headers = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'X-App-Name': 'component-management',
      ...options.headers
    };
    
    const response = await this.authService.makeRequest(url, {
      ...options,
      headers
    });
    
    if (!response.ok) {
      throw new APIError(response.status, await response.text());
    }
    
    return response.json();
  }
  
  // 便利メソッド
  get<T>(endpoint: string): Promise<T>
  post<T>(endpoint: string, data: any): Promise<T>
  put<T>(endpoint: string, data: any): Promise<T>
  delete<T>(endpoint: string): Promise<T>
}

export const apiClient = new SecureAPIClient();
```

### エラーハンドリング

```typescript
// utils/errorHandler.ts
export class APIError extends Error {
  constructor(
    public status: number, 
    message: string,
    public code?: string
  ) {
    super(message);
  }
}

export function handleAPIError(error: APIError): void {
  switch (error.status) {
    case 401:
      // 認証エラー - ログイン画面へ
      authService.logout();
      break;
    case 403:
      // CSRF/権限エラー
      showErrorToast('操作が拒否されました');
      break;
    case 429:
      // レート制限
      showErrorToast('しばらく待ってから再試行してください');
      break;
    default:
      showErrorToast('エラーが発生しました');
  }
}
```

---

## 🔧 環境設定

### Cloudflare Workers設定

```toml
# wrangler.toml
name = "component-api"
main = "src/index.ts"
compatibility_date = "2023-12-01"

[[d1_databases]]
binding = "DB"
database_name = "components-db"
database_id = "your-database-id"

[[kv_namespaces]]
binding = "SESSIONS"
id = "your-kv-namespace-id"

[vars]
JWT_SECRET = "your-jwt-secret-key"
ACCESS_TOKEN_EXPIRY = "1h"
REFRESH_TOKEN_EXPIRY = "30d"
CORS_ORIGIN = "https://component-management.vercel.app"
ENVIRONMENT = "production"
```

### Vercel設定

```bash
# .env.local
NEXT_PUBLIC_API_URL=https://component-api.your-subdomain.workers.dev
NEXT_PUBLIC_APP_NAME=component-management
```

---

## 🧪 テスト計画

### セキュリティテスト

**1. 既存テスト更新**

```bash
# テストスクリプト更新
./test-security.sh      # JWT認証対応
./test-csrf-protection.sh # 多層防御テスト
./test-xss-protection.sh  # サニタイゼーションテスト
./test-performance.sh     # 新規作成
```

**2. 新規テストケース**

```typescript
// tests/auth.test.ts
describe('JWT Authentication', () => {
  test('should login with valid credentials')
  test('should refresh tokens automatically')
  test('should handle token expiry gracefully')
  test('should logout on invalid refresh token')
})

// tests/csrf.test.ts  
describe('CSRF Protection', () => {
  test('should block requests without proper headers')
  test('should allow requests with valid JWT + headers')
  test('should validate origin header')
})
```

---

## 📅 実装スケジュール

### フェーズ1: 基盤実装 (Week 1-2)

- [ ] JWT管理モジュール実装
- [ ] 認証エンドポイント作成
- [ ] In-Memory認証サービス作成
- [ ] 基本テスト作成

### フェーズ2: セキュリティ強化 (Week 3)

- [ ] CSRF保護多層化
- [ ] XSS保護強化
- [ ] セキュリティヘッダー追加
- [ ] セキュリティテスト実装

### フェーズ3: フロントエンド統合 (Week 4)

- [ ] React Context実装
- [ ] APIクライアント作成
- [ ] エラーハンドリング実装
- [ ] UX改善

### フェーズ4: 本番移行 (Week 5)

- [ ] 段階的ロールアウト
- [ ] モニタリング設定
- [ ] パフォーマンス最適化
- [ ] ドキュメント作成

---

## 🎯 成功指標

### セキュリティメトリクス

- **CSRF攻撃防御率**: 99.9%以上
- **XSS攻撃防御率**: 99.9%以上  
- **認証突破率**: 0%
- **セキュリティテスト通過率**: 100%

### パフォーマンスメトリクス

- **ログイン時間**: < 500ms
- **API応答時間**: < 200ms
- **トークンリフレッシュ時間**: < 100ms
- **メモリ使用量**: < 5MB

### UXメトリクス

- **自動ログイン成功率**: 99%以上
- **セッション維持期間**: 30日
- **エラー発生率**: < 0.1%
- **ユーザー体験評価**: 4.5/5以上

---

## ⚠️ リスク管理

### 技術的リスク

1. **JWT実装複雑性**
   - 対策: 段階的実装、十分なテスト
   
2. **トークンリフレッシュ失敗**
   - 対策: フォールバック機構、エラーハンドリング

3. **クロスブラウザ互換性**
   - 対策: 広範囲ブラウザテスト

### セキュリティリスク

1. **JWT漏洩**
   - 対策: In-Memory保存、短期間有効期限

2. **CSRF攻撃進化**
   - 対策: 多層防御、定期見直し

3. **XSS新手法**
   - 対策: 最新のサニタイゼーションライブラリ

---

## 📚 参考資料

### セキュリティ標準

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-bcp)
- [CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

### 技術ドキュメント

- [Cloudflare Workers JWT](https://developers.cloudflare.com/workers/examples/auth-with-headers/)
- [React Security Best Practices](https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

---

## 📞 サポート

**実装中の問題やセキュリティに関する質問があれば、いつでもお聞きください。**

この計画書は実装進捗に応じて随時更新されます。