# フロントエンド統合ガイド

## 📋 概要

このドキュメントでは、JWT認証システムに対応したフロントエンド実装と、プロジェクト構成の推奨事項について説明します。

---

## 🔧 フロントエンド実装アーキテクチャ

### 1. In-Memory認証サービス

```typescript
// services/authService.ts
interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

interface LoginData {
  password: string;
}

class InMemoryAuthService {
  private tokens: AuthTokens | null = null;
  private refreshPromise: Promise<void> | null = null;
  private refreshTimer: NodeJS.Timeout | null = null;

  async login(credentials: LoginData): Promise<void> {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-App-Name': 'component-management'
      },
      credentials: 'include',
      body: JSON.stringify(credentials)
    });

    if (!response.ok) {
      throw new Error('Login failed');
    }

    const data = await response.json();
    
    if (data.accessToken && data.refreshToken) {
      this.tokens = {
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expiresIn: data.tokenExpiresIn
      };
      
      this.scheduleRefresh();
      this.syncAcrossTabs();
    }
  }

  async makeRequest(url: string, options: RequestInit = {}): Promise<Response> {
    // アクセストークンの有効性をチェック
    await this.ensureValidToken();
    
    const headers = {
      ...options.headers,
      'X-Requested-With': 'XMLHttpRequest',
      'X-App-Name': 'component-management'
    };

    // JWTがある場合はBearerトークンとして送信
    if (this.tokens?.accessToken) {
      headers['Authorization'] = `Bearer ${this.tokens.accessToken}`;
    }

    return fetch(url, {
      ...options,
      headers,
      credentials: 'include' // Cookieも併用
    });
  }

  async refreshTokens(): Promise<void> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.performRefresh();
    
    try {
      await this.refreshPromise;
    } finally {
      this.refreshPromise = null;
    }
  }

  private async performRefresh(): Promise<void> {
    if (!this.tokens?.refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify({
        refreshToken: this.tokens.refreshToken
      })
    });

    if (!response.ok) {
      this.logout();
      throw new Error('Token refresh failed');
    }

    const data = await response.json();
    this.tokens = {
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
      expiresIn: data.expiresIn
    };

    this.scheduleRefresh();
    this.syncAcrossTabs();
  }

  private async ensureValidToken(): Promise<void> {
    if (!this.tokens) return;

    // トークンの有効期限をチェック（5分前に更新）
    const tokenPayload = this.parseJWT(this.tokens.accessToken);
    const expiryTime = tokenPayload.exp * 1000;
    const refreshThreshold = 5 * 60 * 1000; // 5分

    if (Date.now() >= expiryTime - refreshThreshold) {
      await this.refreshTokens();
    }
  }

  private scheduleRefresh(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    if (!this.tokens) return;

    const tokenPayload = this.parseJWT(this.tokens.accessToken);
    const expiryTime = tokenPayload.exp * 1000;
    const refreshTime = expiryTime - Date.now() - (5 * 60 * 1000); // 5分前

    if (refreshTime > 0) {
      this.refreshTimer = setTimeout(() => {
        this.refreshTokens().catch(console.error);
      }, refreshTime);
    }
  }

  private parseJWT(token: string): any {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  }

  private syncAcrossTabs(): void {
    // BroadcastChannelでタブ間同期
    if (typeof BroadcastChannel !== 'undefined') {
      const channel = new BroadcastChannel('auth-sync');
      channel.postMessage({
        type: 'tokens-updated',
        tokens: this.tokens
      });
    }
  }

  logout(): void {
    this.tokens = null;
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }

    // サーバー側のログアウト
    fetch('/api/auth/logout', {
      method: 'POST',
      headers: {
        'X-Requested-With': 'XMLHttpRequest'
      },
      credentials: 'include'
    }).catch(console.error);

    // タブ間同期
    if (typeof BroadcastChannel !== 'undefined') {
      const channel = new BroadcastChannel('auth-sync');
      channel.postMessage({ type: 'logout' });
    }
  }

  isAuthenticated(): boolean {
    return this.tokens !== null;
  }

  getAccessToken(): string | null {
    return this.tokens?.accessToken || null;
  }
}

export const authService = new InMemoryAuthService();
```

### 2. React Context & Hooks

```typescript
// contexts/AuthContext.tsx
import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { authService } from '../services/authService';

interface User {
  id: string;
  role: string;
}

interface AuthContextValue {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: { password: string }) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // 初期化時に認証状態をチェック
    checkAuthStatus();
    
    // タブ間同期のリスナー
    if (typeof BroadcastChannel !== 'undefined') {
      const channel = new BroadcastChannel('auth-sync');
      channel.onmessage = (event) => {
        if (event.data.type === 'logout') {
          setUser(null);
        } else if (event.data.type === 'tokens-updated') {
          checkAuthStatus();
        }
      };
      
      return () => channel.close();
    }
  }, []);

  const checkAuthStatus = async () => {
    try {
      if (authService.isAuthenticated()) {
        const response = await authService.makeRequest('/api/auth/status');
        if (response.ok) {
          const data = await response.json();
          if (data.authenticated) {
            setUser({ id: 'admin', role: 'admin' });
          } else {
            setUser(null);
          }
        }
      }
    } catch (error) {
      console.error('Auth status check failed:', error);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (credentials: { password: string }) => {
    setIsLoading(true);
    try {
      await authService.login(credentials);
      setUser({ id: 'admin', role: 'admin' });
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    authService.logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
```

### 3. セキュアAPIクライアント

```typescript
// hooks/useSecureAPI.ts
import { useState, useCallback } from 'react';
import { authService } from '../services/authService';

interface APIError extends Error {
  status: number;
  code?: string;
}

export function useSecureAPI() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const apiCall = useCallback(async <T>(
    url: string, 
    options: RequestInit = {}
  ): Promise<T> => {
    setLoading(true);
    setError(null);

    try {
      const response = await authService.makeRequest(url, options);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const apiError = new Error(errorData.message || 'API request failed') as APIError;
        apiError.status = response.status;
        apiError.code = errorData.code;
        throw apiError;
      }

      return await response.json();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      
      // 認証エラーの場合は自動ログアウト
      if (err instanceof Error && 'status' in err && err.status === 401) {
        authService.logout();
      }
      
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  // 便利メソッド
  const get = useCallback(<T>(url: string) => 
    apiCall<T>(url, { method: 'GET' }), [apiCall]
  );

  const post = useCallback(<T>(url: string, data: any) =>
    apiCall<T>(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    }), [apiCall]
  );

  const put = useCallback(<T>(url: string, data: any) =>
    apiCall<T>(url, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    }), [apiCall]
  );

  const del = useCallback(<T>(url: string) =>
    apiCall<T>(url, { method: 'DELETE' }), [apiCall]
  );

  return {
    loading,
    error,
    apiCall,
    get,
    post,
    put,
    delete: del
  };
}
```

### 4. 使用例

```typescript
// components/ComponentManager.tsx
import React from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useSecureAPI } from '../hooks/useSecureAPI';

export function ComponentManager() {
  const { isAuthenticated, logout } = useAuth();
  const { get, post, loading, error } = useSecureAPI();

  const createComponent = async (componentData: any) => {
    try {
      const result = await post('/api/components', componentData);
      console.log('Component created:', result);
    } catch (err) {
      console.error('Failed to create component:', err);
    }
  };

  const fetchComponents = async () => {
    try {
      const components = await get('/api/components');
      console.log('Components:', components);
    } catch (err) {
      console.error('Failed to fetch components:', err);
    }
  };

  if (!isAuthenticated) {
    return <LoginForm />;
  }

  return (
    <div>
      {loading && <div>Loading...</div>}
      {error && <div>Error: {error}</div>}
      <button onClick={logout}>Logout</button>
      <button onClick={fetchComponents}>Fetch Components</button>
      {/* Component management UI */}
    </div>
  );
}
```

---

## 🔄 JWT トークンリフレッシュ仕組み

### トークンの役割分担

```typescript
// アクセストークン（短期間）
ACCESS_TOKEN_EXPIRY = "1h"  // 1時間で期限切れ

// リフレッシュトークン（長期間）  
REFRESH_TOKEN_EXPIRY = "30d" // 30日間有効
```

### 自動更新フロー

1. **初回ログイン時**
   ```json
   {
     "accessToken": "eyJ...", // 1時間有効
     "refreshToken": "eyJ...", // 30日有効
     "expiresIn": 3600
   }
   ```

2. **アクセストークン期限切れ時**
   - フロントエンドが自動的に `/api/auth/refresh` を呼び出し
   - リフレッシュトークンで新しいペアを取得

3. **新しいトークンペア取得**
   ```typescript
   // POST /api/auth/refresh
   {
     "refreshToken": "現在のリフレッシュトークン"
   }
   
   // レスポンス
   {
     "accessToken": "新しいアクセストークン", // さらに1時間
     "refreshToken": "新しいリフレッシュトークン", // さらに30日
     "expiresIn": 3600
   }
   ```

### セキュリティ上の利点

- **短期アクセストークン**: 万が一漏洩しても1時間で無効
- **長期リフレッシュトークン**: ユーザーは30日間再ログイン不要
- **トークンローテーション**: リフレッシュ時に両方とも新しいトークンに更新

---

## 🏗️ プロジェクト構成の推奨事項

### ディレクトリ構成の比較

#### 現在の分離構成（推奨）
```
component-management/          # フロントエンド
├── src/
├── package.json
└── ...

component-api/                 # API
├── src/
├── wrangler.toml
└── ...
```

#### 統合構成（モノレポ）
```
component-platform/
├── frontend/                  # React/Next.js
│   ├── src/
│   ├── package.json
│   └── ...
├── api/                      # Cloudflare Workers
│   ├── src/
│   ├── wrangler.toml
│   └── ...
├── shared/                   # 共通型定義など
│   ├── types/
│   └── utils/
├── package.json              # ルートpackage.json
└── README.md
```

### 比較分析

| 観点 | 分離構成 | 統合構成（モノレポ） |
|------|----------|---------------------|
| **デプロイ** | ✅ 独立デプロイ可能 | ⚠️ 調整が必要 |
| **開発速度** | ⚠️ 別々に起動 | ✅ 一括開発環境 |
| **型安全性** | ⚠️ 手動同期 | ✅ 共有型定義 |
| **CI/CD** | ✅ シンプル | ⚠️ 複雑 |
| **スケーラビリティ** | ✅ 高い | ⚠️ 中程度 |
| **チーム開発** | ✅ 責任分離 | ✅ 統一管理 |

### 🎯 推奨: 現在の分離構成を維持

#### 理由:

1. **デプロイの独立性**
   - Vercel (フロントエンド) と Cloudflare Workers (API) の独立デプロイ
   - 各サービスに最適化された設定が可能

2. **技術スタックの最適化**
   - フロントエンド: Next.js/Vercel の最適化
   - API: Cloudflare Workers の edge computing 活用

3. **セキュリティ分離**
   - 異なるドメインでのCORS設定
   - 各層での独立したセキュリティ設定

---

## 🚀 改善案: 開発体験の向上

### 1. 共通型定義の共有

```typescript
// 新規: component-types パッケージ
npm create component-types

// api/package.json
{
  "dependencies": {
    "component-types": "file:../component-types"
  }
}

// frontend/package.json  
{
  "dependencies": {
    "component-types": "file:../component-types"
  }
}
```

### 2. 開発環境の統合

```json
// ルートディレクトリに package.json
{
  "scripts": {
    "dev": "concurrently \"npm run dev:api\" \"npm run dev:frontend\"",
    "dev:api": "cd component-api && npm run dev",
    "dev:frontend": "cd component-management && npm run dev",
    "build": "npm run build:api && npm run build:frontend",
    "test": "npm run test:api && npm run test:frontend"
  },
  "devDependencies": {
    "concurrently": "^8.0.0"
  }
}
```

### 3. 環境変数の統一管理

```bash
# .env.shared
API_URL=http://localhost:8787
FRONTEND_URL=http://localhost:3000
```

### 最終推奨構成

```
project-root/
├── component-api/             # 現在のAPI (維持)
├── component-management/      # 現在のフロントエンド (維持)  
├── component-types/           # 新規: 共通型定義
├── package.json              # 新規: 開発用スクリプト
├── .env.shared               # 新規: 共通環境変数
└── README.md                 # 統合ドキュメント
```

### 移行手順

1. **共通型パッケージ作成**
2. **ルートレベル開発スクリプト追加**
3. **CI/CD の調整（必要に応じて）**

---

## 🔑 主要特徴

1. **In-Memory保存**: XSSリスクを最小化
2. **自動リフレッシュ**: UX を損なわない認証維持
3. **タブ間同期**: BroadcastChannelで状態共有
4. **エラーハンドリング**: 認証エラー時の自動ログアウト
5. **CSRF保護**: 全リクエストに適切なヘッダー付与
6. **フォールバック**: JWTとCookieの併用でロバスト性確保

この実装により、セキュリティを保ちながら優れたユーザー体験を実現できます。

---

## 📞 サポート

実装中の問題やフロントエンド統合に関する質問があれば、このドキュメントを参考に進めてください。セキュリティ強化されたAPIとの連携により、安全で快適なユーザー体験を提供できます。