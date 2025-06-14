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

interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

interface Env {
  JWT_SECRET?: string;
  ACCESS_TOKEN_EXPIRY?: string;
  REFRESH_TOKEN_EXPIRY?: string;
}

export class JWTManager {
  private secret: string;
  private accessTokenExpiry: string;
  private refreshTokenExpiry: string;

  constructor(secret: string, config?: TokenConfig) {
    this.secret = secret;
    this.accessTokenExpiry = config?.accessTokenExpiry || '1h';
    this.refreshTokenExpiry = config?.refreshTokenExpiry || '30d';
  }

  private parseExpiry(expiry: string): number {
    const unit = expiry.slice(-1);
    const value = parseInt(expiry.slice(0, -1));
    
    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 60 * 60;
      case 'd': return value * 24 * 60 * 60;
      default: return 60 * 60; // default 1 hour
    }
  }

  private async createJWT(payload: any, expirySeconds: number): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const jwtPayload = {
      ...payload,
      iat: now,
      exp: now + expirySeconds
    };

    const encoder = new TextEncoder();
    const header = { alg: 'HS256', typ: 'JWT' };
    
    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const encodedPayload = btoa(JSON.stringify(jwtPayload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    
    const message = `${encodedHeader}.${encodedPayload}`;
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    
    return `${message}.${encodedSignature}`;
  }

  async generateTokens(userId: string, config?: TokenConfig): Promise<AuthTokens> {
    const accessExpiry = this.parseExpiry(config?.accessTokenExpiry || this.accessTokenExpiry);
    const refreshExpiry = this.parseExpiry(config?.refreshTokenExpiry || this.refreshTokenExpiry);

    const accessTokenPayload = {
      userId,
      type: 'access' as const
    };

    const refreshTokenPayload = {
      userId,
      type: 'refresh' as const
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.createJWT(accessTokenPayload, accessExpiry),
      this.createJWT(refreshTokenPayload, refreshExpiry)
    ]);

    return {
      accessToken,
      refreshToken,
      expiresIn: accessExpiry
    };
  }

  async verifyToken(token: string): Promise<JWTPayload> {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    
    // Verify signature
    const encoder = new TextEncoder();
    const message = `${encodedHeader}.${encodedPayload}`;
    
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signature = Uint8Array.from(atob(encodedSignature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(message));
    
    if (!isValid) {
      throw new Error('Invalid JWT signature');
    }

    // Parse payload
    const payloadJson = atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/'));
    const payload: JWTPayload = JSON.parse(payloadJson);

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      throw new Error('JWT expired');
    }

    return payload;
  }

  async refreshTokens(refreshToken: string): Promise<AuthTokens> {
    const payload = await this.verifyToken(refreshToken);
    
    if (payload.type !== 'refresh') {
      throw new Error('Invalid refresh token');
    }

    return this.generateTokens(payload.userId);
  }

  static fromEnv(env: Env): JWTManager {
    if (!env.JWT_SECRET) {
      throw new Error('JWT_SECRET environment variable is required');
    }

    const config: TokenConfig = {
      accessTokenExpiry: env.ACCESS_TOKEN_EXPIRY || '1h',
      refreshTokenExpiry: env.REFRESH_TOKEN_EXPIRY || '30d'
    };

    return new JWTManager(env.JWT_SECRET, config);
  }
}