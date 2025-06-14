// src/utils/validation.ts - Input validation and XSS protection
import { z } from 'zod';

// Enhanced sanitization functions for Cloudflare Workers environment
// Implements comprehensive XSS protection as per security enhancement plan

// Zod schemas for validation
export const ComponentSchema = z.object({
  name: z.string().min(1, 'Component name is required').max(100, 'Component name too long'),
  category: z.string().max(50, 'Category name too long').default('Other'),
  html: z.string().max(50000, 'HTML content too large').default(''),
  css: z.string().max(50000, 'CSS content too large').default(''),
  js: z.string().max(50000, 'JavaScript content too large').default(''),
  tags: z.union([
    z.string(),
    z.array(z.string())
  ]).transform((val) => {
    if (typeof val === 'string') {
      return val.split(',').map(tag => tag.trim()).filter(Boolean);
    }
    return val;
  }).default([])
});

export const UpdateComponentSchema = ComponentSchema.partial().refine(
  (data) => Object.keys(data).length > 0,
  'At least one field must be provided for update'
);

// 許可されたHTMLタグ（ホワイトリスト方式）
const allowedHTMLTags = [
  'div', 'span', 'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'button', 'input', 'label', 'form', 'a', 'textarea', 'select', 'option',
  'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'table', 'tr', 'td', 'th', 'thead', 'tbody', 'tfoot',
  'section', 'article', 'header', 'footer', 'nav', 'main', 'aside',
  'strong', 'em', 'b', 'i', 'u', 'br', 'hr', 'small', 'sub', 'sup', 'mark',
  'img', 'figure', 'figcaption',
  'details', 'summary', // HTML5 disclosure elements
  'code', 'pre', 'kbd', 'samp', 'var', // コード・プログラミング関連
  'blockquote', 'cite', 'q', 'abbr', 'dfn', // 引用・定義関連
  'time', 'address', // セマンティック要素
  'canvas', // Canvas API用（描画）
  // Phase 1: Basic SVG support (strict security)
  'svg', 'path', 'circle', 'rect', 'ellipse', 'line', 'polygon',
  'g', 'defs', 'title', 'desc'
];

// 許可されたHTMLattributes
const allowedHTMLAttributes = [
  'class', 'id', 'style', 'data-*', 'aria-*', 'role',
  'type', 'name', 'value', 'placeholder', 'href', 'target',
  'src', 'alt', 'width', 'height', 'title',
  // Phase 1: Basic SVG attributes (safe subset)
  'viewBox', 'xmlns', 'xmlns:*', 'd', 'fill', 'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin',
  'cx', 'cy', 'r', 'rx', 'ry', 'x', 'y', 'x1', 'y1', 'x2', 'y2',
  'points', 'transform', 'opacity', 'fill-opacity', 'stroke-opacity'
];

// 危険なHTMLパターン（より包括的）
const dangerousHTMLPatterns = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /<iframe\b[^>]*>/gi,
  /<object\b[^>]*>/gi,
  /<embed\b[^>]*>/gi,
  /<link\b[^>]*>/gi,
  /<meta\b[^>]*>/gi,
  /<base\b[^>]*>/gi,
  /<form\b[^>]*action\s*=\s*["'][^"']*["'][^>]*>/gi, // 外部送信フォーム
  /on\w+\s*=\s*["'][^"']*["']/gi,
  /on\w+\s*=\s*[^"'\s>]+/gi,
  /javascript:/gi,
  /vbscript:/gi,
  /data:text\/html/gi,
  /data:text\/javascript/gi,
  /data:application\/x-javascript/gi,
  /<svg\b[^>]*on\w+\s*=/gi, // SVG内のイベントハンドラ
  /<math\b[^>]*on\w+\s*=/gi, // MathML内のイベントハンドラ
  /&lt;script/gi,
  /&gt;.*?&lt;\/script&gt;/gi,
  /&#x[0-9a-f]+;?/gi, // 16進エンティティエンコーディング回避試行
  /&#[0-9]+;?/gi // 10進エンティティエンコーディング回避試行
];

// SVG専用の危険パターン（Phase 1セキュリティ強化）
const dangerousSVGPatterns = [
  /<foreignObject\b[^>]*>/gi, // 外部オブジェクト埋め込み禁止
  /<use\b[^>]*>/gi, // 外部参照禁止
  /<image\b[^>]*>/gi, // 外部画像参照禁止
  /<animate\b[^>]*>/gi, // アニメーション禁止（Phase 1）
  /<animateTransform\b[^>]*>/gi, // トランスフォームアニメーション禁止
  /<animateMotion\b[^>]*>/gi, // モーションアニメーション禁止
  /<set\b[^>]*>/gi, // セットアニメーション禁止
  /href\s*=\s*["'][^"']*["']/gi, // すべてのhref属性禁止
  /xlink:href\s*=\s*["'][^"']*["']/gi, // xlink:href禁止
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, // SVG内script禁止
];

const dangerousCSSPatterns = [
  /javascript:/gi,
  /expression\s*\(/gi,
  /behavior\s*:/gi,
  /binding\s*:/gi,
  /@import/gi,
  /url\s*\(\s*["']?\s*javascript:/gi,
  /url\s*\(\s*["']?\s*data:text\/html/gi,
  /url\s*\(\s*["']?\s*data:text\/javascript/gi,
  /vbscript:/gi,
  /mozbinding:/gi,
  /-moz-binding/gi,
  /filter\s*:\s*progid/gi, // IE filter expressions
  /zoom\s*:\s*expression/gi,
  /behavior\s*:\s*url/gi,
  /content\s*:\s*url\s*\(/gi, // content property with URLs
  /@charset/gi,
  /@namespace/gi
];

// 削除：dangerousJSPatterns は sanitizeJS 関数内で criticalPatterns として再定義

/**
 * HTMLエンティティエンコーディング
 */
function encodeHTMLEntities(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * SVG専用サニタイズ（基本機能を保ちつつセキュリティを確保）
 */
function sanitizeSVG(svgContent: string): string {
  let sanitized = svgContent;
  
  // Step 1: SVG専用の危険パターンを除去
  dangerousSVGPatterns.forEach(pattern => {
    sanitized = sanitized.replace(pattern, '<!-- removed for security -->');
  });
  
  // Step 2: SVGタグの属性をメイン関数に委譲（viewBox、xmlns等を正しく処理）
  sanitized = sanitized.replace(/<(svg|g|path|circle|rect|ellipse|line|polygon|defs|title|desc)\b([^>]*)>/gi, (match, tagName, attributes) => {
    const cleanAttributes = sanitizeHTMLAttributes(`<${tagName}${attributes}>`);
    return cleanAttributes;
  });
  
  return sanitized;
}

/**
 * ホワイトリスト方式でHTMLタグをサニタイズ
 */
function sanitizeHTMLTags(html: string): string {
  // 許可されていないタグを削除
  return html.replace(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>/gi, (match, tagName) => {
    if (allowedHTMLTags.includes(tagName.toLowerCase())) {
      // 許可されたタグの場合、属性もサニタイズ
      return sanitizeHTMLAttributes(match);
    }
    return ''; // 許可されていないタグは削除
  });
}

/**
 * HTMLattributesをサニタイズ
 */
function sanitizeHTMLAttributes(tag: string): string {
  return tag.replace(/\s+([\w:-]+)\s*=\s*["']([^"']*)["']/gi, (match, attrName, attrValue) => {
    const attr = attrName.toLowerCase();
    
    // 許可された属性のみ残す
    const isAllowed = allowedHTMLAttributes.some(allowed => {
      if (allowed.endsWith('*')) {
        return attr.startsWith(allowed.slice(0, -1));
      }
      return attr === allowed;
    });
    
    if (!isAllowed) return '';
    
    // style属性は特別処理
    if (attr === 'style') {
      const cleanedStyle = sanitizeCSS(attrValue);
      return cleanedStyle ? ` ${attrName}="${cleanedStyle}"` : '';
    }
    
    // その他の属性は危険なパターンをチェック
    if (/javascript:/gi.test(attrValue) || /vbscript:/gi.test(attrValue)) {
      return '';
    }
    
    // データ属性とaria属性は基本的に安全
    if (attr.startsWith('data-') || attr.startsWith('aria-')) {
      return ` ${attrName}="${encodeHTMLEntities(attrValue)}"`;
    }
    
    return ` ${attrName}="${encodeHTMLEntities(attrValue)}"`;
  });
}

/**
 * Sanitize HTML content to prevent XSS attacks (enhanced version with SVG support)
 */
export function sanitizeHTML(html: string): string {
  if (!html || typeof html !== 'string') return '';
  
  let sanitized = html;
  
  // Step 1: Remove dangerous patterns
  dangerousHTMLPatterns.forEach(pattern => {
    sanitized = sanitized.replace(pattern, '');
  });
  
  // Step 2: SVG専用サニタイズ（SVGが含まれる場合）
  if (/<svg\b[^>]*>/i.test(sanitized)) {
    sanitized = sanitized.replace(/<svg\b[^>]*>[\s\S]*?<\/svg>/gi, (svgMatch) => {
      return sanitizeSVG(svgMatch);
    });
  }
  
  // Step 3: Normalize HTML entities to prevent encoding-based attacks
  sanitized = sanitized
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#x27;/gi, "'")
    .replace(/&#x2F;/gi, '/');
  
  // Step 4: Apply whitelist-based tag sanitization
  sanitized = sanitizeHTMLTags(sanitized);
  
  // Step 5: Final cleanup - remove any remaining dangerous patterns
  dangerousHTMLPatterns.forEach(pattern => {
    sanitized = sanitized.replace(pattern, '');
  });
  
  // Step 6: Remove empty tags and normalize whitespace
  sanitized = sanitized
    .replace(/<(\w+)(\s[^>]*)?\s*><\/\1>/gi, '') // Remove empty tags
    .replace(/\s+/g, ' ') // Normalize whitespace
    .trim();
  
  return sanitized;
}

/**
 * Sanitize CSS content to prevent CSS injection attacks (enhanced version)
 */
export function sanitizeCSS(css: string): string {
  if (!css || typeof css !== 'string') return '';
  
  let sanitized = css;
  
  // Step 1: Remove dangerous CSS patterns
  dangerousCSSPatterns.forEach(pattern => {
    sanitized = sanitized.replace(pattern, '/* removed dangerous content */');
  });
  
  // Step 2: Remove CSS comments (potential XSS vector)
  sanitized = sanitized.replace(/\/\*[\s\S]*?\*\//g, '');
  
  // Step 3: Validate and sanitize URLs in CSS
  sanitized = sanitized.replace(/url\s*\(\s*["']?([^"')]+)["']?\s*\)/gi, (match, url) => {
    // 安全なURL schemes のみ許可
    const safeSchemes = ['https:', 'http:', 'data:image/', 'data:font/'];
    const isUrlSafe = safeSchemes.some(scheme => 
      url.toLowerCase().startsWith(scheme) || 
      url.startsWith('/')  // 相対パス
    );
    
    if (isUrlSafe && !url.toLowerCase().includes('javascript:') && !url.toLowerCase().includes('vbscript:')) {
      return `url("${url.replace(/["']/g, '')}")`;
    }
    return '/* unsafe url removed */';
  });
  
  // Step 4: Remove CSS @-rules that could be dangerous
  sanitized = sanitized.replace(/@(import|charset|namespace)\b[^;]+;?/gi, '/* dangerous @-rule removed */');
  
  // Step 5: Validate property values for dangerous content
  sanitized = sanitized.replace(/([\w-]+)\s*:\s*([^;]+);?/gi, (match, property, value) => {
    const prop = property.toLowerCase();
    const val = value.toLowerCase();
    
    // 特定のプロパティで危険な値をチェック
    if ((prop === 'content' || prop === 'background') && val.includes('url(')) {
      // contentやbackgroundのURL使用は制限
      return `${property}: /* url not allowed in ${prop} */;`;
    }
    
    // position: fixed は制限（overlay攻撃防止）
    if (prop === 'position' && val === 'fixed') {
      return `${property}: absolute; /* fixed positioning restricted */`;
    }
    
    // z-indexの異常に高い値を制限
    if (prop === 'z-index') {
      const zValue = parseInt(val);
      if (zValue > 9999) {
        return `${property}: 9999; /* z-index capped */`;
      }
    }
    
    return match;
  });
  
  // Step 6: Normalize whitespace and cleanup
  sanitized = sanitized
    .replace(/\s+/g, ' ')
    .replace(/;\s*;/g, ';')
    .trim();
  
  return sanitized;
}

/**
 * Sanitize JavaScript content (very strict) - Component用のJSを安全に制限
 */
export function sanitizeJS(js: string): string {
  if (!js || typeof js !== 'string') return '';
  
  let sanitized = js;
  
  // 最も危険なパターンのみを削除（緩和版）
  const criticalPatterns = [
    /\beval\s*\(/gi, // eval function calls
    /\bnew\s+Function\s*\(/gi, // Function constructor (more specific)
    /setTimeout\s*\(\s*['"`][^'"`]*<script/gi,
    /setInterval\s*\(\s*['"`][^'"`]*<script/gi,
    /document\.write\s*\(/gi,
    /document\.writeln\s*\(/gi,
    /location\s*=\s*['"`]javascript:/gi,
    /window\s*\[\s*['"`]eval['"`]\s*\]/gi,
    /\[\s*['"`]constructor['"`]\s*\]/gi, // Keep this specific - targets array access only
    /\bimport\s*\(/gi, // Dynamic imports
    /\brequire\s*\(/gi, // Node.js requires
    /<script[^>]*>/gi, // Script tags
    /javascript:/gi, // JavaScript URLs
    /vbscript:/gi, // VBScript URLs
    /data:text\/html/gi, // HTML data URLs
  ];
  
  // 危険なパターンのみを削除
  criticalPatterns.forEach(pattern => {
    sanitized = sanitized.replace(pattern, '/* potentially dangerous code removed */');
  });
  
  // 基本的な整形のみ
  sanitized = sanitized
    .replace(/\s+/g, ' ')
    .replace(/;\s*;/g, ';')
    .trim();
  
  return sanitized || '/* Empty JavaScript content */';
}



/**
 * Validate and sanitize component data (enhanced security version)
 */
export function validateAndSanitizeComponent(data: any) {
  // First validate the structure
  const validationResult = ComponentSchema.safeParse(data);
  
  if (!validationResult.success) {
    return {
      success: false,
      error: 'Validation failed',
      details: validationResult.error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message
      }))
    };
  }
  
  const validated = validationResult.data;
  
  // Enhanced sanitization with logging
  const originalHTML = validated.html;
  const originalCSS = validated.css;
  const originalJS = validated.js;
  
  const sanitized = {
    ...validated,
    name: validated.name.trim().replace(/[<>]/g, ''), // Remove angle brackets from name
    category: validated.category.trim().replace(/[<>]/g, ''),
    html: sanitizeHTML(validated.html),
    css: sanitizeCSS(validated.css),
    js: sanitizeJS(validated.js),
    tags: validated.tags.map((tag: string) => tag.trim().replace(/[<>]/g, '')).filter(Boolean)
  };
  
  // セキュリティログ: サニタイゼーションで内容が変更された場合
  const warnings = [];
  if (originalHTML !== sanitized.html && originalHTML.length > 0) {
    warnings.push('HTML content was sanitized for security');
  }
  if (originalCSS !== sanitized.css && originalCSS.length > 0) {
    warnings.push('CSS content was sanitized for security');
  }
  if (originalJS !== sanitized.js && originalJS.length > 0) {
    warnings.push('JavaScript content was sanitized for security');
  }
  
  const result: any = {
    success: true,
    data: sanitized
  };
  
  if (warnings.length > 0) {
    result.warnings = warnings;
    console.warn('Component sanitization warnings:', warnings);
  }
  
  return result;
}

/**
 * Validate and sanitize component update data
 */
export function validateAndSanitizeUpdate(data: any) {
  // First validate the structure
  const validationResult = UpdateComponentSchema.safeParse(data);
  
  if (!validationResult.success) {
    return {
      success: false,
      error: 'Validation failed',
      details: validationResult.error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message
      }))
    };
  }
  
  const validated = validationResult.data;
  
  // Then sanitize the content
  const sanitized: any = {};
  
  if (validated.name !== undefined) {
    sanitized.name = validated.name.trim();
  }
  if (validated.category !== undefined) {
    sanitized.category = validated.category.trim();
  }
  if (validated.html !== undefined) {
    sanitized.html = sanitizeHTML(validated.html);
  }
  if (validated.css !== undefined) {
    sanitized.css = sanitizeCSS(validated.css);
  }
  if (validated.js !== undefined) {
    sanitized.js = sanitizeJS(validated.js);
  }
  if (validated.tags !== undefined) {
    sanitized.tags = validated.tags.map((tag: string) => tag.trim()).filter(Boolean);
  }
  
  return {
    success: true,
    data: sanitized
  };
}

// Export types for use in other files
export type ComponentData = z.infer<typeof ComponentSchema>;
export type UpdateComponentData = z.infer<typeof UpdateComponentSchema>;