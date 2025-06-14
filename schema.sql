-- schema.sql - Components Database Schema
-- Cloudflare D1 (SQLite) Database Schema

CREATE TABLE IF NOT EXISTS components (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'Other',
    html TEXT NOT NULL DEFAULT '',
    css TEXT NOT NULL DEFAULT '',
    js TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]', -- JSON array as string
    author TEXT NOT NULL DEFAULT 'Anonymous',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- インデックスの作成
CREATE INDEX IF NOT EXISTS idx_components_category ON components(category);
CREATE INDEX IF NOT EXISTS idx_components_created_at ON components(created_at);
CREATE INDEX IF NOT EXISTS idx_components_updated_at ON components(updated_at);
CREATE INDEX IF NOT EXISTS idx_components_is_deleted ON components(is_deleted);
CREATE INDEX IF NOT EXISTS idx_components_name ON components(name);

-- 検索用のインデックス
CREATE INDEX IF NOT EXISTS idx_components_search ON components(name, category, tags);

-- サンプルデータの挿入（テスト用）
INSERT OR IGNORE INTO components (
    id, name, category, html, css, js, tags, author, created_at, updated_at
) VALUES (
    'sample-button-001',
    'Basic Button',
    'UI',
    '<button class="btn-primary">Click Me</button>',
    '.btn-primary { background: #3b82f6; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; } .btn-primary:hover { background: #2563eb; }',
    'document.querySelector(".btn-primary").addEventListener("click", () => alert("Button clicked!"));',
    '["button", "ui", "interactive"]',
    'System',
    datetime('now'),
    datetime('now')
);

INSERT OR IGNORE INTO components (
    id, name, category, html, css, js, tags, author, created_at, updated_at
) VALUES (
    'sample-card-001',
    'Info Card',
    'Layout',
    '<div class="info-card"><h3>Card Title</h3><p>Card content goes here.</p></div>',
    '.info-card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); } .info-card h3 { margin: 0 0 8px 0; color: #1f2937; } .info-card p { margin: 0; color: #6b7280; }',
    '',
    '["card", "layout", "container"]',
    'System',
    datetime('now'),
    datetime('now')
);
