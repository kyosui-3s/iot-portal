"""
QuoteFlow — 営業見積管理 SaaS（デモ用、意図的な脆弱性を多数含む）
"""
import sqlite3
import os
import subprocess
import urllib.request
from flask import Flask, request, redirect, Response, jsonify, send_from_directory

app = Flask(__name__, static_folder='static', static_url_path='')
DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'iot_portal.db'))
PDF_DIR = os.path.join(os.path.dirname(__file__), 'quote_files')

# ─────────── Database ───────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # 既存スキーマを完全に作り直し
    for t in ('users', 'customers', 'quotes', 'quote_items', 'contacts', 'inquiries', 'devices', 'device_logs'):
        c.execute(f"DROP TABLE IF EXISTS {t}")

    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        email TEXT, password TEXT, name TEXT, role TEXT, department TEXT
    )''')
    c.execute('''CREATE TABLE customers (
        id INTEGER PRIMARY KEY,
        name TEXT, company TEXT, industry TEXT,
        email TEXT, phone TEXT, address TEXT,
        contact_person TEXT, annual_revenue INTEGER, owner_id INTEGER
    )''')
    c.execute('''CREATE TABLE contacts (
        id INTEGER PRIMARY KEY,
        customer_id INTEGER, name TEXT, email TEXT, phone TEXT, role TEXT
    )''')
    c.execute('''CREATE TABLE quotes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket TEXT, customer_id INTEGER, title TEXT,
        status TEXT, total INTEGER, tax INTEGER,
        valid_until TEXT, created_by INTEGER, created_at TEXT,
        notes TEXT
    )''')
    c.execute('''CREATE TABLE quote_items (
        id INTEGER PRIMARY KEY,
        quote_id INTEGER, product_name TEXT, description TEXT,
        qty INTEGER, unit_price INTEGER, subtotal INTEGER
    )''')

    # ─── Users ───
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?)", [
        (1, 'admin@3sec-demo.com', 'Admin123!', '管理者 太郎', 'admin', 'システム管理'),
        (2, 'tanaka@3sec-demo.com', 'User123!', '田中 営業', 'sales', '営業1課'),
        (3, 'suzuki@3sec-demo.com', 'User123!', '鈴木 営業', 'sales', '営業2課'),
    ])
    # ─── Customers ───
    c.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)", [
        (1, '山田 太郎', '株式会社サンプル工業',          '製造業', 'yamada@sample-ind.co.jp',  '03-1234-5678', '東京都千代田区1-1-1',     '山田 太郎', 5000000000, 2),
        (2, '佐藤 花子', '株式会社デモ商事',              '商社',   'sato@demo-trade.co.jp',    '06-2345-6789', '大阪府大阪市北区2-2-2',   '佐藤 花子',  800000000, 2),
        (3, '鈴木 一郎', 'テスト電子株式会社',            '電機',   'suzuki@test-elec.co.jp',   '052-3456-7890','愛知県名古屋市中区3-3-3', '鈴木 一郎', 2500000000, 3),
        (4, '高橋 美咲', '株式会社マーケット',            '小売',   'takahashi@market.co.jp',   '011-4567-8901','北海道札幌市中央区4-4-4', '高橋 美咲',  300000000, 2),
        (5, '伊藤 健太', 'グローバル物流株式会社',        '物流',   'ito@global-logi.co.jp',    '092-5678-9012','福岡県福岡市博多区5-5-5', '伊藤 健太', 1200000000, 3),
        (6, '渡辺 由美', 'スマート建設工業',              '建設',   'watanabe@smart-build.com', '045-6789-0123','神奈川県横浜市西区6-6-6', '渡辺 由美',  900000000, 2),
    ])
    # ─── Contacts ───
    c.executemany("INSERT INTO contacts VALUES (?,?,?,?,?,?)", [
        (1, 1, '山田 太郎',  'yamada@sample-ind.co.jp',    '03-1234-5678', '代表取締役'),
        (2, 1, '山本 部長',  'yamamoto@sample-ind.co.jp',  '03-1234-5679', '購買部長'),
        (3, 1, '中村 課長',  'nakamura@sample-ind.co.jp',  '03-1234-5680', '購買課長'),
        (4, 2, '佐藤 花子',  'sato@demo-trade.co.jp',      '06-2345-6789', 'CEO'),
        (5, 2, '木村 部長',  'kimura@demo-trade.co.jp',    '06-2345-6790', '営業部長'),
        (6, 3, '鈴木 一郎',  'suzuki@test-elec.co.jp',     '052-3456-7890','取締役'),
        (7, 3, '小林 主任',  'kobayashi@test-elec.co.jp',  '052-3456-7891','資材主任'),
        (8, 4, '高橋 美咲',  'takahashi@market.co.jp',     '011-4567-8901','社長'),
        (9, 5, '伊藤 健太',  'ito@global-logi.co.jp',      '092-5678-9012','COO'),
    ])
    # ─── Quotes (ticket は連番 Q-1001 から、IDOR 用) ───
    quotes_data = [
        (1,  'Q-1001', 1, 'サーバ更改一式',        'sent',     8500000, 850000, '2026-06-30', 2, '2026-05-01 10:00:00', '初回見積'),
        (2,  'Q-1002', 1, '保守契約延長',          'draft',    1200000, 120000, '2026-07-31', 2, '2026-05-05 14:30:00', '前年同条件'),
        (3,  'Q-1003', 2, 'EC構築プロジェクト',    'accepted', 25000000, 2500000,'2026-06-15', 2, '2026-04-20 09:00:00', '基本契約済'),
        (4,  'Q-1004', 3, 'IoT センサー導入',      'sent',     4800000, 480000, '2026-07-01', 3, '2026-05-10 11:00:00', '工場ライン3用'),
        (5,  'Q-1005', 3, 'ネットワーク機器更新',  'rejected', 6200000, 620000, '2026-05-31', 3, '2026-04-15 16:00:00', '今期見送り'),
        (6,  'Q-1006', 4, 'POSシステム入替',       'draft',    3500000, 350000, '2026-08-31', 2, '2026-05-20 13:00:00', '5店舗分'),
        (7,  'Q-1007', 5, '物流WMS刷新',           'sent',     18000000, 1800000,'2026-09-30', 3, '2026-05-15 10:30:00', '提案中'),
        (8,  'Q-1008', 6, 'BIMソフトライセンス',   'accepted', 5500000, 550000, '2026-06-30', 2, '2026-04-25 14:00:00', '年間契約'),
        (9,  'Q-1009', 1, 'セキュリティ監査',      'sent',     2800000, 280000, '2026-07-31', 2, '2026-05-22 09:00:00', '内部統制対応'),
        (10, 'Q-1010', 2, 'API連携開発',           'draft',    4200000, 420000, '2026-08-15', 3, '2026-05-25 15:00:00', '段階リリース'),
    ]
    c.executemany("INSERT INTO quotes (id, ticket, customer_id, title, status, total, tax, valid_until, created_by, created_at, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?)", quotes_data)

    # ─── Quote items ───
    items_data = [
        # Q-1001
        (101, 1, 'PowerEdge R760 サーバ',      'CPU x2, 256GB RAM, NVMe 4TB',     2, 2800000, 5600000),
        (102, 1, 'Cisco Catalyst 9300',        '48ポート PoE+',                    1, 1200000, 1200000),
        (103, 1, '構築・移行作業',              '土日含む計5営業日',                1, 1700000, 1700000),
        # Q-1002
        (104, 2, '年間保守',                    '24h365日',                         12, 100000, 1200000),
        # Q-1003
        (105, 3, 'EC基盤構築',                  'AWS上に構築',                      1, 18000000, 18000000),
        (106, 3, 'デザイン制作',                'TOP+10カテゴリ',                   1, 4000000, 4000000),
        (107, 3, '初期商品登録',                '5000SKU',                          1, 3000000, 3000000),
        # Q-1004
        (108, 4, '温度センサー',                'LoRaWAN対応',                      40, 80000, 3200000),
        (109, 4, 'ゲートウェイ',                'マルチプロトコル',                 4, 200000, 800000),
        (110, 4, '設置工事',                    'ライン3全域',                      1, 800000, 800000),
        # Q-1006
        (111, 6, 'POS端末',                     'タッチパネル一体型',               5, 500000, 2500000),
        (112, 6, 'バックヤード PC',             'i7/16GB',                          5, 200000, 1000000),
    ]
    c.executemany("INSERT INTO quote_items VALUES (?,?,?,?,?,?,?)", items_data)

    conn.commit()
    conn.close()

    # PDFディレクトリ準備（Path Traversal デモ用）
    os.makedirs(PDF_DIR, exist_ok=True)
    sample_pdfs = {
        'quote_Q-1001.pdf': 'QUOTE Q-1001\n\nCustomer: 株式会社サンプル工業\nTotal: 8,500,000 JPY\nValid until: 2026-06-30\n\nThis is a sample PDF.\n',
        'quote_Q-1002.pdf': 'QUOTE Q-1002\n\nCustomer: 株式会社サンプル工業\nTotal: 1,200,000 JPY\n',
        'quote_Q-1003.pdf': 'QUOTE Q-1003\n\nCustomer: 株式会社デモ商事\nTotal: 25,000,000 JPY\n',
        'quote_Q-1004.pdf': 'QUOTE Q-1004\n\nCustomer: テスト電子株式会社\nTotal: 4,800,000 JPY\n',
        'template_default.pdf': 'DEFAULT TEMPLATE\n\n[Customer Name]\n[Total]\n',
    }
    for fname, content in sample_pdfs.items():
        p = os.path.join(PDF_DIR, fname)
        if not os.path.exists(p):
            with open(p, 'w', encoding='utf-8') as f:
                f.write(content)

init_db()


# ─────────── Response Headers (意図的な脆弱性) ───────────
@app.after_request
def add_headers(response):
    # VULN: CORS 全オリジン許可 + credentials
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = '*'
    # VULN: 偽装 Server ヘッダー
    response.headers['Server'] = 'Apache/2.4.49 (Unix)'
    # VULN: セキュリティヘッダー未設定 (X-Frame-Options, CSP, HSTS etc.)
    return response


# ─────────── SPA ルーティング ───────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/dashboard')
@app.route('/customers')
@app.route('/customers/<int:cid>')
@app.route('/customers/<int:cid>/contacts')
@app.route('/customers/<int:cid>/contacts/<int:contact_id>')
@app.route('/contacts/<int:contact_id>')
@app.route('/quotes')
@app.route('/quotes/new')
@app.route('/quotes/confirm')
@app.route('/quotes/complete')
@app.route('/quotes/<int:qid>')
@app.route('/quotes/<int:qid>/items')
def spa_pages(cid=None, contact_id=None, qid=None):
    return send_from_directory('static', 'index.html')


# ─────────── sitemap / robots ───────────
@app.route('/sitemap.xml')
def sitemap():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://sub.3sec-demo.com/</loc></url>
  <url><loc>https://sub.3sec-demo.com/dashboard</loc></url>
  <url><loc>https://sub.3sec-demo.com/customers</loc></url>
  <url><loc>https://sub.3sec-demo.com/customers/1</loc></url>
  <url><loc>https://sub.3sec-demo.com/customers/1/contacts</loc></url>
  <url><loc>https://sub.3sec-demo.com/customers/1/contacts/1</loc></url>
  <url><loc>https://sub.3sec-demo.com/quotes</loc></url>
  <url><loc>https://sub.3sec-demo.com/quotes/1</loc></url>
  <url><loc>https://sub.3sec-demo.com/quotes/1/items</loc></url>
  <url><loc>https://sub.3sec-demo.com/quotes/1/pdf?file=quote_Q-1001.pdf</loc></url>
  <url><loc>https://sub.3sec-demo.com/quotes/new</loc></url>
  <url><loc>https://sub.3sec-demo.com/tools/import</loc></url>
  <url><loc>https://sub.3sec-demo.com/tools/import?url=https://example.com</loc></url>
  <url><loc>https://sub.3sec-demo.com/admin/export</loc></url>
  <url><loc>https://sub.3sec-demo.com/admin/export?format=csv</loc></url>
  <url><loc>https://sub.3sec-demo.com/api/customers?id=1</loc></url>
</urlset>"""
    return Response(xml, mimetype='application/xml')


@app.route('/robots.txt')
def robots():
    return Response("""User-agent: *
Allow: /
Disallow: /admin/
Disallow: /quotes/new
Disallow: /quotes/confirm
Disallow: /quotes/complete
Disallow: /api/quotes/submit
Disallow: /api/quotes/confirm
Disallow: /api/quotes/by-ticket/
Sitemap: https://sub.3sec-demo.com/sitemap.xml
""", mimetype='text/plain')


# ═══════════════════════════════════════════════════════════
# 認証 (VULN: SQL Injection in POST body)
# ═══════════════════════════════════════════════════════════
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def api_login():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json(force=True, silent=True) or {}
    email = data.get('email', '')
    password = data.get('password', '')
    # VULN: SQL Injection - 文字列連結
    sql = "SELECT * FROM users WHERE email='" + email + "' AND password='" + password + "'"
    try:
        conn = get_db()
        user = conn.execute(sql).fetchone()
        conn.close()
        if user:
            resp = jsonify({'success': True, 'user': {'id': user['id'], 'email': user['email'], 'name': user['name'], 'role': user['role']}})
            # VULN: HttpOnly/Secure/SameSite なし
            resp.set_cookie('session_user', email, path='/')
            resp.set_cookie('user_role', user['role'], path='/')
            return resp
        return jsonify({'success': False, 'error': f'認証失敗。実行SQL: {sql}'}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'sql': sql}), 500


# ═══════════════════════════════════════════════════════════
# REST APIs (顧客)
# ═══════════════════════════════════════════════════════════
@app.route('/api/customers')
def api_customers_list():
    # VULN: SQLi via numeric param (?id=1' で SQL syntax error)
    cid = request.args.get('id', '')
    q = request.args.get('q', '')
    conn = get_db()
    if cid:
        sql = "SELECT * FROM customers WHERE id=" + cid
        try:
            rows = conn.execute(sql).fetchall()
            conn.close()
            return jsonify({'sql': sql, 'customers': [dict(r) for r in rows]})
        except Exception as e:
            conn.close()
            return jsonify({'error': 'mysql_fetch_array(): SQL syntax error: ' + str(e), 'sql': sql}), 500
    if q:
        sql = "SELECT * FROM customers WHERE company LIKE '%" + q + "%' OR name LIKE '%" + q + "%'"
        try:
            rows = conn.execute(sql).fetchall()
            conn.close()
            return jsonify({'sql': sql, 'customers': [dict(r) for r in rows]})
        except Exception as e:
            conn.close()
            return jsonify({'error': 'You have an error in your SQL syntax: ' + str(e), 'sql': sql}), 500
    rows = conn.execute("SELECT * FROM customers").fetchall()
    conn.close()
    return jsonify({'customers': [dict(r) for r in rows]})


@app.route('/api/customers/<customer_id>')
def api_customer_detail(customer_id):
    # VULN: SQL Injection in path param + IDOR (認証なし)
    sql = "SELECT * FROM customers WHERE id=" + customer_id
    try:
        conn = get_db()
        row = conn.execute(sql).fetchone()
        contacts = conn.execute("SELECT * FROM contacts WHERE customer_id=?", (customer_id if customer_id.isdigit() else 0,)).fetchall()
        conn.close()
        if row:
            return jsonify({'customer': dict(row), 'contacts': [dict(c) for c in contacts]})
        return jsonify({'error': '顧客が見つかりません', 'sql': sql}), 404
    except Exception as e:
        return jsonify({'error': 'mysql_fetch_array(): SQL syntax error near: ' + str(e), 'sql': sql}), 500


@app.route('/api/customers/<customer_id>/contacts')
def api_customer_contacts(customer_id):
    # VULN: IDOR (認証なし) + SQLi via path param
    sql = "SELECT * FROM contacts WHERE customer_id=" + customer_id
    try:
        conn = get_db()
        rows = conn.execute(sql).fetchall()
        cust = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id if customer_id.isdigit() else 0,)).fetchone()
        conn.close()
        return jsonify({'customer': dict(cust) if cust else None, 'contacts': [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({'error': 'You have an error in your SQL syntax: ' + str(e), 'sql': sql}), 500


@app.route('/api/contacts/<contact_id>')
def api_contact_detail(contact_id):
    # VULN: IDOR (認証なし) + SQLi via path param
    sql = "SELECT ct.*, c.company AS customer_company FROM contacts ct LEFT JOIN customers c ON ct.customer_id=c.id WHERE ct.id=" + contact_id
    try:
        conn = get_db()
        row = conn.execute(sql).fetchone()
        conn.close()
        if row:
            return jsonify({'contact': dict(row)})
        return jsonify({'error': '担当者が見つかりません', 'sql': sql}), 404
    except Exception as e:
        return jsonify({'error': 'mysql_fetch_array(): SQL syntax error: ' + str(e), 'sql': sql}), 500


@app.route('/api/quotes/<quote_id>/items')
def api_quote_items(quote_id):
    # VULN: SQLi via path param
    sql = "SELECT * FROM quote_items WHERE quote_id=" + quote_id
    try:
        conn = get_db()
        rows = conn.execute(sql).fetchall()
        q = conn.execute("SELECT q.*, c.company AS customer_company FROM quotes q LEFT JOIN customers c ON q.customer_id=c.id WHERE q.id=?", (quote_id if quote_id.isdigit() else 0,)).fetchone()
        conn.close()
        return jsonify({'quote': dict(q) if q else None, 'items': [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({'error': 'You have an error in your SQL syntax: ' + str(e), 'sql': sql}), 500


# ═══════════════════════════════════════════════════════════
# REST APIs (見積)
# ═══════════════════════════════════════════════════════════
@app.route('/api/quotes')
def api_quotes_list():
    conn = get_db()
    rows = conn.execute("""SELECT q.*, c.company AS customer_company, c.name AS customer_name
                           FROM quotes q LEFT JOIN customers c ON q.customer_id=c.id
                           ORDER BY q.id DESC""").fetchall()
    conn.close()
    return jsonify({'quotes': [dict(r) for r in rows]})


@app.route('/api/quotes/<quote_id>')
def api_quote_detail(quote_id):
    # VULN: SQLi via numeric param + IDOR
    sql = "SELECT q.*, c.company AS customer_company, c.name AS customer_name FROM quotes q LEFT JOIN customers c ON q.customer_id=c.id WHERE q.id=" + quote_id
    try:
        conn = get_db()
        row = conn.execute(sql).fetchone()
        items = conn.execute("SELECT * FROM quote_items WHERE quote_id=?", (quote_id if quote_id.isdigit() else 0,)).fetchall()
        conn.close()
        if row:
            return jsonify({'quote': dict(row), 'items': [dict(i) for i in items]})
        return jsonify({'error': '見積が見つかりません', 'sql': sql}), 404
    except Exception as e:
        return jsonify({'error': 'You have an error in your SQL syntax: ' + str(e), 'sql': sql}), 500


@app.route('/api/quotes/<quote_id>', methods=['DELETE', 'OPTIONS'])
def api_quote_delete(quote_id):
    # VULN: 認可チェック無し (任意ユーザーが任意見積を削除可能、CSRFも可能)
    if request.method == 'OPTIONS':
        return '', 204
    try:
        conn = get_db()
        conn.execute("DELETE FROM quote_items WHERE quote_id=?", (int(quote_id),))
        cur = conn.execute("DELETE FROM quotes WHERE id=?", (int(quote_id),))
        conn.commit()
        deleted = cur.rowcount
        conn.close()
        if deleted == 0:
            return jsonify({'error': '見積が見つかりません'}), 404
        return jsonify({'success': True, 'deleted_id': int(quote_id)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/quotes/by-ticket/<ticket>')
def api_quote_by_ticket(ticket):
    # VULN: IDOR (連番 Q-1001..) 認証なし
    conn = get_db()
    row = conn.execute("""SELECT q.*, c.company AS customer_company, c.name AS customer_name
                          FROM quotes q LEFT JOIN customers c ON q.customer_id=c.id
                          WHERE q.ticket=?""", (ticket,)).fetchone()
    items = []
    if row:
        items = conn.execute("SELECT * FROM quote_items WHERE quote_id=?", (row['id'],)).fetchall()
    conn.close()
    if not row:
        return jsonify({'error': f'チケット {ticket} は存在しません'}), 404
    return jsonify({'quote': dict(row), 'items': [dict(i) for i in items]})


# ═══════════════════════════════════════════════════════════
# 見積作成フロー（フォームゲート、DAST自動巡回不可）
# ═══════════════════════════════════════════════════════════
@app.route('/api/quotes/confirm', methods=['POST', 'OPTIONS'])
def api_quote_confirm():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json(force=True, silent=True) or {}
    if not (data.get('customer_id') and data.get('title') and data.get('total')):
        return jsonify({'error': '必須項目が未入力です'}), 422
    return jsonify(data)


@app.route('/api/quotes/submit', methods=['POST', 'OPTIONS'])
def api_quote_submit():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json(force=True, silent=True) or {}
    if not (data.get('customer_id') and data.get('title') and data.get('total')):
        return jsonify({'error': '必須項目が未入力です'}), 422
    conn = get_db()
    # VULN: 連番チケット (IDOR で他の見積を閲覧可能)
    cur = conn.execute("SELECT MAX(CAST(SUBSTR(ticket,3) AS INTEGER)) FROM quotes WHERE ticket LIKE 'Q-%'")
    last = cur.fetchone()[0] or 1000
    new_ticket = f'Q-{int(last)+1}'
    conn.execute("""INSERT INTO quotes (ticket, customer_id, title, status, total, tax, valid_until, created_by, created_at, notes)
                    VALUES (?, ?, ?, 'draft', ?, ?, ?, 2, datetime('now'), ?)""",
                 (new_ticket, data.get('customer_id'), data.get('title'), int(data.get('total', 0)),
                  int(int(data.get('total', 0)) * 0.1), data.get('valid_until', '2026-12-31'), data.get('notes', '')))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'ticket': new_ticket})


# ═══════════════════════════════════════════════════════════
# 見積 PDF ダウンロード (VULN: Path Traversal / LFI)
# ═══════════════════════════════════════════════════════════
@app.route('/quotes/<quote_id>/pdf')
def quote_pdf(quote_id):
    fname = request.args.get('file', f'quote_Q-1001.pdf')
    # VULN: パス検証なし → /quotes/X/pdf?file=../../etc/passwd で /etc/passwd 読み込み
    filepath = os.path.join(PDF_DIR, fname)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        return Response(content, mimetype='text/plain',
                        headers={'Content-Disposition': f'inline; filename="{fname}"'})
    except Exception as e:
        return Response(f'<h1>PDF読み込みエラー</h1><p>{e}</p><p>パス: {filepath}</p>', mimetype='text/html', status=500)


# ═══════════════════════════════════════════════════════════
# レガシーHTML: 顧客検索 (SQLi error-based + 反射XSS)
# ═══════════════════════════════════════════════════════════
@app.route('/customers/search')
def customers_search_html():
    q = request.args.get('q', '')
    if not q:
        return Response('''<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>顧客検索（旧UI）</title>
<style>body{font-family:Arial;max-width:900px;margin:40px auto;padding:0 20px}
input{padding:8px;font-size:14px;width:300px}button{padding:8px 16px;background:#2563eb;color:#fff;border:0;cursor:pointer;font-size:14px}
table{width:100%;border-collapse:collapse;margin-top:20px}th,td{padding:8px;border:1px solid #ddd}th{background:#1e3a5f;color:#fff}</style></head>
<body>
<h1>顧客検索（旧UI）</h1>
<p>レガシー互換のため残されている検索ページです。</p>
<form method="GET" action="/customers/search">
  <input name="q" placeholder="会社名 / 担当者名" autofocus>
  <button type="submit">検索</button>
</form>
<p><a href="/customers/search?q=サンプル">サンプル: サンプル</a> | <a href="/customers/search?q=株式会社">株式会社</a></p>
</body></html>''', mimetype='text/html')

    # VULN: SQLi 文字列連結
    sql = "SELECT id, name, company, industry, email, phone FROM customers WHERE company LIKE '%" + q + "%' OR name LIKE '%" + q + "%' OR contact_person LIKE '%" + q + "%'"
    try:
        conn = get_db()
        rows = conn.execute(sql).fetchall()
        conn.close()
        result_rows = ''.join(
            f'<tr><td>{r["id"]}</td><td>{r["name"]}</td><td>{r["company"]}</td><td>{r["industry"]}</td><td>{r["email"]}</td><td>{r["phone"]}</td></tr>'
            for r in rows
        )
        # VULN: q をエスケープせず title/body に埋め込む (反射XSS)
        return Response(f'''<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>検索結果: {q}</title></head>
<body style="font-family:Arial;max-width:900px;margin:40px auto;padding:0 20px">
<h1>検索結果: {q}</h1>
<p>実行SQL: <code>{sql}</code></p>
<p>該当: {len(rows)} 件</p>
<table border="1" cellpadding="5">
<tr><th>ID</th><th>担当者</th><th>会社名</th><th>業種</th><th>メール</th><th>電話</th></tr>
{result_rows}
</table>
<p><a href="/customers/search">← 戻る</a></p>
</body></html>''', mimetype='text/html')
    except Exception as e:
        # VULN: SQL error 露出 + 500
        return Response(f'''<!DOCTYPE html>
<html><body>
<h1>Database Error</h1>
<p><strong>You have an error in your SQL syntax:</strong> {str(e)}</p>
<p><strong>SQL:</strong> <code>{sql}</code></p>
<p><strong>Input q:</strong> {q}</p>
<a href="/customers/search">戻る</a>
</body></html>''', mimetype='text/html', status=500)


# ═══════════════════════════════════════════════════════════
# ツール: 他社見積URL取込 (VULN: SSRF)
# ═══════════════════════════════════════════════════════════
@app.route('/tools/import')
def tools_import_html():
    url = request.args.get('url', '')
    if not url:
        return Response('''<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>他社見積URL取込</title></head>
<body style="font-family:Arial;max-width:800px;margin:40px auto;padding:0 20px">
<h1>他社見積URL取込ツール</h1>
<p>競合他社が Web 公開している見積テンプレートを参照する機能です。</p>
<form method="GET" action="/tools/import">
  <label>URL: <input type="text" name="url" value="https://example.com/quote-template.html" style="padding:8px;width:500px"></label>
  <button type="submit" style="padding:8px 16px;background:#2563eb;color:#fff;border:0">取得</button>
</form>
</body></html>''', mimetype='text/html')

    # VULN: SSRF - 任意URL fetch、IMDS や内部ネットワーク到達可
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'QuoteFlow-Importer/1.0'})
        resp = urllib.request.urlopen(req, timeout=5)
        body = resp.read(16384).decode('utf-8', errors='replace')
        status_code = resp.status
        headers_str = '\n'.join(f'{k}: {v}' for k, v in resp.headers.items())
    except Exception as e:
        body = str(e)
        status_code = 0
        headers_str = ''
    return Response(f'''<!DOCTYPE html>
<html><body style="font-family:Arial;max-width:900px;margin:40px auto;padding:0 20px">
<h1>取込結果</h1>
<p>URL: <code>{url}</code></p>
<p>Status: <strong>{status_code}</strong></p>
<h3>Response Headers</h3>
<pre style="background:#f5f5f5;padding:10px">{headers_str}</pre>
<h3>Response Body</h3>
<pre style="background:#f5f5f5;padding:10px;max-height:500px;overflow:auto">{body}</pre>
<a href="/tools/import">戻る</a>
</body></html>''', mimetype='text/html')


# ═══════════════════════════════════════════════════════════
# 管理者: バッチエクスポート (VULN: OS Command Injection)
# ═══════════════════════════════════════════════════════════
@app.route('/admin/export')
def admin_export_html():
    fmt = request.args.get('format', '')
    cmd_arg = request.args.get('cmd', '')
    if not fmt and not cmd_arg:
        return Response('''<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>管理者: データエクスポート</title></head>
<body style="font-family:Arial;max-width:800px;margin:40px auto;padding:0 20px">
<h1>データエクスポート（管理者用）</h1>
<form method="GET" action="/admin/export">
  <label>フォーマット:
    <select name="format" style="padding:8px"><option>csv</option><option>tsv</option><option>json</option></select>
  </label>
  <label>追加オプション: <input name="cmd" value="" placeholder="echo done" style="padding:8px;width:300px"></label>
  <button type="submit" style="padding:8px 16px;background:#dc2626;color:#fff;border:0">エクスポート実行</button>
</form>
<p style="color:#666;font-size:12px">追加オプションは内部スクリプトに渡されます。</p>
</body></html>''', mimetype='text/html')

    # VULN: OS Command Injection - shell=True + 入力直接連結 (区切り ; で直接実行可能)
    full_cmd = f"echo 'Exporting {fmt}...'; {cmd_arg if cmd_arg else 'echo done'}"
    try:
        output = subprocess.check_output(full_cmd, shell=True, stderr=subprocess.STDOUT, timeout=8).decode('utf-8', errors='replace')
        status = 200
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='replace') if e.output else str(e)
        status = 200
    except Exception as e:
        output = str(e)
        status = 500
    return Response(f'''<!DOCTYPE html>
<html><body style="font-family:Arial;max-width:900px;margin:40px auto;padding:0 20px">
<h1>エクスポート実行ログ</h1>
<p>実行コマンド: <code>{full_cmd}</code></p>
<pre style="background:#000;color:#0f0;padding:10px">{output}</pre>
<a href="/admin/export">戻る</a>
</body></html>''', mimetype='text/html', status=status)


# ═══════════════════════════════════════════════════════════
# 起動
# ═══════════════════════════════════════════════════════════
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
