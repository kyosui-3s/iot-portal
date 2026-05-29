import sqlite3
import os
import json
import subprocess
import urllib.request
from flask import Flask, request, redirect, Response, jsonify, send_from_directory

app = Flask(__name__, static_folder='static', static_url_path='')
DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'iot_portal.db'))
LOG_DIR = os.path.join(os.path.dirname(__file__), 'device_logs')

# ─────────── Database ───────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, role TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, name TEXT, type TEXT, location TEXT, status TEXT, ip_address TEXT, firmware TEXT)')
    # スキーマ移行: 旧 inquiries に ticket カラムが無ければ作り直し
    c.execute("CREATE TABLE IF NOT EXISTS inquiries (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, name TEXT, email TEXT, company TEXT, message TEXT, created_at TEXT)")
    cols = [r[1] for r in c.execute("PRAGMA table_info(inquiries)").fetchall()]
    if 'ticket' not in cols:
        c.execute("DROP TABLE inquiries")
        c.execute("CREATE TABLE inquiries (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, name TEXT, email TEXT, company TEXT, message TEXT, created_at TEXT)")
    c.execute('CREATE TABLE IF NOT EXISTS device_logs (id INTEGER PRIMARY KEY, device_id INTEGER, level TEXT, message TEXT, created_at TEXT)')
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users VALUES (1,'admin@3sec-demo.com','Admin123!','admin')")
    c.execute("INSERT INTO users VALUES (2,'user@3sec-demo.com','User123!','user')")
    c.execute("DELETE FROM devices")
    devices = [
        (1, '温度センサー A', 'sensor',    '工場棟1F',       'online',  '192.168.1.101', 'v2.1.3'),
        (2, '湿度センサー B', 'sensor',    '工場棟2F',       'online',  '192.168.1.102', 'v2.1.3'),
        (3, '圧力センサー C', 'sensor',    '倉庫棟',         'warning', '192.168.1.103', 'v2.0.1'),
        (4, '振動センサー D', 'sensor',    '工場棟1F',       'online',  '192.168.1.104', 'v2.1.3'),
        (5, 'カメラ E',       'camera',    '正門',           'online',  '192.168.1.105', 'v1.8.0'),
        (6, '温度センサー F', 'sensor',    '研究棟',         'offline', '192.168.1.106', 'v2.0.1'),
    ]
    c.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?,?)", devices)

    # Seed device_logs
    c.execute("DELETE FROM device_logs")
    seed_logs = [
        (101, 1, 'INFO',    '温度: 24.5℃ 正常範囲',                     '2026-05-29 09:00:00'),
        (102, 1, 'WARNING', '温度上昇検知 27.8℃',                       '2026-05-29 09:15:00'),
        (103, 1, 'INFO',    'キャリブレーション完了',                    '2026-05-29 09:30:00'),
        (201, 2, 'INFO',    '湿度: 52% 正常',                            '2026-05-29 09:00:00'),
        (202, 2, 'ERROR',   'センサー通信タイムアウト',                  '2026-05-29 10:42:00'),
        (301, 3, 'WARNING', '圧力異常 1.8MPa（閾値超過）',               '2026-05-29 08:00:00'),
        (302, 3, 'WARNING', 'メンテナンス推奨',                          '2026-05-29 08:30:00'),
    ]
    c.executemany("INSERT INTO device_logs VALUES (?,?,?,?,?)", seed_logs)

    # Reset inquiries
    c.execute("DELETE FROM inquiries")
    # Seed inquiries (IDOR デモ用 - 連番ticket)
    seed_inquiries = [
        (1, '10000001', '山田 太郎', 'yamada@example.co.jp', '株式会社サンプル',     '導入相談です',     '2026-05-20 10:00:00'),
        (2, '10000002', '鈴木 花子', 'suzuki@example.co.jp', '株式会社テスト',       '見積もり依頼',     '2026-05-22 14:30:00'),
        (3, '10000003', '佐藤 一郎', 'sato@example.co.jp',   '株式会社デモ',         '機能について',     '2026-05-25 09:15:00'),
    ]
    c.executemany("INSERT INTO inquiries (id, ticket, name, email, company, message, created_at) VALUES (?,?,?,?,?,?,?)", seed_inquiries)
    conn.commit()
    conn.close()

    # ログファイルディレクトリ作成 + サンプルログファイル作成（パストラバーサルデモ用）
    os.makedirs(LOG_DIR, exist_ok=True)
    sample_files = {
        '101.log': "[2026-05-29 09:00:00] INFO 温度: 24.5℃ 正常範囲\n[2026-05-29 09:01:00] DEBUG sensor poll ok\n",
        '102.log': "[2026-05-29 09:15:00] WARNING 温度上昇検知 27.8℃\n[2026-05-29 09:16:00] DEBUG threshold=25\n",
        '103.log': "[2026-05-29 09:30:00] INFO キャリブレーション完了\n",
        '201.log': "[2026-05-29 09:00:00] INFO 湿度: 52% 正常\n",
        '202.log': "[2026-05-29 10:42:00] ERROR センサー通信タイムアウト\nretry=3\n",
        '301.log': "[2026-05-29 08:00:00] WARNING 圧力異常 1.8MPa（閾値超過）\nthreshold=1.5\n",
        '302.log': "[2026-05-29 08:30:00] WARNING メンテナンス推奨\n",
    }
    for fname, content in sample_files.items():
        p = os.path.join(LOG_DIR, fname)
        if not os.path.exists(p):
            with open(p, 'w', encoding='utf-8') as f:
                f.write(content)

init_db()

# ─────────── Response Headers (意図的に不備) ───────────
@app.after_request
def add_headers(response):
    # VULN: CORS 誤設定 - 全オリジン許可 + credentials
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = '*'
    # VULN: 偽装 Server ヘッダー
    response.headers['Server'] = 'Apache/2.4.49 (Unix)'
    # VULN: セキュリティヘッダー未設定
    return response

# ─────────── SPA: 全てのフロントエンドルーティングを index.html に ───────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

# ─────────── レガシーHTML検索画面（DAST検出用に明示的に残す） ───────────
# VULN: SQL Injection (反射型) + Reflected XSS + SQL文露出
# /devices/search?q=X' OR '1'='1 で発火、エラー時 SQL文丸出し
@app.route('/devices/search')
def devices_search_legacy():
    q = request.args.get('q', '')
    if not q:
        # 空クエリは検索フォーム表示
        return Response('''<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>デバイス検索（レガシー）</title>
<style>body{font-family:Arial,sans-serif;max-width:800px;margin:40px auto;padding:0 20px}
input{padding:8px;font-size:14px;width:300px}button{padding:8px 16px;background:#2563eb;color:#fff;border:0;cursor:pointer}
table{width:100%;border-collapse:collapse;margin-top:20px}th,td{padding:8px;border:1px solid #ddd;text-align:left}
th{background:#1e3a5f;color:#fff}</style></head>
<body>
<h1>デバイス検索（レガシー版）</h1>
<p>古いシステムとの互換性のため残されている検索ページです。</p>
<form method="GET" action="/devices/search">
  <input name="q" placeholder="デバイス名 / 設置場所" autofocus>
  <button type="submit">検索</button>
</form>
<p><a href="/devices/search?q=sensor">サンプル: sensor</a></p>
</body></html>''', mimetype='text/html')

    # VULN: SQL injection - 文字列連結
    sql = "SELECT id, name, type, location, status, ip_address, firmware FROM devices WHERE name LIKE '%" + q + "%' OR location LIKE '%" + q + "%'"
    try:
        conn = get_db()
        rows = conn.execute(sql).fetchall()
        conn.close()
        result_rows = ''.join(
            f'<tr><td>{r["id"]}</td><td>{r["name"]}</td><td>{r["type"]}</td><td>{r["location"]}</td><td>{r["status"]}</td><td>{r["ip_address"]}</td><td>{r["firmware"]}</td></tr>'
            for r in rows
        )
        # VULN: Reflected XSS - q を未エスケープで埋め込み
        html = f'''<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>検索結果: {q}</title></head>
<body>
<h1>検索結果: {q}</h1>
<p>実行SQL: <code>{sql}</code></p>
<p>該当: {len(rows)} 件</p>
<table border="1" cellpadding="5">
<tr><th>ID</th><th>名称</th><th>種別</th><th>設置場所</th><th>状態</th><th>IP</th><th>FW</th></tr>
{result_rows}
</table>
<p><a href="/devices/search">← 戻る</a></p>
</body></html>'''
        return Response(html, mimetype='text/html')
    except Exception as e:
        # VULN: SQL エラー詳細露出 + 500 ステータス
        err_html = f'''<!DOCTYPE html>
<html><body>
<h1>Database Error</h1>
<p><strong>Error:</strong> {str(e)}</p>
<p><strong>SQL:</strong> <code>{sql}</code></p>
<p><strong>Query:</strong> {q}</p>
<a href="/devices/search">戻る</a>
</body></html>'''
        return Response(err_html, mimetype='text/html', status=500)


# ─────────── REST API版: クエリパラメータSQLi ───────────
# VULN: GET /api/devices?q=X' OR '1'='1 で発火
@app.route('/api/devices')
def api_devices_query():
    q = request.args.get('q', '')
    conn = get_db()
    if q:
        sql = "SELECT * FROM devices WHERE name LIKE '%" + q + "%'"
        try:
            rows = conn.execute(sql).fetchall()
            conn.close()
            return jsonify({'query': q, 'sql': sql, 'devices': [dict(r) for r in rows]})
        except Exception as e:
            conn.close()
            return jsonify({'error': f'SQL Error: {str(e)}', 'sql': sql, 'query': q}), 500
    rows = conn.execute("SELECT * FROM devices").fetchall()
    conn.close()
    return jsonify({'devices': [dict(r) for r in rows]})


@app.route('/dashboard')
@app.route('/devices')
@app.route('/devices/<path:rest>')
@app.route('/contact')
@app.route('/contact/<path:rest>')
def spa_pages(rest=None):
    return send_from_directory('static', 'index.html')

# ─────────── sitemap / robots ───────────
@app.route('/sitemap.xml')
def sitemap():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://sub.3sec-demo.com/</loc></url>
  <url><loc>http://sub.3sec-demo.com/dashboard</loc></url>
  <url><loc>http://sub.3sec-demo.com/devices</loc></url>
  <url><loc>http://sub.3sec-demo.com/devices/1</loc></url>
  <url><loc>http://sub.3sec-demo.com/devices/1/logs</loc></url>
  <url><loc>http://sub.3sec-demo.com/devices/search</loc></url>
  <url><loc>http://sub.3sec-demo.com/devices/search?q=sensor</loc></url>
  <url><loc>http://sub.3sec-demo.com/api/devices?q=sensor</loc></url>
  <url><loc>http://sub.3sec-demo.com/contact</loc></url>
  <url><loc>http://sub.3sec-demo.com/graphql</loc></url>
  <url><loc>http://sub.3sec-demo.com/partner/</loc></url>
</urlset>"""
    return Response(xml, mimetype='application/xml')

@app.route('/robots.txt')
def robots():
    return Response("User-agent: *\nAllow: /\nSitemap: http://sub.3sec-demo.com/sitemap.xml\n", mimetype='text/plain')

# ─────────── REST API: ログイン ───────────
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def api_login():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json(force=True, silent=True) or {}
    email = data.get('email', '')
    password = data.get('password', '')

    # VULN: SQL インジェクション - 文字列連結でクエリ組み立て
    sql = "SELECT * FROM users WHERE email='" + email + "' AND password='" + password + "'"
    try:
        conn = get_db()
        user = conn.execute(sql).fetchone()
        conn.close()
        if user:
            resp = jsonify({'success': True, 'user': {'id': user['id'], 'email': user['email'], 'role': user['role']}})
            # VULN: Cookie - HttpOnly/Secure/SameSite 属性なし
            resp.set_cookie('session_user', email, path='/')
            resp.set_cookie('user_role', user['role'], path='/')
            return resp
        return jsonify({'success': False, 'error': f'ログイン失敗。SQL: {sql}'}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'sql': sql}), 500

# ─────────── GraphQL API ───────────
def resolve_graphql(query, variables=None):
    variables = variables or {}
    q = query.strip()

    # IntrospectionQuery - VULN: イントロスペクション有効
    if '__schema' in q or '__type' in q:
        return {'data': {'__schema': {
            'types': [
                {'name': 'Query', 'fields': [
                    {'name': 'devices', 'args': [{'name': 'search', 'type': 'String'}]},
                    {'name': 'device', 'args': [{'name': 'id', 'type': 'Int!'}]},
                    {'name': 'users', 'args': []},
                    {'name': 'ping', 'args': [{'name': 'host', 'type': 'String!'}]},
                    {'name': 'fetch_url', 'args': [{'name': 'url', 'type': 'String!'}]},
                ]},
                {'name': 'Mutation', 'fields': [
                    {'name': 'submitInquiry', 'args': [
                        {'name': 'name', 'type': 'String!'},
                        {'name': 'email', 'type': 'String!'},
                        {'name': 'company', 'type': 'String'},
                        {'name': 'message', 'type': 'String!'},
                    ]},
                ]},
                {'name': 'Device', 'fields': [
                    {'name': 'id'}, {'name': 'name'}, {'name': 'type'},
                    {'name': 'location'}, {'name': 'status'},
                    {'name': 'ip_address'}, {'name': 'firmware'},
                ]},
                {'name': 'PingResult', 'fields': [{'name': 'host'}, {'name': 'output'}]},
                {'name': 'FetchResult', 'fields': [{'name': 'url'}, {'name': 'status'}, {'name': 'body'}]},
            ],
            'queryType': {'name': 'Query'},
            'mutationType': {'name': 'Mutation'},
        }}}

    import re
    # devices query
    if 'devices' in q and 'device(' not in q:
        search = variables.get('search', '')
        m = re.search(r'search\s*:\s*"([^"]*)"', q)
        if m:
            search = m.group(1)
        conn = get_db()
        if search:
            # VULN: SQL インジェクション（GraphQL 経由）
            sql = "SELECT * FROM devices WHERE name LIKE '%" + search + "%' OR location LIKE '%" + search + "%'"
            try:
                rows = conn.execute(sql).fetchall()
            except Exception as e:
                conn.close()
                return {'errors': [{'message': f'SQL Error: {str(e)}', 'sql': sql}]}
        else:
            rows = conn.execute("SELECT * FROM devices").fetchall()
        conn.close()
        return {'data': {'devices': [dict(r) for r in rows]}}

    # single device
    if 'device(' in q:
        m = re.search(r'id\s*:\s*(\d+)', q)
        did = int(m.group(1)) if m else variables.get('id', 1)
        conn = get_db()
        row = conn.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
        conn.close()
        return {'data': {'device': dict(row) if row else None}}

    # ping - VULN: OS コマンドインジェクション (GraphQL 経由のみ残す。UI からは到達しない)
    if 'ping' in q:
        m = re.search(r'host\s*:\s*"([^"]*)"', q)
        host = m.group(1) if m else variables.get('host', '127.0.0.1')
        output = subprocess.getoutput(f'ping -c 1 -W 2 {host} 2>&1')
        return {'data': {'ping': {'host': host, 'output': output}}}

    # fetch_url - VULN: SSRF (GraphQL 経由のみ残す)
    if 'fetch_url' in q:
        m = re.search(r'url\s*:\s*"([^"]*)"', q)
        url = m.group(1) if m else variables.get('url', '')
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'IoT-Portal/1.0'})
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read(4096).decode('utf-8', errors='replace')
            return {'data': {'fetch_url': {'url': url, 'status': resp.status, 'body': body}}}
        except Exception as e:
            return {'data': {'fetch_url': {'url': url, 'status': 0, 'body': str(e)}}}

    # users
    if 'users' in q:
        conn = get_db()
        rows = conn.execute("SELECT id, email, role FROM users").fetchall()
        conn.close()
        return {'data': {'users': [dict(r) for r in rows]}}

    # submitInquiry mutation
    if 'submitInquiry' in q:
        name = re.search(r'name\s*:\s*"([^"]*)"', q)
        email = re.search(r'email\s*:\s*"([^"]*)"', q)
        message = re.search(r'message\s*:\s*"([^"]*)"', q)
        n = name.group(1) if name else variables.get('name', '')
        e = email.group(1) if email else variables.get('email', '')
        msg = message.group(1) if message else variables.get('message', '')
        conn = get_db()
        conn.execute("INSERT INTO inquiries (ticket, name, email, message, created_at) VALUES (?, ?, ?, ?, datetime('now'))", ('legacy', n, e, msg))
        conn.commit()
        conn.close()
        return {'data': {'submitInquiry': {'name': n, 'email': e, 'message': msg}}}

    return {'errors': [{'message': 'Unknown query'}]}

@app.route('/graphql', methods=['GET', 'POST', 'OPTIONS'])
def graphql_endpoint():
    if request.method == 'OPTIONS':
        return '', 204
    if request.method == 'GET':
        # VULN: GraphQL Playground を本番で公開
        return '''<!DOCTYPE html>
<html><head><title>GraphQL Playground</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/graphql-playground-react/build/static/css/index.css"/>
<script src="https://cdn.jsdelivr.net/npm/graphql-playground-react/build/static/js/middleware.js"></script>
</head><body><div id="root"></div><script>
window.addEventListener('load',function(){
GraphQLPlayground.init(document.getElementById('root'),{endpoint:'/graphql'})
})</script></body></html>''', 200, {'Content-Type': 'text/html'}

    data = request.get_json(force=True, silent=True) or {}
    query = data.get('query', '')
    variables = data.get('variables', {})
    result = resolve_graphql(query, variables)
    return jsonify(result)

# ─────────── REST API: デバイス詳細 ───────────
@app.route('/api/device/<device_id>')
def api_device_detail(device_id):
    # VULN: SQL インジェクション - パスパラメータを直接SQLに組み込み
    sql = "SELECT * FROM devices WHERE id=" + device_id
    try:
        conn = get_db()
        row = conn.execute(sql).fetchone()
        conn.close()
        if row:
            return jsonify(dict(row))
        return jsonify({'error': f'デバイスが見つかりません (ID: {device_id})<br>実行SQL: {sql}'}), 404
    except Exception as e:
        return jsonify({'error': f'<strong>Database Error</strong>: {str(e)}<br>SQL: {sql}<br>入力値: {device_id}'}), 500

# ─────────── REST API: デバイスログ一覧 ───────────
# VULN: Stored XSS - ログメッセージはアンエスケープのまま返却し、フロント側でv-htmlレンダリング
@app.route('/api/device/<int:device_id>/logs')
def api_device_logs(device_id):
    keyword = request.args.get('q', '')
    conn = get_db()
    if keyword:
        # VULN: SQL インジェクション + 検索キーワードがメッセージにそのまま埋め込まれる
        sql = f"SELECT * FROM device_logs WHERE device_id={device_id} AND message LIKE '%{keyword}%'"
        try:
            rows = conn.execute(sql).fetchall()
        except Exception as e:
            conn.close()
            return jsonify({'error': str(e), 'sql': sql}), 500
    else:
        rows = conn.execute("SELECT * FROM device_logs WHERE device_id=?", (device_id,)).fetchall()
    conn.close()
    return jsonify({'logs': [dict(r) for r in rows], 'keyword': keyword})

# ─────────── REST API: デバイスログ追加（Stored XSS 投入口） ───────────
# VULN: 認証なしで任意デバイスにログを書き込める + サニタイズなし → Stored XSS
@app.route('/api/device/<int:device_id>/logs', methods=['POST'])
def api_device_logs_add(device_id):
    data = request.get_json(force=True, silent=True) or {}
    message = data.get('message', '')
    level = data.get('level', 'INFO')
    conn = get_db()
    # VULN: メッセージをサニタイズせずに保存
    conn.execute("INSERT INTO device_logs (device_id, level, message, created_at) VALUES (?, ?, ?, datetime('now'))",
                 (device_id, level, message))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ─────────── REST API: ログ詳細（パストラバーサル） ───────────
# VULN: log_id をファイル名に直接利用 → ../../etc/passwd 等にアクセス可能
@app.route('/api/device/<int:device_id>/logs/<log_id>')
def api_device_log_detail(device_id, log_id):
    # DBからメタ情報取得
    conn = get_db()
    try:
        meta = conn.execute("SELECT * FROM device_logs WHERE id=?", (int(log_id),)).fetchone()
    except Exception:
        meta = None
    conn.close()

    # VULN: log_id をファイルパスに直接利用（パストラバーサル）
    filepath = os.path.join(LOG_DIR, log_id + '.log')
    raw_content = ''
    error = ''
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            raw_content = f.read()
    except Exception as e:
        error = f'ログファイル読込エラー: {e} (path={filepath})'

    return jsonify({
        'meta': dict(meta) if meta else None,
        'raw': raw_content,
        'error': error,
        'filepath': filepath,
    })

# ─────────── REST API: お問い合わせ確認（フォーム必須） ───────────
# このエンドポイントは POST のみ受付。GET だと422返却 → DAST 自動巡回不可
# VULN: CSRF トークンなし + 入力をそのまま返却（反射型XSSの土台）
@app.route('/api/inquiry/confirm', methods=['POST', 'OPTIONS'])
def api_inquiry_confirm():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json(force=True, silent=True) or {}
    name = data.get('name', '')
    email = data.get('email', '')
    company = data.get('company', '')
    message = data.get('message', '')
    if not (name and email and message):
        return jsonify({'error': '必須項目が未入力です'}), 422
    # 確認画面用に echo back（DB保存はまだ）
    return jsonify({'name': name, 'email': email, 'company': company, 'message': message})

# ─────────── REST API: お問い合わせ送信 ───────────
@app.route('/api/inquiry/submit', methods=['POST', 'OPTIONS'])
def api_inquiry_submit():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json(force=True, silent=True) or {}
    name = data.get('name', '')
    email = data.get('email', '')
    company = data.get('company', '')
    message = data.get('message', '')
    if not (name and email and message):
        return jsonify({'error': '必須項目が未入力です'}), 422

    # VULN: チケット番号は単純な連番（推測可能） → IDOR
    conn = get_db()
    cur = conn.execute("SELECT MAX(CAST(ticket AS INTEGER)) FROM inquiries WHERE ticket GLOB '[0-9]*'")
    last = cur.fetchone()[0] or 10000000
    new_ticket = str(int(last) + 1)
    conn.execute("INSERT INTO inquiries (ticket, name, email, company, message, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
                 (new_ticket, name, email, company, message))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'ticket': new_ticket})

# ─────────── REST API: お問い合わせ参照（IDOR） ───────────
# VULN: チケット番号さえ知っていれば認証なしで他人の問い合わせを閲覧可能
@app.route('/api/inquiry/<ticket>')
def api_inquiry_get(ticket):
    conn = get_db()
    row = conn.execute("SELECT * FROM inquiries WHERE ticket=?", (ticket,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'チケットが見つかりません'}), 404
    return jsonify(dict(row))

# ─────────── レガシー（GraphQL submitInquiry経由でも使われる）───────────
@app.route('/api/inquiry', methods=['POST', 'OPTIONS'])
def api_inquiry_legacy():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json(force=True, silent=True) or {}
    conn = get_db()
    conn.execute("INSERT INTO inquiries (ticket, name, email, company, message, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
                 ('legacy', data.get('name',''), data.get('email',''), data.get('company',''), data.get('message','')))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'お問い合わせを受け付けました'})

# ─────────── オープンリダイレクト（既存） ───────────
@app.route('/redirect')
def open_redirect():
    url = request.args.get('url', '/')
    return redirect(url)

# ─────────── パートナーポータル（既存維持） ───────────

PARTNER_PAGE_STYLE = """
<style>
  body { font-family: 'Helvetica Neue', Arial, sans-serif; margin: 0; background: #f8fafc; color: #333; }
  .partner-header { background: linear-gradient(135deg, #1e3a5f, #2563eb); padding: 16px 24px; }
  .partner-header h1 { color: #fff; font-size: 18px; margin: 0; }
  .partner-header p { color: #93c5fd; font-size: 13px; margin: 4px 0 0; }
  .container { max-width: 900px; margin: 0 auto; padding: 24px; }
  .card { background: #fff; border: 2px solid #e2e8f0; border-radius: 12px; padding: 32px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
  .form-group { margin-bottom: 20px; }
  .form-group label { display: block; font-size: 14px; font-weight: 700; color: #1e3a5f; margin-bottom: 6px; }
  .form-group input { width: 100%; padding: 12px 16px; border: 2px solid #cbd5e1; border-radius: 8px; font-size: 14px; box-sizing: border-box; }
  .form-group input:focus { outline: none; border-color: #2563eb; }
  .form-group .hint { font-size: 12px; color: #94a3b8; margin-top: 4px; }
  .btn { padding: 12px 32px; border: none; border-radius: 8px; font-size: 14px; font-weight: 700; cursor: pointer; }
  .btn-primary { background: #2563eb; color: #fff; }
  .btn-primary:hover { background: #1d4ed8; }
  .alert { padding: 12px 16px; border-radius: 8px; font-size: 14px; margin-bottom: 16px; }
  .alert-danger { background: #fef2f2; border: 2px solid #fecaca; color: #dc2626; }
  .alert-success { background: #f0fdf4; border: 2px solid #bbf7d0; color: #16a34a; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 10px 16px; background: #1e3a5f; color: #fff; font-size: 13px; }
  td { padding: 10px 16px; border-bottom: 1px solid #e2e8f0; font-size: 14px; }
  tr:nth-child(even) { background: #f1f5f9; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 700; }
  .badge-green { background: #dcfce7; color: #16a34a; }
  .badge-red { background: #fee2e2; color: #dc2626; }
</style>
"""

@app.route('/partner/', methods=['GET', 'POST'])
def partner_login():
    error = ''
    if request.method == 'POST':
        dealer_code = request.form.get('dealer_code', '')
        contract_number = request.form.get('contract_number', '')
        import re
        if not re.match(r'^DLR-\d{4}$', dealer_code):
            error = '代理店コードの形式が正しくありません（DLR-XXXX 形式で入力してください）'
        elif not contract_number.isdigit() or int(contract_number) < 1000 or int(contract_number) > 9999:
            error = '契約番号は1000〜9999の範囲で入力してください'
        else:
            resp = redirect('/partner/dashboard/')
            resp.set_cookie('partner_session', f'{dealer_code}:{contract_number}', path='/partner/')
            return resp

    return f'''<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>パートナーポータル - IoT Portal</title>
{PARTNER_PAGE_STYLE}
</head><body>
<div class="partner-header"><h1>🤝 パートナーポータル</h1><p>代理店様向け管理画面</p></div>
<div class="container">
  <div class="card">
    <h2 style="margin:0 0 8px;color:#1e3a5f">パートナーログイン</h2>
    <p style="color:#64748b;font-size:14px;margin:0 0 24px">代理店契約情報を入力してアクセスしてください</p>
    {'<div class="alert alert-danger">'+error+'</div>' if error else ''}
    <form method="POST" action="/partner/">
      <div class="form-group">
        <label>代理店コード <span style="color:#dc2626">*</span></label>
        <input type="text" name="dealer_code" placeholder="DLR-0001" required>
        <p class="hint">契約時に発行された代理店コード（DLR-XXXX 形式）</p>
      </div>
      <div class="form-group">
        <label>契約番号 <span style="color:#dc2626">*</span></label>
        <input type="text" name="contract_number" placeholder="1000" required>
        <p class="hint">1000〜9999の範囲で入力してください</p>
      </div>
      <button type="submit" class="btn btn-primary">ログイン</button>
    </form>
  </div>
</div>
</body></html>''', 200, {'Content-Type': 'text/html; charset=utf-8'}


@app.route('/partner/dashboard/')
def partner_dashboard():
    session = request.cookies.get('partner_session', '')
    if not session or ':' not in session:
        return redirect('/partner/')
    dealer_code, contract_number = session.split(':', 1)
    conn = get_db()
    devices = conn.execute("SELECT * FROM devices").fetchall()
    conn.close()
    device_rows = ''
    for d in devices:
        status_class = 'badge-green' if d['status'] == 'online' else 'badge-red'
        device_rows += f'<tr><td>{d["id"]}</td><td><strong>{d["name"]}</strong></td><td>{d["location"]}</td><td><span class="badge {status_class}">{d["status"]}</span></td><td style="font-family:monospace">{d["ip_address"]}</td></tr>'

    return f'''<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>パートナーダッシュボード - IoT Portal</title>
{PARTNER_PAGE_STYLE}
</head><body>
<div class="partner-header">
  <h1>🤝 パートナーダッシュボード</h1>
  <p>代理店コード: {dealer_code} ／ 契約番号: {contract_number}</p>
</div>
<div class="container">
  <div class="card">
    <h2 style="margin:0 0 16px;color:#1e3a5f">契約情報</h2>
    <table>
      <tr><th style="width:200px">代理店コード</th><td>{dealer_code}</td></tr>
      <tr><th>契約番号</th><td>{contract_number}</td></tr>
      <tr><th>契約プラン</th><td>エンタープライズ（100台）</td></tr>
      <tr><th>契約期間</th><td>2025/04/01 〜 2026/03/31</td></tr>
    </table>
  </div>
  <div class="card">
    <h2 style="margin:0 0 16px;color:#1e3a5f">管理デバイス一覧</h2>
    <table>
      <tr><th>ID</th><th>名称</th><th>設置場所</th><th>ステータス</th><th>IP</th></tr>
      {device_rows}
    </table>
  </div>
</div>
</body></html>''', 200, {'Content-Type': 'text/html; charset=utf-8'}


# ─────────── 起動 ───────────
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
