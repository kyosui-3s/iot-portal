import sqlite3
import os
import json
import subprocess
import urllib.request
from flask import Flask, request, redirect, Response, jsonify, send_from_directory

app = Flask(__name__, static_folder='static', static_url_path='')
DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'iot_portal.db'))

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
    c.execute('CREATE TABLE IF NOT EXISTS inquiries (id INTEGER PRIMARY KEY, name TEXT, email TEXT, company TEXT, message TEXT, created_at TEXT)')
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
    conn.commit()
    conn.close()

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
    #   - Content-Security-Policy なし
    #   - Strict-Transport-Security なし
    #   - X-Frame-Options なし → クリックジャッキング
    #   - X-Content-Type-Options なし
    return response

# ─────────── SPA: 全てのフロントエンドルーティングを index.html に ───────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/dashboard')
@app.route('/devices')
@app.route('/device')
@app.route('/contact')
def spa_pages():
    return send_from_directory('static', 'index.html')

# ─────────── sitemap / robots ───────────
@app.route('/sitemap.xml')
def sitemap():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://sub.3sec-demo.com/</loc></url>
  <url><loc>http://sub.3sec-demo.com/graphql</loc></url>
  <url><loc>http://sub.3sec-demo.com/devices/search</loc></url>
  <url><loc>http://sub.3sec-demo.com/tools/ping</loc></url>
  <url><loc>http://sub.3sec-demo.com/tools/fetch</loc></url>
  <url><loc>http://sub.3sec-demo.com/download</loc></url>
  <url><loc>http://sub.3sec-demo.com/redirect?url=/</loc></url>
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
        # VULN: エラーメッセージに SQL 文とスタックトレース漏洩
        return jsonify({'success': False, 'error': str(e), 'sql': sql}), 500

# ─────────── GraphQL API ───────────
GRAPHQL_SCHEMA = """
type Device {
  id: Int
  name: String
  type: String
  location: String
  status: String
  ip_address: String
  firmware: String
}

type User {
  id: Int
  email: String
  role: String
}

type Inquiry {
  id: Int
  name: String
  email: String
  message: String
}

type PingResult {
  host: String
  output: String
}

type FetchResult {
  url: String
  status: Int
  body: String
}

type Query {
  devices(search: String): [Device]
  device(id: Int!): Device
  users: [User]
  ping(host: String!): PingResult
  fetch_url(url: String!): FetchResult
}

type Mutation {
  submitInquiry(name: String!, email: String!, company: String, message: String!): Inquiry
}
"""

def resolve_graphql(query, variables=None):
    """簡易GraphQLリゾルバー"""
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

    # devices query
    if 'devices' in q and 'device(' not in q:
        search = variables.get('search', '')
        # searchパラメータが query 文字列内にある場合も取得
        import re
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
        import re
        m = re.search(r'id\s*:\s*(\d+)', q)
        did = int(m.group(1)) if m else variables.get('id', 1)
        conn = get_db()
        row = conn.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
        conn.close()
        return {'data': {'device': dict(row) if row else None}}

    # ping - VULN: OS コマンドインジェクション
    if 'ping' in q:
        import re
        m = re.search(r'host\s*:\s*"([^"]*)"', q)
        host = m.group(1) if m else variables.get('host', '127.0.0.1')
        # VULN: ユーザー入力を直接シェルコマンドに渡す
        output = subprocess.getoutput(f'ping -c 1 -W 2 {host} 2>&1')
        return {'data': {'ping': {'host': host, 'output': output}}}

    # fetch_url - VULN: SSRF（サーバーサイドリクエストフォージェリ）
    if 'fetch_url' in q:
        import re
        m = re.search(r'url\s*:\s*"([^"]*)"', q)
        url = m.group(1) if m else variables.get('url', '')
        try:
            # VULN: 任意の URL にサーバーからリクエスト（内部ネットワークアクセス可能）
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
        import re
        name = re.search(r'name\s*:\s*"([^"]*)"', q)
        email = re.search(r'email\s*:\s*"([^"]*)"', q)
        message = re.search(r'message\s*:\s*"([^"]*)"', q)
        n = name.group(1) if name else variables.get('name', '')
        e = email.group(1) if email else variables.get('email', '')
        msg = message.group(1) if message else variables.get('message', '')
        conn = get_db()
        conn.execute("INSERT INTO inquiries (name, email, message, created_at) VALUES (?, ?, ?, datetime('now'))", (n, e, msg))
        conn.commit()
        conn.close()
        return {'data': {'submitInquiry': {'name': n, 'email': e, 'message': msg}}}

    return {'errors': [{'message': 'Unknown query'}]}

@app.route('/graphql', methods=['GET', 'POST', 'OPTIONS'])
def graphql_endpoint():
    if request.method == 'OPTIONS':
        return '', 204

    # GET: GraphQL Playground / IDE 用
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

# ─────────── REST: お問い合わせ（オープンリダイレクト） ───────────
@app.route('/api/inquiry', methods=['POST', 'OPTIONS'])
def api_inquiry():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json(force=True, silent=True) or {}
    conn = get_db()
    conn.execute("INSERT INTO inquiries (name, email, company, message, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                 (data.get('name',''), data.get('email',''), data.get('company',''), data.get('message','')))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'お問い合わせを受け付けました'})

# ─────────── REST API: デバイス詳細（手動巡回用・Critical脆弱性） ───────────
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

# ─────────── サーバーレンダリングページ（DASTが検出しやすい形式） ───────────

# VULN: 反射型XSS + SQLi - GETパラメータをHTMLにそのまま埋め込み
@app.route('/devices/search')
def devices_search_page():
    q = request.args.get('q', '')
    result_html = ''
    if q:
        sql = "SELECT * FROM devices WHERE name LIKE '%" + q + "%' OR location LIKE '%" + q + "%'"
        try:
            conn = get_db()
            rows = conn.execute(sql).fetchall()
            conn.close()
            result_html = '<h3>検索結果</h3><table class="table table-bordered"><tr><th>ID</th><th>名前</th><th>場所</th><th>ステータス</th><th>IP</th></tr>'
            for r in rows:
                result_html += f"<tr><td>{r['id']}</td><td>{r['name']}</td><td>{r['location']}</td><td>{r['status']}</td><td>{r['ip_address']}</td></tr>"
            result_html += '</table>'
        except Exception as e:
            result_html = f'<div class="alert alert-danger"><strong>sqlite3.OperationalError:</strong> {str(e)}<br><code>SQL: {sql}</code></div>'
            return f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SQL Error - IoT Portal</title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
</head><body>
<div class="container" style="margin-top:20px">
<h2>データベースエラー</h2>
{result_html}
<p>入力値: {q}</p>
<a href="/devices/search">戻る</a>
</div></body></html>''', 500, {'Content-Type': 'text/html; charset=utf-8'}
    return f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>デバイス検索 - IoT Portal</title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
</head><body>
<div class="container" style="margin-top:20px">
<h2>デバイス検索</h2>
<form method="GET" action="/devices/search">
<div class="input-group"><input type="text" name="q" value="{q}" class="form-control" placeholder="デバイス名・設置場所で検索">
<span class="input-group-btn"><button class="btn btn-primary" type="submit">検索</button></span></div>
</form>
<p class="text-muted" style="margin-top:10px">検索キーワード: {q}</p>
{result_html}
<hr><p><a href="/">トップへ</a> | <a href="/devices/search">デバイス検索</a> | <a href="/tools/ping">ネットワーク診断</a> | <a href="/tools/fetch">FW更新チェック</a> | <a href="/download">ダウンロード</a></p>
</div></body></html>''', 200, {'Content-Type': 'text/html; charset=utf-8'}

# VULN: OSコマンドインジェクション - GETパラメータ経由
@app.route('/tools/ping')
def ping_page():
    host = request.args.get('host', '')
    result_html = ''
    if host:
        output = subprocess.getoutput(f'ping -c 2 -W 2 {host} 2>&1')
        result_html = f'<h3>結果</h3><pre>{output}</pre>'
    return f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ネットワーク診断 - IoT Portal</title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
</head><body>
<div class="container" style="margin-top:20px">
<h2>ネットワーク診断ツール</h2>
<form method="GET" action="/tools/ping">
<div class="input-group"><input type="text" name="host" value="{host}" class="form-control" placeholder="IPアドレスまたはホスト名">
<span class="input-group-btn"><button class="btn btn-primary" type="submit">Ping実行</button></span></div>
</form>
{result_html}
<hr><p><a href="/">トップへ</a> | <a href="/devices/search">デバイス検索</a> | <a href="/tools/ping">ネットワーク診断</a> | <a href="/tools/fetch">FW更新チェック</a> | <a href="/download">ダウンロード</a></p>
</div></body></html>''', 200, {'Content-Type': 'text/html; charset=utf-8'}

# VULN: SSRF - GETパラメータで任意URLにアクセス
@app.route('/tools/fetch')
def fetch_page():
    url = request.args.get('url', '')
    result_html = ''
    if url:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'IoT-Portal/1.0'})
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read(4096).decode('utf-8', errors='replace')
            import html as html_mod
            result_html = f'<h3>結果 (Status: {resp.status})</h3><pre>{html_mod.escape(body)}</pre>'
        except Exception as e:
            result_html = f'<div class="alert alert-danger">エラー: {str(e)}<br>URL: {url}</div>'
    return f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ファームウェア更新チェック - IoT Portal</title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
</head><body>
<div class="container" style="margin-top:20px">
<h2>ファームウェア更新チェック</h2>
<form method="GET" action="/tools/fetch">
<div class="input-group"><input type="text" name="url" value="{url}" class="form-control" placeholder="https://vendor.example.com/firmware/latest.json">
<span class="input-group-btn"><button class="btn btn-primary" type="submit">取得</button></span></div>
</form>
{result_html}
<hr><p><a href="/">トップへ</a> | <a href="/devices/search">デバイス検索</a> | <a href="/tools/ping">ネットワーク診断</a> | <a href="/tools/fetch">FW更新チェック</a> | <a href="/download">ダウンロード</a></p>
</div></body></html>''', 200, {'Content-Type': 'text/html; charset=utf-8'}

# VULN: パストラバーサル - ファイルダウンロード
@app.route('/download')
def download_file():
    filename = request.args.get('file', '')
    if not filename:
        return f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ダウンロード - IoT Portal</title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
</head><body>
<div class="container" style="margin-top:20px">
<h2>ファームウェアダウンロード</h2>
<ul><li><a href="/download?file=firmware_v2.1.3.bin">firmware_v2.1.3.bin</a></li>
<li><a href="/download?file=firmware_v2.0.1.bin">firmware_v2.0.1.bin</a></li></ul>
<hr><p><a href="/">トップへ</a> | <a href="/devices/search">デバイス検索</a> | <a href="/tools/ping">ネットワーク診断</a> | <a href="/tools/fetch">FW更新チェック</a> | <a href="/download">ダウンロード</a></p>
</div></body></html>''', 200, {'Content-Type': 'text/html; charset=utf-8'}
    filepath = os.path.join(os.path.dirname(__file__), 'firmware', filename)
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        return Response(content, mimetype='application/octet-stream', headers={'Content-Disposition': f'attachment; filename={filename}'})
    except Exception as e:
        return f'<html><body><h1>エラー</h1><pre>File: {filepath}\nError: {e}</pre></body></html>', 404, {'Content-Type': 'text/html'}

# VULN: オープンリダイレクト
@app.route('/redirect')
def open_redirect():
    url = request.args.get('url', '/')
    return redirect(url)

# ─────────── パートナーポータル（手動巡回デモ用） ───────────

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

        # バリデーション: 代理店コード DLR-XXXX 形式
        import re
        if not re.match(r'^DLR-\d{4}$', dealer_code):
            error = '代理店コードの形式が正しくありません（DLR-XXXX 形式で入力してください）'
        # バリデーション: 契約番号 1000〜9999 の範囲
        elif not contract_number.isdigit() or int(contract_number) < 1000 or int(contract_number) > 9999:
            error = '契約番号は1000〜9999の範囲で入力してください'
        else:
            # 通過 → セッションCookieを発行してダッシュボードへ
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
    # セッションチェック
    session = request.cookies.get('partner_session', '')
    if not session or ':' not in session:
        return redirect('/partner/')

    dealer_code, contract_number = session.split(':', 1)

    # デバイス取得
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

  <div class="card">
    <h2 style="margin:0 0 16px;color:#1e3a5f">デバイス検索</h2>
    <form method="GET" action="/partner/dashboard/">
      <div class="form-group">
        <label>デバイス名・設置場所で検索</label>
        <input type="text" name="q" placeholder="例: 温度センサー" value="{request.args.get('q', '')}">
      </div>
      <button type="submit" class="btn btn-primary">検索</button>
    </form>
  </div>
</div>
</body></html>''', 200, {'Content-Type': 'text/html; charset=utf-8'}


# ─────────── 起動 ───────────
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
