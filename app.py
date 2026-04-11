import sqlite3
import os
from flask import Flask, request, redirect, Response

app = Flask(__name__)
DB_PATH = '/opt/iot-portal/iot_portal.db'

# --------------- Database ---------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, role TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, name TEXT, location TEXT, status TEXT, ip_address TEXT, firmware_version TEXT)')
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users VALUES (1, 'admin@3sec-demo.com', 'Admin123!', 'admin')")
    c.execute("INSERT INTO users VALUES (2, 'user@3sec-demo.com', 'User123!', 'user')")
    c.execute("DELETE FROM devices")
    devices = [
        (1, '温度センサー A', '工場棟1F', 'online', '192.168.1.101', 'v2.1.3'),
        (2, '湿度センサー B', '工場棟2F', 'online', '192.168.1.102', 'v2.1.3'),
        (3, '圧力センサー C', '倉庫棟', 'warning', '192.168.1.103', 'v2.0.1'),
        (4, '振動センサー D', '工場棟1F', 'online', '192.168.1.104', 'v2.1.3'),
        (5, 'カメラ E', '正門', 'online', '192.168.1.105', 'v1.8.0'),
        (6, '温度センサー F', '研究棟', 'offline', '192.168.1.106', 'v2.0.1'),
        (7, '流量計 G', '工場棟1F', 'online', '192.168.1.107', 'v2.1.3'),
        (8, 'ガス検知器 H', '工場棟2F', 'warning', '192.168.1.108', 'v2.1.3'),
        (9, 'ドアセンサー I', 'サーバールーム', 'online', '192.168.1.109', 'v1.5.0'),
    ]
    c.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?)", devices)
    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()
else:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("SELECT ip_address FROM devices LIMIT 1")
        conn.close()
    except Exception:
        os.remove(DB_PATH)
        init_db()

# --------------- Navigation ---------------
NAV_HTML = """
<nav class="navbar navbar-default">
  <div class="container">
    <ul class="nav navbar-nav">
      <li><a href="/dashboard">ダッシュボード</a></li>
      <li><a href="/devices">デバイス管理</a></li>
      <li><a href="/devices?search=%E6%B8%A9%E5%BA%A6">デバイス検索</a></li>
      <li><a href="/devices/detail?id=1">デバイス詳細</a></li>
      <li><a href="/firmware">ファームウェア</a></li>
      <li><a href="/firmware/upload">FWアップロード</a></li>
      <li><a href="/download?file=firmware_v2.1.3.bin">FWダウンロード</a></li>
      <li><a href="/tools/ping">Pingツール</a></li>
      <li><a href="/tools/template-preview">テンプレート</a></li>
      <li><a href="/contact">お問い合わせ</a></li>
      <li><a href="/settings">設定</a></li>
      <li><a href="/admin/dashboard">管理パネル</a></li>
      <li><a href="/admin/users">ユーザー管理</a></li>
      <li><a href="/admin/logs">監査ログ</a></li>
      <li><a href="/admin/settings">システム設定</a></li>
      <li><a href="/files/">ファイル一覧</a></li>
    </ul>
  </div>
</nav>
"""

def render_page(title, body_content):
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title} - IoT Portal</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
    <script src="https://code.jquery.com/jquery-2.2.4.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
{NAV_HTML}
<div class="container">
{body_content}
</div>
</body>
</html>""", 200, {{'Content-Type': 'text/html; charset=utf-8'}}

# --------------- After Request Headers ---------------
@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Server'] = 'Apache/2.4.49 (Unix)'
    return response

# --------------- Auth-free pages ---------------

@app.route('/')
def index():
    return render_page("IoT Device Management Portal", """
    <h1>IoT Device Management Portal</h1>
    <p>Smart Factory向けIoTデバイス統合管理システム</p>
    <p><a href="/login" class="btn btn-primary">ログイン</a></p>
    <p><a href="/dashboard">ダッシュボードへ</a></p>
    """)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        sql = "SELECT * FROM users WHERE email='" + email + "' AND password='" + password + "'"
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(sql)
            user = cursor.fetchone()
            conn.close()
            if user:
                resp = redirect('/dashboard')
                resp.set_cookie('session_user', email, path='/', max_age=86400)
                resp.set_cookie('user_role', user['role'], path='/', max_age=86400)
                return resp
            else:
                return render_page("ログイン失敗", f"""
                <h1>ログインに失敗しました</h1>
                <p>メールアドレス: {email}</p>
                <p>実行SQL: {sql}</p>
                <form method="POST" action="/login">
                    <input type="text" name="email" class="form-control" value="">
                    <input type="password" name="password" class="form-control">
                    <button type="submit" class="btn btn-primary">再試行</button>
                </form>
                """)
        except Exception as e:
            return render_page("データベースエラー", f"""
            <h1>データベースエラー</h1>
            <div class="alert alert-danger">
                <p><strong>sqlite3.OperationalError</strong>: {str(e)}</p>
                <p>SQL: {sql}</p>
            </div>
            <p>入力値 email: {email}</p>
            <form method="POST" action="/login">
                <input type="text" name="email" class="form-control">
                <input type="password" name="password" class="form-control">
                <button type="submit" class="btn btn-primary">再試行</button>
            </form>
            """)
    return render_page("ログイン", """
    <h1>ログイン</h1>
    <form method="POST" action="/login">
        <div class="form-group">
            <label>メールアドレス</label>
            <input type="text" name="email" class="form-control" placeholder="admin@3sec-demo.com">
        </div>
        <div class="form-group">
            <label>パスワード</label>
            <input type="password" name="password" class="form-control">
        </div>
        <button type="submit" class="btn btn-primary">ログイン</button>
    </form>
    """)

@app.route('/sitemap.xml')
def sitemap():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://sub.3sec-demo.com/</loc></url>
  <url><loc>http://sub.3sec-demo.com/login</loc></url>
  <url><loc>http://sub.3sec-demo.com/dashboard</loc></url>
  <url><loc>http://sub.3sec-demo.com/devices</loc></url>
  <url><loc>http://sub.3sec-demo.com/devices?search=%E6%B8%A9%E5%BA%A6</loc></url>
  <url><loc>http://sub.3sec-demo.com/devices/detail?id=1</loc></url>
  <url><loc>http://sub.3sec-demo.com/firmware</loc></url>
  <url><loc>http://sub.3sec-demo.com/firmware/upload</loc></url>
  <url><loc>http://sub.3sec-demo.com/download?file=firmware_v2.1.3.bin</loc></url>
  <url><loc>http://sub.3sec-demo.com/tools/ping</loc></url>
  <url><loc>http://sub.3sec-demo.com/tools/template-preview</loc></url>
  <url><loc>http://sub.3sec-demo.com/contact</loc></url>
  <url><loc>http://sub.3sec-demo.com/settings</loc></url>
  <url><loc>http://sub.3sec-demo.com/admin/dashboard</loc></url>
  <url><loc>http://sub.3sec-demo.com/admin/users</loc></url>
  <url><loc>http://sub.3sec-demo.com/admin/logs</loc></url>
  <url><loc>http://sub.3sec-demo.com/admin/settings</loc></url>
  <url><loc>http://sub.3sec-demo.com/files/</loc></url>
</urlset>"""
    return Response(xml, mimetype='application/xml')

@app.route('/robots.txt')
def robots():
    return Response("User-agent: *\nAllow: /\nSitemap: http://sub.3sec-demo.com/sitemap.xml\n", mimetype='text/plain')

@app.route('/static/css/style.css')
def style_css():
    css = "body { padding-top: 10px; } .navbar { margin-bottom: 15px; } .container { max-width: 1200px; }"
    return Response(css, mimetype='text/css')

@app.route('/favicon.ico')
def favicon():
    return Response('', status=200)

@app.route('/admin/users')
def admin_users():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    db.close()
    rows = "".join(f"<tr><td>{u['id']}</td><td>{u['email']}</td><td>{u['role']}</td><td>{u['password']}</td></tr>" for u in users)
    return render_page("ユーザー管理", f"""
    <h1>ユーザー管理</h1>
    <table class="table table-bordered">
        <tr><th>ID</th><th>メール</th><th>ロール</th><th>パスワード</th></tr>
        {rows}
    </table>
    """)

@app.route('/api/debug/config')
def debug_config():
    import json
    config = {{"DB_PATH": "/opt/iot-portal/iot_portal.db", "SECRET_KEY": "super-secret-key-never-share", "API_KEY": "sk-demo-3shake-api-key-12345", "DEBUG": True, "INTERNAL_IP": "172.18.0.5"}}
    return f"""<html><body>{NAV_HTML}<h1>Debug Config</h1><pre>{json.dumps(config, indent=2)}</pre></body></html>""", 200, {{'Content-Type': 'text/html'}}

# --------------- Auth-required pages ---------------

@app.route('/dashboard')
def dashboard():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    return render_page("ダッシュボード", """
    <h1>ダッシュボード</h1>
    <div class="row">
        <div class="col-md-3"><div class="panel panel-info"><div class="panel-body"><h3>12</h3>登録デバイス</div></div></div>
        <div class="col-md-3"><div class="panel panel-success"><div class="panel-body"><h3>9</h3>オンライン</div></div></div>
        <div class="col-md-3"><div class="panel panel-warning"><div class="panel-body"><h3>2</h3>警告</div></div></div>
        <div class="col-md-3"><div class="panel panel-danger"><div class="panel-body"><h3>1</h3>オフライン</div></div></div>
    </div>
    <h3>最近のデバイス</h3>
    <ul>
        <li><a href="/devices/detail?id=1">温度センサー A</a></li>
        <li><a href="/devices/detail?id=2">湿度センサー B</a></li>
        <li><a href="/devices/detail?id=3">圧力センサー C</a></li>
    </ul>
    <h3>クイック検索</h3>
    <form method="GET" action="/devices">
        <input type="text" name="search" class="form-control" placeholder="デバイス名で検索">
        <button type="submit" class="btn btn-default">検索</button>
    </form>
    """)

@app.route('/devices')
def devices():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    search = request.args.get('search', '')
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if search:
            sql = "SELECT * FROM devices WHERE name LIKE '%" + search + "%' OR location LIKE '%" + search + "%'"
            cursor.execute(sql)
        else:
            sql = "SELECT * FROM devices"
            cursor.execute(sql)
        results = cursor.fetchall()
        rows_html = ""
        for r in results:
            rows_html += f"<tr><td>{r['id']}</td><td>{r['name']}</td><td>{r['location']}</td><td>{r['status']}</td><td>{r['ip_address']}</td><td>{r['firmware_version']}</td></tr>"
        conn.close()
        return render_page("デバイス管理", f"""
        <h1>デバイス管理</h1>
        <form method="GET" action="/devices">
            <input type="text" name="search" value="{search}" class="form-control" placeholder="検索...">
            <button type="submit" class="btn btn-default">検索</button>
        </form>
        <p>検索クエリ: {search}</p>
        <p>実行SQL: {sql}</p>
        <table class="table table-bordered">
            <tr><th>ID</th><th>デバイス名</th><th>設置場所</th><th>ステータス</th><th>IP</th><th>FW</th></tr>
            {rows_html}
        </table>
        """)
    except Exception as e:
        return render_page("SQLエラー", f"""
        <h1>データベースエラー</h1>
        <div class="alert alert-danger">
            <p><strong>sqlite3.OperationalError</strong>: {str(e)}</p>
            <p>SQL: {sql}</p>
        </div>
        <p>入力値: {search}</p>
        <a href="/devices">戻る</a>
        """)

@app.route('/devices/detail')
def device_detail():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    device_id = request.args.get('id', '1')
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        sql = "SELECT * FROM devices WHERE id=" + device_id
        cursor.execute(sql)
        device = cursor.fetchone()
        conn.close()
        if device:
            return render_page("デバイス詳細", f"""
            <h1>デバイス詳細</h1>
            <p>SQL: {sql}</p>
            <table class="table">
                <tr><th>ID</th><td>{device['id']}</td></tr>
                <tr><th>名前</th><td>{device['name']}</td></tr>
                <tr><th>場所</th><td>{device['location']}</td></tr>
                <tr><th>ステータス</th><td>{device['status']}</td></tr>
                <tr><th>IP</th><td>{device['ip_address']}</td></tr>
            </table>
            """)
        else:
            return render_page("デバイス詳細", f"<h1>デバイスが見つかりません</h1><p>SQL: {sql}</p>")
    except Exception as e:
        return render_page("SQLエラー", f"""
        <h1>データベースエラー</h1>
        <p><strong>sqlite3.OperationalError</strong>: {str(e)}</p>
        <p>SQL: {sql}</p>
        <p>入力値 id: {device_id}</p>
        """)

@app.route('/tools/ping', methods=['GET', 'POST'])
def ping_tool():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    result = ""
    if request.method == 'POST':
        host = request.form.get('host', '')
        output = os.popen(f'ping -c 2 {host} 2>&1').read()
        result = f"<h3>実行結果</h3><pre>{output}</pre>"
    return render_page("ネットワーク診断ツール", f"""
    <h1>ネットワーク診断ツール</h1>
    <form method="POST" action="/tools/ping">
        <div class="form-group">
            <label>ホスト名またはIPアドレス</label>
            <input type="text" name="host" class="form-control" value="192.168.1.1">
        </div>
        <button type="submit" class="btn btn-primary">Ping実行</button>
    </form>
    {result}
    """)

@app.route('/tools/template-preview', methods=['GET', 'POST'])
def template_preview():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    result = ""
    if request.method == 'POST':
        template_code = request.form.get('template', '')
        try:
            from jinja2 import Template
            rendered = Template(template_code).render(device_name="センサーA", temperature=25.3, status="online")
            result = f"<h3>プレビュー結果</h3><div class='well'>{rendered}</div>"
        except Exception as e:
            result = f"<h3>エラー</h3><pre>{e}</pre>"
    return render_page("テンプレートプレビュー", f"""
    <h1>通知テンプレートプレビュー</h1>
    <form method="POST" action="/tools/template-preview">
        <div class="form-group">
            <label>テンプレート</label>
            <textarea name="template" class="form-control" rows="6">{{{{device_name}}}}のステータスが{{{{status}}}}に変更されました。温度: {{{{temperature}}}}℃</textarea>
        </div>
        <button type="submit" class="btn btn-primary">プレビュー</button>
    </form>
    {result}
    """)

@app.route('/download')
def download():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    filename = request.args.get('file', '')
    if not filename:
        return render_page("ダウンロード", """
        <h1>ファームウェアダウンロード</h1>
        <ul>
            <li><a href="/download?file=firmware_v2.1.3.bin">firmware_v2.1.3.bin</a></li>
            <li><a href="/download?file=firmware_v2.0.1.bin">firmware_v2.0.1.bin</a></li>
        </ul>
        """)
    filepath = f'/opt/iot-portal/firmware/{filename}'
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        return render_page("ダウンロード", f"""
        <h1>ファイル: {filename}</h1>
        <pre>{content}</pre>
        """)
    except Exception as e:
        return render_page("エラー", f"""
        <h1>ダウンロードエラー</h1>
        <pre>File: {filepath}</pre>
        <pre>Error: {e}</pre>
        """)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    submitted = request.args.get('submitted', '')
    message = request.args.get('message', '')
    if submitted:
        return render_page("お問い合わせ完了", f"""
        <h1>お問い合わせを受け付けました</h1>
        <div class="alert alert-success"><p>{message}</p></div>
        <a href="/contact">新しいお問い合わせ</a>
        """)
    if request.method == 'POST':
        msg = request.form.get('message', '')
        name = request.form.get('name', '')
        return redirect(f'/contact?submitted=1&message=お問い合わせ「{name}」を受け付けました')
    return render_page("お問い合わせ", """
    <h1>お問い合わせ</h1>
    <form method="POST" action="/contact">
        <div class="form-group">
            <label>お名前</label>
            <input type="text" name="name" class="form-control" placeholder="山田太郎">
        </div>
        <div class="form-group">
            <label>メッセージ</label>
            <textarea name="message" class="form-control" rows="5"></textarea>
        </div>
        <button type="submit" class="btn btn-primary">送信</button>
    </form>
    """)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    updated = request.args.get('updated', '')
    if request.method == 'POST':
        company = request.form.get('company_name', '')
        email = request.form.get('notification_email', '')
        return redirect(f'/settings?updated=1&company={company}&email={email}')
    if updated:
        company = request.args.get('company', '')
        email_param = request.args.get('email', '')
        return render_page("設定", f"""
        <h1>設定</h1>
        <div class="alert alert-success">設定を更新しました: {company} / {email_param}</div>
        """)
    return render_page("設定", """
    <h1>システム設定</h1>
    <form method="POST" action="/settings">
        <div class="form-group"><label>会社名</label><input type="text" name="company_name" class="form-control" value="3-shake Inc."></div>
        <div class="form-group"><label>通知先メール</label><input type="email" name="notification_email" class="form-control" value="admin@3sec-demo.com"></div>
        <div class="form-group"><label>アラート閾値（℃）</label><input type="number" name="threshold" class="form-control" value="40"></div>
        <button type="submit" class="btn btn-primary">設定を保存</button>
    </form>
    <h3>パスワード変更</h3>
    <form method="POST" action="/api/change-password">
        <div class="form-group"><label>新しいパスワード</label><input type="password" name="new_password" class="form-control"></div>
        <button type="submit" class="btn btn-warning">パスワード変更</button>
    </form>
    """)

@app.route('/firmware')
def firmware():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    result = request.args.get('result', '')
    result_html = f'<div class="alert alert-info">結果: {result}</div>' if result else ""
    return render_page("ファームウェア管理", f"""
    <h1>ファームウェア管理</h1>
    {result_html}
    <h3>アップロード</h3>
    <form method="POST" action="/firmware/upload" enctype="multipart/form-data">
        <div class="form-group"><label>ファームウェアファイル</label><input type="file" name="firmware_file" class="form-control"></div>
        <div class="form-group"><label>バージョン</label><input type="text" name="version" class="form-control" placeholder="v2.1.4"></div>
        <button type="submit" class="btn btn-primary">アップロード</button>
    </form>
    <h3>ダウンロード</h3>
    <ul>
        <li><a href="/download?file=firmware_v2.1.3.bin">firmware_v2.1.3.bin (最新)</a></li>
        <li><a href="/download?file=firmware_v2.0.1.bin">firmware_v2.0.1.bin</a></li>
    </ul>
    """)

@app.route('/firmware/upload', methods=['GET', 'POST'])
def firmware_upload():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    if request.method == 'POST':
        filename = request.form.get('version', 'unknown')
        return redirect(f'/firmware?result=ファームウェアファイルをアップロードしました:+{filename}')
    return render_page("FWアップロード", """
    <h1>ファームウェアアップロード</h1>
    <form method="POST" action="/firmware/upload" enctype="multipart/form-data">
        <div class="form-group"><label>ファームウェアファイル</label><input type="file" name="firmware_file" class="form-control"></div>
        <div class="form-group"><label>バージョン</label><input type="text" name="version" class="form-control" placeholder="v2.1.4"></div>
        <button type="submit" class="btn btn-primary">アップロード</button>
    </form>
    """)

@app.route('/admin/dashboard')
def admin_dashboard():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    return render_page("管理パネル", """
    <h1>管理パネル</h1>
    <div class="row">
        <div class="col-md-4"><div class="panel panel-default"><div class="panel-heading">ユーザー数</div><div class="panel-body"><h2>24</h2></div></div></div>
        <div class="col-md-4"><div class="panel panel-default"><div class="panel-heading">アクティブセッション</div><div class="panel-body"><h2>8</h2></div></div></div>
        <div class="col-md-4"><div class="panel panel-default"><div class="panel-heading">今日のアラート</div><div class="panel-body"><h2>3</h2></div></div></div>
    </div>
    """)

@app.route('/admin/logs')
def admin_logs():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    return render_page("監査ログ", """
    <h1>監査ログ</h1>
    <table class="table table-bordered">
        <tr><th>日時</th><th>ユーザー</th><th>アクション</th><th>IP</th></tr>
        <tr><td>2026-02-28 10:15:00</td><td>admin@3sec-demo.com</td><td>ログイン成功</td><td>172.18.0.1</td></tr>
        <tr><td>2026-02-28 09:30:00</td><td>user@3sec-demo.com</td><td>デバイス追加</td><td>192.168.1.100</td></tr>
    </table>
    """)

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if not request.cookies.get('session_user'):
        return redirect('/login')
    if request.method == 'POST':
        return render_page("システム設定", '<h1>システム設定</h1><div class="alert alert-success">設定を更新しました</div>')
    return render_page("システム設定", """
    <h1>システム設定</h1>
    <form method="POST" action="/admin/settings">
        <div class="form-group"><label>セッションタイムアウト（分）</label><input type="number" name="session_timeout" class="form-control" value="30"></div>
        <div class="form-group"><label>最大ログイン試行回数</label><input type="number" name="max_login_attempts" class="form-control" value="5"></div>
        <button type="submit" class="btn btn-danger">設定を保存</button>
    </form>
    """)

@app.route('/api/change-password', methods=['POST'])
def change_password():
    new_password = request.form.get('new_password', '')
    return render_page("パスワード変更", f"""
    <h1>パスワードを変更しました</h1>
    <p>新しいパスワード: {new_password}</p>
    """)

# --------------- App entry ---------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
