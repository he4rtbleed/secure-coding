import sqlite3
import uuid
import os
import secrets
from datetime import timedelta, datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, send
from flask_talisman import Talisman  # HTTPS 및 보안 헤더 설정을 위한 라이브러리 추가
from flask_wtf.csrf import CSRFProtect  # CSRF 보호 추가
import functools
from utils.security import hash_password, verify_password, validate_password_strength, sanitize_input

app = Flask(__name__)
# 안전한 랜덤 시크릿 키 생성 (하드코딩된 시크릿 키 대신)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
# 세션 쿠키 설정
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF 방지
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # 세션 유효 시간 설정

# CSRF 보호 활성화
csrf = CSRFProtect(app)

DATABASE = 'market.db'
# SocketIO 설정 업데이트 - 웹소켓 HTTPS 지원
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Talisman을 사용하여 HTTPS 적용 (개발 환경에서는 필요시 비활성화)
# 운영 환경에서는 force_https=True로 설정하여 HTTPS 강제 적용
if os.environ.get('FLASK_ENV') == 'production':
    talisman = Talisman(
        app,
        force_https=True,
        content_security_policy={
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline' cdnjs.cloudflare.com",
            'style-src': "'self' 'unsafe-inline' cdn.jsdelivr.net",
            'img-src': "'self' data:",
            'font-src': "'self' cdn.jsdelivr.net",
            'connect-src': "'self' wss: ws:",
        },
        content_security_policy_nonce_in=['script-src', 'style-src'],
        session_cookie_secure=True,
        session_cookie_http_only=True
    )
else:
    # 개발 환경에서는 HTTPS 강제 적용 비활성화하고 CSP를 더 유연하게 설정
    talisman = Talisman(
        app,
        force_https=False,
        content_security_policy={
            'default-src': ["'self'", '*'],
            'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", '*'],
            'style-src': ["'self'", "'unsafe-inline'", '*'],
            'img-src': ["'self'", 'data:', '*'],
            'font-src': ["'self'", '*'],
            'connect-src': ["'self'", 'ws:', 'wss:', '*'],
        },
        content_security_policy_nonce_in=['script-src', 'style-src'],
        session_cookie_http_only=True
    )

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # 테이블 존재 여부 확인
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
        tables_exists = cursor.fetchone()
        
        if not tables_exists:
            # 사용자 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    bio TEXT,
                    balance INTEGER DEFAULT 10000,
                    role TEXT DEFAULT 'user',
                    status TEXT DEFAULT 'active'
                )
            """)
            # 상품 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS product (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    price TEXT NOT NULL,
                    seller_id TEXT NOT NULL
                )
            """)
            # 신고 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS report (
                    id TEXT PRIMARY KEY,
                    reporter_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT DEFAULT 'pending'
                )
            """)
            # 송금 내역 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS 'transaction' (
                    id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    receiver_id TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'completed'
                )
            """)
            db.commit()
            print("데이터베이스 테이블이 성공적으로 생성되었습니다.")

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        password = request.form['password']
        
        # 비밀번호 강도 검증
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            flash(message)
            return redirect(url_for('register'))
        
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        
        # 비밀번호 해싱 및 사용자 생성
        hashed_password = hash_password(password)
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and verify_password(user['password'], password):
            # 계정 상태 확인 (status 필드가 있는 경우에만)
            try:
                if user['status'] != 'active':
                    flash('계정이 활성화되어 있지 않습니다. 관리자에게 문의하세요.')
                    return redirect(url_for('login'))
            except (IndexError, KeyError):
                # status 필드가 없는 경우
                pass
                
            # 세션 고정 공격 방지: 로그인 시 세션 ID 재생성
            session.clear()
            session['user_id'] = user['id']
            # 사용자 역할 저장 (role 필드가 있는 경우에만)
            try:
                session['user_role'] = user['role']
            except (IndexError, KeyError):
                session['user_role'] = 'user'
            # 세션에 로그인 시간 저장
            session['login_time'] = datetime.now().timestamp()
            session.permanent = True  # 세션 유지 시간 활성화
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    # 세션 완전히 제거
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 로그인 상태 및 활성 상태 확인 데코레이터
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        # 세션 타임아웃 확인 (30분 이상 활동이 없으면 세션 만료)
        if 'login_time' in session:
            login_time = session.get('login_time')
            # 세션 유효 시간 확인
            if datetime.now().timestamp() - login_time > 1800:  # 30분
                session.clear()
                flash('세션이 만료되었습니다. 다시 로그인해주세요.')
                return redirect(url_for('login'))
            # 활성 상태면 로그인 시간 갱신
            session['login_time'] = datetime.now().timestamp()
        
        # 사용자 상태 확인 (정지, 차단된 경우 접근 제한)
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user:
            # 사용자가 존재하지 않는 경우
            session.clear()
            flash('계정 정보를 찾을 수 없습니다. 다시 로그인해주세요.')
            return redirect(url_for('login'))
            
        try:
            if user['status'] != 'active':
                # 사용자가 활성 상태가 아닌 경우
                session.clear()
                flash(f'계정이 {user["status"]} 상태입니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))
        except (IndexError, KeyError):
            # status 필드가 없는 경우 (기본적으로 활성 상태로 간주)
            pass
            
        return view(**kwargs)
    return wrapped_view

# 관리자 권한 확인 데코레이터
def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
            
        # 사용자 정보 조회
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        # 관리자 권한 확인 (role 필드가 'admin'인지 확인)
        try:
            if not user or user['role'] != 'admin':
                abort(403)  # 접근 거부
        except (IndexError, KeyError):
            # role 필드가 없는 경우 (기본 사용자 권한)
            abort(403)  # 접근 거부
            
        return view(**kwargs)
    return wrapped_view

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    # URL에서 target_id 매개변수 가져오기
    target_id = request.args.get('target_id', '')
    
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = sanitize_input(request.form['reason'])
        
        # 입력값 검증
        if not target_id or not reason:
            flash('신고 대상과 사유를 모두 입력해주세요.')
            return redirect(url_for('report'))
            
        if len(reason) < 10:
            flash('신고 사유는 최소 10자 이상 입력해주세요.')
            return redirect(url_for('report'))
        
        db = get_db()
        cursor = db.cursor()
        
        # 대상 ID 유효성 검사 (사용자 또는, 상품 ID가 존재하는지 확인)
        cursor.execute("SELECT id FROM user WHERE id = ?", (target_id,))
        user_exists = cursor.fetchone()
        
        cursor.execute("SELECT id FROM product WHERE id = ?", (target_id,))
        product_exists = cursor.fetchone()
        
        if not user_exists and not product_exists:
            flash('존재하지 않는 대상입니다.')
            return redirect(url_for('report'))
            
        # 중복 신고 확인
        cursor.execute(
            "SELECT * FROM report WHERE reporter_id = ? AND target_id = ? AND status != 'rejected'", 
            (session['user_id'], target_id)
        )
        existing_report = cursor.fetchone()
        
        if existing_report:
            flash('이미 신고한 대상입니다. 처리 결과를 기다려주세요.')
            return redirect(url_for('dashboard'))
        
        # 자신을 신고하는 경우 방지
        if target_id == session['user_id']:
            flash('자신을 신고할 수 없습니다.')
            return redirect(url_for('report'))
        
        # 신고 처리
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    
    return render_template('report.html', target_id=target_id)

# 비밀번호 변경
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # 새 비밀번호와 확인 비밀번호 일치 여부 확인
        if new_password != confirm_password:
            flash('새 비밀번호와 확인 비밀번호가 일치하지 않습니다.')
            return redirect(url_for('change_password'))
        
        # 새 비밀번호 강도 검증
        is_valid, message = validate_password_strength(new_password)
        if not is_valid:
            flash(message)
            return redirect(url_for('change_password'))
        
        # 현재 사용자 정보 조회
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        # 현재 비밀번호 확인
        if not verify_password(user['password'], current_password):
            flash('현재 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('change_password'))
        
        # 비밀번호 해싱 및 업데이트
        hashed_password = hash_password(new_password)
        cursor.execute("UPDATE user SET password = ? WHERE id = ?", 
                       (hashed_password, session['user_id']))
        db.commit()
        
        flash('비밀번호가 성공적으로 변경되었습니다.')
        return redirect(url_for('profile'))
    
    return render_template('change_password.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    # 메시지 ID 생성
    data['message_id'] = str(uuid.uuid4())
    
    # XSS 방지를 위한 메시지 내용 살균
    data['message'] = sanitize_input(data.get('message', ''))
    
    # 유효성 검사: 필수 필드가 있는지 확인
    required_fields = ['user_id', 'username', 'message']
    if not all(field in data for field in required_fields):
        return
    
    # 빈 메시지 거부
    if not data['message'].strip():
        return
    
    try:
        # 메시지 저장 (데이터베이스에 저장)
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 메시지 저장
        cursor.execute(
            "INSERT INTO chat_messages (id, user_id, username, message) VALUES (?, ?, ?, ?)",
            (data['message_id'], data['user_id'], data['username'], data['message'])
        )
        db.commit()
    except Exception as e:
        print(f"메시지 저장 오류: {str(e)}")
    
    # 모든 클라이언트에게 메시지 브로드캐스트
    send(data, broadcast=True)

# 채팅 페이지
@app.route('/chat')
@login_required
def chat():
    # 사용자 이름 세션에 저장
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    if user:
        session['username'] = user['username']
    
    # 이전 채팅 메시지 로드(최근 50개)
    cursor.execute("""
        SELECT * FROM chat_messages 
        ORDER BY timestamp DESC 
        LIMIT 50
    """)
    messages = cursor.fetchall()
    messages = list(reversed(messages))  # 시간순으로 정렬
    
    return render_template('chat.html', messages=messages)

# 상품 검색
@app.route('/search', methods=['GET'])
def search():
    # 키워드 가져오기
    keyword = request.args.get('keyword', '')
    
    # 입력값 검증
    keyword = sanitize_input(keyword)
    
    db = get_db()
    cursor = db.cursor()
    
    # SQL 파라미터화 쿼리를 사용하여 SQL Injection 방지
    # LIKE 절에 사용될 검색어 준비 (부분 일치 검색)
    search_term = f"%{keyword}%"
    
    # 검색 쿼리 실행 (제목과 설명에서 검색)
    cursor.execute(
        "SELECT * FROM product WHERE title LIKE ? OR description LIKE ?",
        (search_term, search_term)
    )
    products = cursor.fetchall()
    
    return render_template('search_results.html', products=products, keyword=keyword)

# 송금 페이지
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    error = None
    success = None
    
    if request.method == 'POST':
        receiver_username = sanitize_input(request.form['receiver_username'])
        amount = request.form.get('amount', '0')
        
        # 입력값 검증
        try:
            amount = int(amount)
            if amount <= 0:
                error = "송금 금액은 양수여야 합니다."
        except ValueError:
            error = "송금 금액은 숫자여야 합니다."
            
        # 수신자 확인
        cursor.execute("SELECT * FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        
        if not receiver:
            error = "존재하지 않는 사용자입니다."
        elif receiver['id'] == current_user['id']:
            error = "자신에게 송금할 수 없습니다."
            
        # 잔액 확인
        if not error and amount > current_user['balance']:
            error = "잔액이 부족합니다."
            
        # 송금 처리
        if not error:
            try:
                # 트랜잭션 시작
                db.execute("BEGIN TRANSACTION")
                
                # 송금자 잔액 차감
                cursor.execute(
                    "UPDATE user SET balance = balance - ? WHERE id = ?",
                    (amount, current_user['id'])
                )
                
                # 수신자 잔액 증가
                cursor.execute(
                    "UPDATE user SET balance = balance + ? WHERE id = ?",
                    (amount, receiver['id'])
                )
                
                # 거래 내역 기록
                transaction_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO 'transaction' (id, sender_id, receiver_id, amount) VALUES (?, ?, ?, ?)",
                    (transaction_id, current_user['id'], receiver['id'], amount)
                )
                
                # 트랜잭션 커밋
                db.commit()
                success = f"{receiver_username}님에게 {amount}원을 성공적으로 송금했습니다."
                
                # 현재 사용자 정보 갱신
                cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
                current_user = cursor.fetchone()
                
            except Exception as e:
                # 오류 발생 시 롤백
                db.rollback()
                error = f"송금 처리 중 오류가 발생했습니다: {str(e)}"
    
    # 송금 내역 조회
    cursor.execute("""
        SELECT t.*, sender.username as sender_username, receiver.username as receiver_username
        FROM 'transaction' t
        JOIN user sender ON t.sender_id = sender.id
        JOIN user receiver ON t.receiver_id = receiver.id
        WHERE t.sender_id = ? OR t.receiver_id = ?
        ORDER BY t.timestamp DESC
        LIMIT 10
    """, (current_user['id'], current_user['id']))
    transactions = cursor.fetchall()
    
    return render_template('transfer.html', user=current_user, error=error, success=success, transactions=transactions)

# 관리자 대시보드
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor()
    
    # 요약 통계
    cursor.execute("SELECT COUNT(*) as total FROM user")
    user_count = cursor.fetchone()['total']
    
    cursor.execute("SELECT COUNT(*) as total FROM product")
    product_count = cursor.fetchone()['total']
    
    cursor.execute("SELECT COUNT(*) as total FROM report WHERE status IS NULL OR status = 'pending'")
    pending_reports = cursor.fetchone()['total']
    
    cursor.execute("SELECT COUNT(*) as total FROM 'transaction'")
    transaction_count = cursor.fetchone()['total']
    
    stats = {
        'user_count': user_count,
        'product_count': product_count,
        'pending_reports': pending_reports,
        'transaction_count': transaction_count
    }
    
    return render_template('admin/dashboard.html', stats=stats)

# 사용자 관리
@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    cursor = db.cursor()
    
    # 모든 사용자 목록 조회
    cursor.execute("SELECT * FROM user ORDER BY username")
    users = cursor.fetchall()
    
    return render_template('admin/users.html', users=users)

# 사용자 상태/역할 변경
@app.route('/admin/users/<user_id>/update', methods=['POST'])
@admin_required
def admin_update_user(user_id):
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_users'))
    
    status = request.form.get('status')
    role = request.form.get('role')
    
    # 유효한 상태와 역할만 허용
    valid_statuses = ['active', 'suspended', 'banned']
    valid_roles = ['user', 'admin']
    
    if status and status in valid_statuses:
        cursor.execute("UPDATE user SET status = ? WHERE id = ?", (status, user_id))
    
    if role and role in valid_roles:
        cursor.execute("UPDATE user SET role = ? WHERE id = ?", (role, user_id))
    
    db.commit()
    flash('사용자 정보가 업데이트되었습니다.')
    return redirect(url_for('admin_users'))

# 상품 관리
@app.route('/admin/products')
@admin_required
def admin_products():
    db = get_db()
    cursor = db.cursor()
    
    # 모든 상품 목록 조회 (판매자 정보 포함)
    cursor.execute("""
        SELECT p.*, u.username as seller_username
        FROM product p
        JOIN user u ON p.seller_id = u.id
        ORDER BY p.title
    """)
    products = cursor.fetchall()
    
    return render_template('admin/products.html', products=products)

# 상품 삭제
@app.route('/admin/products/<product_id>/delete', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 확인
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('admin_products'))
    
    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin_products'))

# 신고 관리
@app.route('/admin/reports')
@admin_required
def admin_reports():
    db = get_db()
    cursor = db.cursor()
    
    # 모든 신고 내역 조회 (신고자 정보 포함)
    cursor.execute("""
        SELECT r.*, reporter.username as reporter_username
        FROM report r
        JOIN user reporter ON r.reporter_id = reporter.id
        ORDER BY r.id DESC
    """)
    reports = cursor.fetchall()
    
    # 신고 대상 정보 추가
    reports_with_target = []
    for report in reports:
        # 사용자인지 확인
        cursor.execute("SELECT username FROM user WHERE id = ?", (report['target_id'],))
        user_target = cursor.fetchone()
        
        # 상품인지 확인
        cursor.execute("SELECT title FROM product WHERE id = ?", (report['target_id'],))
        product_target = cursor.fetchone()
        
        report_dict = dict(report)
        if user_target:
            report_dict['target_type'] = '사용자'
            report_dict['target_name'] = user_target['username']
        elif product_target:
            report_dict['target_type'] = '상품'
            report_dict['target_name'] = product_target['title']
        else:
            report_dict['target_type'] = '알 수 없음'
            report_dict['target_name'] = '삭제됨'
            
        reports_with_target.append(report_dict)
    
    return render_template('admin/reports.html', reports=reports_with_target)

# 신고 처리
@app.route('/admin/reports/<report_id>/update', methods=['POST'])
@admin_required
def admin_update_report(report_id):
    db = get_db()
    cursor = db.cursor()
    
    # 신고 내역 확인
    cursor.execute("SELECT * FROM report WHERE id = ?", (report_id,))
    report = cursor.fetchone()
    
    if not report:
        flash('신고 내역을 찾을 수 없습니다.')
        return redirect(url_for('admin_reports'))
    
    status = request.form.get('status')
    
    # 유효한 상태만 허용
    valid_statuses = ['pending', 'resolved', 'rejected']
    
    if status and status in valid_statuses:
        cursor.execute("UPDATE report SET status = ? WHERE id = ?", (status, report_id))
        db.commit()
        flash('신고 상태가 업데이트되었습니다.')
    
    return redirect(url_for('admin_reports'))

# 송금 내역 관리
@app.route('/admin/transactions')
@admin_required
def admin_transactions():
    db = get_db()
    cursor = db.cursor()
    
    # 모든 송금 내역 조회
    cursor.execute("""
        SELECT t.*, sender.username as sender_username, receiver.username as receiver_username
        FROM 'transaction' t
        JOIN user sender ON t.sender_id = sender.id
        JOIN user receiver ON t.receiver_id = receiver.id
        ORDER BY t.timestamp DESC
    """)
    transactions = cursor.fetchall()
    
    return render_template('admin/transactions.html', transactions=transactions)

# 앱 컨텍스트 내에서 테이블 생성
with app.app_context():
    init_db()

# 403 에러 처리 - 접근 거부
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# 404 에러 처리 - 페이지 찾을 수 없음
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

# 500 에러 처리 - 서버 에러
@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500
