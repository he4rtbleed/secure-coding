import sqlite3
import uuid
import os
import secrets
from datetime import timedelta, datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
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
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
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
                reason TEXT NOT NULL
            )
        """)
        db.commit()

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
            # 세션 고정 공격 방지: 로그인 시 세션 ID 재생성
            session.clear()
            session['user_id'] = user['id']
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

# 로그인 상태 확인 데코레이터
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
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

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

# 앱 컨텍스트 내에서 테이블 생성
with app.app_context():
    init_db()
