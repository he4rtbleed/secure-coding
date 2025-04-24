import os
import sys
import sqlite3
import uuid

# 현재 디렉토리에서 상위 디렉토리를 추가하여 utils 패키지를 임포트할 수 있도록 설정
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.security import hash_password

def create_admin_user(username, password):
    """
    관리자 계정 생성
    """
    # 데이터베이스 경로 (절대 경로로 변경)
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'market.db')
    
    # 데이터베이스 연결
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 테이블 존재 여부 확인 및 생성
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
    if not cursor.fetchone():
        print("사용자 테이블이 존재하지 않습니다. 테이블을 생성합니다.")
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
        conn.commit()
    
    # 사용자 존재 여부 확인
    cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        if existing_user['role'] == 'admin':
            print(f"이미 '{username}' 계정은 관리자 권한을 가지고 있습니다.")
            conn.close()
            return
        
        # 일반 사용자 계정을 관리자로 업그레이드
        cursor.execute("UPDATE user SET role = 'admin' WHERE username = ?", (username,))
        conn.commit()
        print(f"사용자 '{username}'의 권한이 관리자로 업그레이드되었습니다.")
    else:
        # 새 관리자 계정 생성
        user_id = str(uuid.uuid4())
        hashed_password = hash_password(password)
        
        cursor.execute("""
            INSERT INTO user (id, username, password, role, status) 
            VALUES (?, ?, ?, 'admin', 'active')
        """, (user_id, username, hashed_password))
        
        conn.commit()
        print(f"새 관리자 계정 '{username}'이 생성되었습니다.")
    
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("사용법: python create_admin.py <username> <password>")
        sys.exit(1)
    
    username = sys.argv[1]
    password = sys.argv[2]
    
    create_admin_user(username, password) 