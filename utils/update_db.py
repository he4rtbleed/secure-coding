import os
import sys
import sqlite3

# 현재 디렉토리에서 상위 디렉토리를 추가하여 utils 패키지를 임포트할 수 있도록 설정
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def update_database():
    """
    기존 데이터베이스의 테이블 스키마를 업데이트하는 함수
    - user 테이블에 role, status, balance 필드 추가
    - report 테이블에 status 필드 추가
    """
    # 데이터베이스 경로 (절대 경로로 변경)
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'market.db')
    
    # 데이터베이스 연결
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 1. 테이블 존재 여부 확인
    print("테이블 구조 확인 중...")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [table['name'] for table in cursor.fetchall()]
    
    if 'user' in tables:
        # 2. user 테이블 컬럼 확인
        cursor.execute("PRAGMA table_info(user)")
        columns = [column['name'] for column in cursor.fetchall()]
        
        # role 필드 추가 (없는 경우)
        if 'role' not in columns:
            print("user 테이블에 role 필드 추가...")
            cursor.execute("ALTER TABLE user ADD COLUMN role TEXT DEFAULT 'user'")
        
        # status 필드 추가 (없는 경우)
        if 'status' not in columns:
            print("user 테이블에 status 필드 추가...")
            cursor.execute("ALTER TABLE user ADD COLUMN status TEXT DEFAULT 'active'")
        
        # balance 필드 추가 (없는 경우)
        if 'balance' not in columns:
            print("user 테이블에 balance 필드 추가...")
            cursor.execute("ALTER TABLE user ADD COLUMN balance INTEGER DEFAULT 10000")
    
    if 'report' in tables:
        # 3. report 테이블 컬럼 확인
        cursor.execute("PRAGMA table_info(report)")
        columns = [column['name'] for column in cursor.fetchall()]
        
        # status 필드 추가 (없는 경우)
        if 'status' not in columns:
            print("report 테이블에 status 필드 추가...")
            cursor.execute("ALTER TABLE report ADD COLUMN status TEXT DEFAULT 'pending'")
    
    # 4. transaction 테이블 생성 (없는 경우)
    if 'transaction' not in tables:
        print("transaction 테이블 생성...")
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
        
    # 변경사항 커밋 및 연결 종료
    conn.commit()
    conn.close()
    
    print("데이터베이스 업데이트가 완료되었습니다.")

if __name__ == "__main__":
    update_database() 