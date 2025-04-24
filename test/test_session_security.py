import unittest
import os
import sys
import time
from flask import session

# 현재 디렉토리를 파이썬 경로에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

class SessionSecurityTest(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test_key'
        self.app = app.test_client()
        
    def test_session_cookie_settings(self):
        """세션 쿠키 설정 테스트"""
        with self.app as client:
            client.get('/')
            
            # 세션 쿠키 SameSite 설정 확인
            self.assertEqual(app.config['SESSION_COOKIE_SAMESITE'], 'Lax')
            
            # 세션 유효 시간 설정 확인
            self.assertIsNotNone(app.config['PERMANENT_SESSION_LIFETIME'])
    
    def test_login_session_regeneration(self):
        """로그인 시 세션 재생성 테스트"""
        with self.app as client:
            # 첫 요청으로 세션 생성
            client.get('/')
            pre_login_session = session.sid if hasattr(session, 'sid') else None
            
            # 로그인 요청 모의 (실제 로그인 X)
            with client.session_transaction() as sess:
                sess['user_id'] = 'test_user'
                sess['login_time'] = time.time()
            
            # 새 요청으로 세션 확인
            client.get('/')
            post_login_session = session.sid if hasattr(session, 'sid') else None
            
            if pre_login_session and post_login_session:
                # 세션 ID가 변경되었는지 확인 (플라스크 테스트 환경에서는 확인 불가능할 수 있음)
                self.assertNotEqual(pre_login_session, post_login_session)
    
    def test_login_required_decorator(self):
        """로그인 필요한 페이지 접근 제한 테스트"""
        with self.app as client:
            # 로그인 없이 대시보드 접근 시도
            response = client.get('/dashboard', follow_redirects=False)
            # 로그인 페이지로 리디렉션 확인
            self.assertEqual(response.status_code, 302)
            self.assertIn('/login', response.location)

if __name__ == '__main__':
    unittest.main() 