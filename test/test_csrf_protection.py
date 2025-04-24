import unittest
import sys
import os
from bs4 import BeautifulSoup

# 현재 디렉토리를 파이썬 경로에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

class CSRFProtectionTest(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = True
        self.app = app.test_client()
    
    def test_csrf_token_in_forms(self):
        """모든 폼 페이지에 CSRF 토큰이 포함되어 있는지 테스트"""
        # 회원가입 페이지
        response = self.app.get('/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn('csrf_token', response.get_data(as_text=True))
        
        # 로그인 페이지
        response = self.app.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn('csrf_token', response.get_data(as_text=True))
        
        # 비밀번호 변경 페이지 - 로그인 필요
        with self.app as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 'test_user'  # 세션에 사용자 ID 추가
            
            response = client.get('/change_password')
            self.assertEqual(response.status_code, 200)
            self.assertIn('csrf_token', response.get_data(as_text=True))
    
    def test_form_submission_without_csrf_token(self):
        """CSRF 토큰 없이 폼 제출 시 거부되는지 테스트"""
        # CSRF 토큰 없이 회원가입 시도
        response = self.app.post('/register', data={
            'username': 'test_user',
            'password': 'Test1234!'
        })
        # CSRFError로 인해 400 Bad Request 응답 기대
        self.assertEqual(response.status_code, 400)
        
        # CSRF 토큰 없이 로그인 시도
        response = self.app.post('/login', data={
            'username': 'test_user',
            'password': 'Test1234!'
        })
        # CSRFError로 인해 400 Bad Request 응답 기대
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main() 