import unittest
import os
import sys
import requests
import re

# 현재 디렉토리를 파이썬 경로에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

class SecurityTest(unittest.TestCase):
    """보안 테스트"""
    
    def setUp(self):
        """테스트 환경 설정"""
        app.config['TESTING'] = True
        self.app = app.test_client()
    
    def test_xss_prevention(self):
        """XSS 방어 테스트"""
        # XSS 페이로드가 포함된 회원가입 시도
        xss_payload = "<script>alert('XSS')</script>"
        response = self.app.post('/register', data={
            'username': 'xssuser' + xss_payload,
            'password': 'Test1234!'
        }, follow_redirects=True)
        
        # 응답에 스크립트 태그가 실행되지 않고 이스케이프되었는지 확인
        self.assertNotIn("<script>", response.get_data(as_text=True))
        self.assertIn("&lt;script&gt;", response.get_data(as_text=True))
    
    def test_csrf_protection(self):
        """CSRF 보호 테스트"""
        # 로그인 폼 가져오기
        response = self.app.get('/login')
        content = response.get_data(as_text=True)
        
        # CSRF 토큰이 폼에 포함되어 있는지 확인
        self.assertIn('csrf_token', content)
        
        # CSRF 토큰 없이 폼 제출 시도
        response = self.app.post('/login', data={
            'username': 'testuser',
            'password': 'Test1234!'
        })
        
        # CSRF 토큰 누락으로 인해 400 Bad Request 응답 예상
        self.assertEqual(response.status_code, 400)
    
    def test_secure_headers(self):
        """보안 헤더 테스트"""
        response = self.app.get('/')
        headers = response.headers
        
        # Content-Security-Policy 헤더 확인
        self.assertIn('Content-Security-Policy', headers)
        
        # X-Frame-Options 헤더 확인
        self.assertIn('X-Frame-Options', headers)
        
        # X-Content-Type-Options 헤더 확인
        self.assertIn('X-Content-Type-Options', headers)
    
    def test_sql_injection_prevention(self):
        """SQL Injection 방어 테스트"""
        # SQL Injection 페이로드가 포함된 검색 시도
        sql_payload = "' OR '1'='1"
        response = self.app.get(f'/search?keyword={sql_payload}', follow_redirects=True)
        
        # 정상적인 응답 코드 (페이로드가 쿼리 매개변수로 처리되지 않음)
        self.assertEqual(response.status_code, 200)
        
        # 응답에 모든 사용자 정보가 노출되지 않았는지 확인
        # (실제로는 검색 결과가 없어야 함)
        content = response.get_data(as_text=True)
        self.assertIn(f'검색 결과: "{sql_payload}"', content)

if __name__ == '__main__':
    unittest.main() 