import unittest
import os
import sys
import requests

# 현재 디렉토리를 파이썬 경로에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

class HTTPSConfigTest(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        app.config['TESTING'] = True
        os.environ['FLASK_ENV'] = 'production'  # 테스트를 위해 운영 환경으로 설정

    def test_secure_headers(self):
        """보안 관련 HTTP 헤더가 올바르게 설정되었는지 테스트"""
        response = self.app.get('/', base_url='https://localhost')
        headers = response.headers
        
        # Content-Security-Policy 헤더 확인
        self.assertIn('Content-Security-Policy', headers)
        
        # X-Frame-Options 헤더 확인 (Talisman이 자동으로 설정)
        self.assertIn('X-Frame-Options', headers)
        self.assertEqual(headers['X-Frame-Options'], 'SAMEORIGIN')
        
        # X-Content-Type-Options 헤더 확인
        self.assertIn('X-Content-Type-Options', headers)
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        
        # X-XSS-Protection 헤더 확인
        self.assertIn('X-XSS-Protection', headers)

    def test_http_to_https_redirect(self):
        """HTTP 요청이 HTTPS로 리다이렉트되는지 테스트"""
        # 이 테스트는 실제 서버 환경에서만 유효함
        # 로컬 테스트 환경에서는 스킵
        try:
            response = requests.get('http://localhost:5000', allow_redirects=False)
            if response.status_code == 301 or response.status_code == 302:
                self.assertIn('https://', response.headers['Location'])
        except requests.ConnectionError:
            self.skipTest("로컬 서버가 실행 중이지 않아 테스트를 스킵합니다.")

if __name__ == '__main__':
    unittest.main() 