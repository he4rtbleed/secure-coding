import unittest
import os
import sys
import tempfile
import shutil
from datetime import datetime

# 현재 디렉토리를 파이썬 경로에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, init_db
from utils.security import hash_password

class IntegrationTest(unittest.TestCase):
    """애플리케이션 통합 테스트"""
    
    def setUp(self):
        """테스트 환경 설정"""
        # 임시 데이터베이스 파일 생성
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.config['TESTING'] = True
        self.app = app.test_client()
        
        with app.app_context():
            init_db()
            
            # 테스트용 사용자 추가
            conn = app.extensions.get('get_db')()
            cursor = conn.cursor()
            
            # 일반 사용자
            user_id = '1234-test-user-id'
            cursor.execute(
                "INSERT INTO user (id, username, password, role, status) VALUES (?, ?, ?, ?, ?)",
                (user_id, 'testuser', hash_password('Test1234!'), 'user', 'active')
            )
            
            # 관리자 사용자
            admin_id = '1234-test-admin-id'
            cursor.execute(
                "INSERT INTO user (id, username, password, role, status) VALUES (?, ?, ?, ?, ?)",
                (admin_id, 'testadmin', hash_password('Admin1234!'), 'admin', 'active')
            )
            
            # 테스트용 상품 추가
            product_id = '1234-test-product-id'
            cursor.execute(
                "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
                (product_id, 'Test Product', 'Test Description', '10000', user_id)
            )
            
            conn.commit()
    
    def tearDown(self):
        """테스트 환경 정리"""
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])
    
    def test_index_page(self):
        """홈페이지 접속 테스트"""
        response = self.app.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
    def test_register_and_login(self):
        """회원가입 및 로그인 테스트"""
        # 회원가입
        response = self.app.post('/register', data={
            'username': 'newuser',
            'password': 'NewUser1234!'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('회원가입이 완료되었습니다', response.get_data(as_text=True))
        
        # 로그인
        response = self.app.post('/login', data={
            'username': 'newuser',
            'password': 'NewUser1234!'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('로그인 성공', response.get_data(as_text=True))
    
    def test_product_creation(self):
        """상품 등록 테스트"""
        # 먼저 로그인
        self.app.post('/login', data={
            'username': 'testuser',
            'password': 'Test1234!'
        })
        
        # 상품 등록
        response = self.app.post('/product/new', data={
            'title': 'New Product',
            'description': 'New Product Description',
            'price': '5000'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('상품이 등록되었습니다', response.get_data(as_text=True))
    
    def test_search_functionality(self):
        """검색 기능 테스트"""
        # 먼저 로그인
        self.app.post('/login', data={
            'username': 'testuser',
            'password': 'Test1234!'
        })
        
        # 검색 테스트
        response = self.app.get('/search?keyword=Test', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test Product', response.get_data(as_text=True))
        
        # 없는 상품 검색
        response = self.app.get('/search?keyword=NonExistentProduct', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('검색 결과가 없습니다', response.get_data(as_text=True))
    
    def test_transfer_functionality(self):
        """송금 기능 테스트"""
        # 먼저 로그인
        self.app.post('/login', data={
            'username': 'testuser',
            'password': 'Test1234!'
        })
        
        # 송금 테스트
        response = self.app.post('/transfer', data={
            'receiver_username': 'testadmin',
            'amount': '1000'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('성공적으로 송금', response.get_data(as_text=True))
    
    def test_admin_access(self):
        """관리자 접근 테스트"""
        # 일반 사용자로 로그인
        self.app.post('/login', data={
            'username': 'testuser',
            'password': 'Test1234!'
        })
        
        # 관리자 페이지 접근 시도 (실패 예상)
        response = self.app.get('/admin', follow_redirects=True)
        self.assertEqual(response.status_code, 403) # Forbidden
        
        # 로그아웃
        self.app.get('/logout')
        
        # 관리자로 로그인
        self.app.post('/login', data={
            'username': 'testadmin',
            'password': 'Admin1234!'
        })
        
        # 관리자 페이지 접근 시도 (성공 예상)
        response = self.app.get('/admin')
        self.assertEqual(response.status_code, 200)
        self.assertIn('관리자 대시보드', response.get_data(as_text=True))

if __name__ == '__main__':
    unittest.main() 