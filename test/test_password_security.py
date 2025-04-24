import unittest
import sys
import os

# 현재 디렉토리를 파이썬 경로에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.security import hash_password, verify_password, validate_password_strength, sanitize_input

class PasswordSecurityTest(unittest.TestCase):
    def test_password_hashing(self):
        """비밀번호 해싱 테스트"""
        password = "SecurePass123!"
        hashed = hash_password(password)
        
        # 해시된 비밀번호가 원본과 다른지 확인
        self.assertNotEqual(password, hashed)
        
        # 해시된 비밀번호 길이 확인 (bcrypt는 60자 문자열)
        self.assertGreater(len(hashed), 50)
        
        # 해시에 salt가 포함되어 있는지 확인
        self.assertTrue(hashed.startswith('$2b$'))
    
    def test_password_verification(self):
        """비밀번호 검증 테스트"""
        password = "SecurePass123!"
        hashed = hash_password(password)
        
        # 옳은 비밀번호가 검증을 통과하는지 확인
        self.assertTrue(verify_password(hashed, password))
        
        # 틀린 비밀번호가 검증을 통과하지 못하는지 확인
        self.assertFalse(verify_password(hashed, "WrongPassword123!"))
        self.assertFalse(verify_password(hashed, "securepass123!"))  # 대소문자 구분
    
    def test_password_strength(self):
        """비밀번호 강도 검증 테스트"""
        # 유효한 비밀번호
        valid, _ = validate_password_strength("SecurePass123!")
        self.assertTrue(valid)
        
        # 짧은 비밀번호
        valid, message = validate_password_strength("Short1!")
        self.assertFalse(valid)
        self.assertIn("8자 이상", message)
        
        # 대문자 없는 비밀번호
        valid, message = validate_password_strength("securepass123!")
        self.assertFalse(valid)
        self.assertIn("대문자", message)
        
        # 소문자 없는 비밀번호
        valid, message = validate_password_strength("SECUREPASS123!")
        self.assertFalse(valid)
        self.assertIn("소문자", message)
        
        # 숫자 없는 비밀번호
        valid, message = validate_password_strength("SecurePassword!")
        self.assertFalse(valid)
        self.assertIn("숫자", message)
        
        # 특수문자 없는 비밀번호
        valid, message = validate_password_strength("SecurePassword123")
        self.assertFalse(valid)
        self.assertIn("특수문자", message)
    
    def test_input_sanitization(self):
        """XSS 방지를 위한 입력 살균 테스트"""
        # HTML 태그 포함 입력
        input_with_tags = "<script>alert('XSS');</script>"
        sanitized = sanitize_input(input_with_tags)
        self.assertNotIn("<script>", sanitized)
        self.assertIn("&lt;script&gt;", sanitized)
        
        # 따옴표 포함 입력
        input_with_quotes = "Single ' and Double \" quotes"
        sanitized = sanitize_input(input_with_quotes)
        self.assertNotIn("'", sanitized)
        self.assertNotIn("\"", sanitized)

if __name__ == '__main__':
    unittest.main() 