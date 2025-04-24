import bcrypt
import re

def hash_password(password):
    """비밀번호를 안전하게 해싱"""
    # 문자열을 바이트로 인코딩
    password_bytes = password.encode('utf-8')
    # 솔트 생성 및 해싱
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    # 바이트를 문자열로 디코딩하여 저장
    return hashed.decode('utf-8')

def verify_password(stored_hash, provided_password):
    """저장된 해시와 제공된 비밀번호 비교"""
    # 문자열을 바이트로 인코딩
    stored_hash_bytes = stored_hash.encode('utf-8')
    provided_password_bytes = provided_password.encode('utf-8')
    # 해시 검증
    return bcrypt.checkpw(provided_password_bytes, stored_hash_bytes)

def validate_password_strength(password):
    """
    비밀번호 강도 검증 함수
    최소 8자 이상, 대소문자, 숫자, 특수문자 포함 여부 확인
    """
    if len(password) < 8:
        return False, "비밀번호는 최소 8자 이상이어야 합니다."
        
    # 대문자 포함 여부 확인
    if not re.search(r'[A-Z]', password):
        return False, "비밀번호에는 최소 하나의 대문자가 포함되어야 합니다."
        
    # 소문자 포함 여부 확인
    if not re.search(r'[a-z]', password):
        return False, "비밀번호에는 최소 하나의 소문자가 포함되어야 합니다."
        
    # 숫자 포함 여부 확인
    if not re.search(r'[0-9]', password):
        return False, "비밀번호에는 최소 하나의 숫자가 포함되어야 합니다."
        
    # 특수문자 포함 여부 확인
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "비밀번호에는 최소 하나의 특수문자가 포함되어야 합니다."
        
    return True, "비밀번호가 유효합니다."

def sanitize_input(input_text):
    """
    XSS 방지를 위한 입력 데이터 살균
    """
    if input_text is None:
        return ""
    
    # HTML 태그 및 위험한 문자 이스케이프 처리
    result = input_text.replace('<', '&lt;').replace('>', '&gt;')
    result = result.replace('"', '&quot;').replace("'", '&#x27;')
    
    return result 