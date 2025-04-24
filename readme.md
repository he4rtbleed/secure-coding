# Secure Coding

## Tiny Secondhand Shopping Platform.

You should add some functions and complete the security requirements.

## requirements

if you don't have a miniconda(or anaconda), you can install it on this url. - https://docs.anaconda.com/free/miniconda/index.html

## 사용 방법

### 환경 설정 및 패키지 설치
```
git clone https://github.com/ugonfor/secure-coding
conda env create -f enviroments.yaml
conda activate secure_coding
```

### 패키지 업데이트 (환경 구성 후 라이브러리 변경 시)
```
conda env update -f enviroments.yaml
```

### 서버 실행
```
python run.py
```

개발 환경에서는 자체 서명 인증서(self-signed certificate)를 사용하여 HTTPS로 실행됩니다.
기본 포트는 5001입니다 (https://localhost:5001).

다른 포트를 사용하려면 환경 변수를 설정하세요:
```
PORT=8000 python run.py  # 포트 8000으로 실행
```

### 운영 환경에서 실행
```
FLASK_ENV=production python run.py
```

운영 환경에서는 실제 인증서를 사용하는 것이 좋습니다. 다음과 같이 인증서 경로를 설정할 수 있습니다:
```
FLASK_ENV=production SSL_CERT_PATH=/경로/인증서.pem SSL_KEY_PATH=/경로/키.pem python run.py
```

### 외부 접근 허용 (개발 용도)
외부에서 접근 가능하도록 ngrok과 같은 도구를 활용할 수 있습니다:
```
# optional
sudo snap install ngrok
ngrok http https://localhost:5001
```

## 보안 설정

### HTTPS 설정
이 애플리케이션은 Flask-Talisman을 사용하여 HTTPS와 보안 헤더를 적용합니다. 

#### 개발 환경 실행
```
python run.py
```
개발 환경에서는 자체 서명된 인증서(self-signed certificate)를 사용하여 HTTPS를 테스트할 수 있습니다.

#### 운영 환경 실행
운영 환경에서는 다음과 같이 실행합니다:
```
export FLASK_ENV=production
export SSL_CERT_PATH=/경로/인증서.pem
export SSL_KEY_PATH=/경로/키.pem
python run.py
```

유효한 SSL 인증서가 필요합니다. Let's Encrypt와 같은 서비스를 통해 무료 인증서를 발급받을 수 있습니다.

### 보안 기능
- HTTPS 강제 적용
- Content Security Policy
- XSS 방지 헤더
- 클릭재킹 방지 (X-Frame-Options)
- MIME 스니핑 방지 (X-Content-Type-Options)
- 안전한 쿠키 설정 (HttpOnly, SameSite)
- 세션 타임아웃 및 자동 로그아웃

### 관리자 계정 생성
애플리케이션에 관리자 권한으로 접근하려면 다음 명령어를 사용하여 관리자 계정을 생성하세요:
```
python utils/create_admin.py admin Password123!
```
위 명령어는 'admin' 아이디와 'Password123!' 비밀번호를 가진 관리자 계정을 생성합니다.

### 제공되는 기능
- 회원 가입 및 로그인 (비밀번호 해싱, 안전한 세션 관리)
- 상품 등록, 조회, 검색
- 사용자 간 실시간 채팅
- 사용자 간 송금 기능
- 신고 기능
- 관리자 기능 (사용자, 상품, 신고, 거래 내역 관리)

### 보안 기능
- HTTPS 강제 적용
- Content Security Policy
- XSS 방지 헤더
- 클릭재킹 방지 (X-Frame-Options)
- MIME 스니핑 방지 (X-Content-Type-Options)
- 안전한 쿠키 설정 (HttpOnly, SameSite)
- 세션 타임아웃 및 자동 로그아웃
- CSRF 토큰 보호
- SQL Injection 방지
- 비밀번호 해싱
- 입력값 검증 및 살균

### 초기 실행 및 데이터베이스 설정
애플리케이션을 처음 실행하는 경우, 다음과 같이 데이터베이스를 초기화하고 관리자 계정을 생성합니다:

```
# 데이터베이스 스키마 업데이트
python utils/update_db.py

# 관리자 계정 생성
python utils/create_admin.py admin Password123!
```

업데이트된 애플리케이션을 기존 데이터베이스와 함께 사용하려면 먼저 `update_db.py` 스크립트를 실행하여 필요한 테이블과 컬럼이 추가되었는지 확인하세요.