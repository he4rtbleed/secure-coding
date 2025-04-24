import os
from app import app, socketio

"""
이 파일은 애플리케이션의 메인 실행 파일입니다.
개발 또는 운영 환경에 따라 적절한 설정으로 애플리케이션을 실행합니다.

실행 방법:
- 개발 환경: python run.py
- 운영 환경: FLASK_ENV=production python run.py

HTTPS 설정:
- 개발 환경: 자체 서명 인증서 사용
- 운영 환경: 실제 인증서 사용 (인증서 경로 환경변수로 설정 가능)
  SSL_CERT_PATH: 인증서 경로
  SSL_KEY_PATH: 키 파일 경로
"""

if __name__ == '__main__':
    # 환경 변수 설정 (운영 환경: production, 개발 환경: development)
    os.environ['FLASK_ENV'] = os.environ.get('FLASK_ENV', 'development')
    
    # 포트 설정 (기본값: 5001)
    port = int(os.environ.get('PORT', 5001))
    
    # 개발 환경에서는 디버그 모드 활성화와 함께 'adhoc' SSL 사용 (self-signed certificate)
    if os.environ.get('FLASK_ENV') == 'development':
        print(f"개발 환경에서 HTTPS로 서버를 시작합니다. (자체 서명 인증서 사용, 포트: {port})")
        socketio.run(app, host='0.0.0.0', port=port, debug=True, ssl_context='adhoc')
    else:
        # 운영 환경에서는 실제 인증서 사용
        # 인증서 경로 설정 (운영 서버에서 설정 필요)
        cert_path = os.environ.get('SSL_CERT_PATH', 'cert.pem')
        key_path = os.environ.get('SSL_KEY_PATH', 'key.pem')
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            print(f"운영 환경에서 HTTPS로 서버를 시작합니다. 인증서: {cert_path}, 키: {key_path}, 포트: {port}")
            socketio.run(app, host='0.0.0.0', port=port, debug=False, ssl_context=(cert_path, key_path))
        else:
            print(f"경고: SSL 인증서를 찾을 수 없어 adhoc 인증서를 사용합니다. 포트: {port}")
            socketio.run(app, host='0.0.0.0', port=port, debug=False, ssl_context='adhoc') 