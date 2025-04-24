import unittest
import os
import sys

def run_all_tests():
    """
    test 디렉토리의 모든 테스트를 실행
    """
    # 테스트 디렉토리 확인 및 생성
    if not os.path.exists('test'):
        os.makedirs('test')
        print("테스트 디렉토리를 생성했습니다.")
        return
    
    # 테스트 디렉토리의 모든 테스트 파일 검색
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('test', pattern='test_*.py')
    
    # 테스트 실행
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)
    
    # 테스트 결과 반환
    return result.wasSuccessful()

if __name__ == "__main__":
    print("안전한 중고거래 시스템 테스트 시작...")
    
    # 테스트 디렉토리를 Python 경로에 추가
    sys.path.append(os.path.abspath('test'))
    
    # 모든 테스트 실행
    success = run_all_tests()
    
    if success:
        print("\n모든 테스트가 성공적으로 완료되었습니다.")
        sys.exit(0)
    else:
        print("\n일부 테스트가 실패했습니다.")
        sys.exit(1) 