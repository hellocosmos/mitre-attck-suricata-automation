# AI-based Suricata Workflow Automation with MITRE ATT&CK
## 1. Overview
This code implements a system that automatically converts techniques from the MITRE ATT&CK framework into rules for the Suricata intrusion detection system (IDS). The system performs the following main functions:
1. Extract network-related techniques from the MITRE ATT&CK database
2. Automatically generate Suricata rules for each technique
3. Validate the generated rules
4. Compile the results into a report
## 2. Main Classes and Functions
### 2.1 SuricataRule Class
- Represents the structure of a Suricata rule
- Consists of headers and options
### 2.2 SuricataRuleValidator Class
- Checks the validity of generated Suricata rules
- Validates rule syntax, required options, performance impact, etc.
### 2.3 SuricataSimulator Class
- Tests the actual operation of generated rules through simulation
- Creates virtual network packets to verify rule application results
### 2.4 MitreAttackSuricataSystem Class
- Core class of the entire system
- Manages all processes including MITRE ATT&CK database integration, OpenAI GPT model usage, Suricata rule generation and validation
## 3. Main Process Analysis
### 3.1 Database Initialization and Connection
- Uses SQLite database to store MITRE ATT&CK technique information and generated Suricata rules
### 3.2 Filtering Network-Related Techniques
- Extracts techniques containing network-related keywords from the MITRE ATT&CK database
### 3.3 Suricata Rule Generation
- Uses OpenAI's GPT-4o-mini model to automatically generate Suricata rules for each technique
- Generated rules undergo post-processing to refine format and content
### 3.4 Rule Validity Verification
1. Syntax validation using Suricata command-line tool
2. Flexible validation through SuricataRuleValidator
3. Operational simulation using SuricataSimulator
### 3.5 Result Report Generation
- Generate detailed reports for each technique
- Create a summary report for the entire process
## 4. Key Technologies and Libraries
- Python 3.x
- SQLite3: Local database management
- OpenAI API: Rule generation through GPT model
- Suricata: IDS rule validation
- Regular expressions (re module): String processing and pattern matching
- Logging (logging module): Debugging and process tracking
## 5. Code Quality and Improvement Areas
### 5.1 Strengths
- Well-modularized with clearly separated functions
- Detailed logging enables easy debugging and monitoring
- Multiple validation stages increase the reliability of generated rules
### 5.2 Areas for Improvement
- Error handling: Insufficient handling of some exception cases
- Configuration management: Hardcoded values should be separated into a configuration file
- Parallel processing: Consider parallel processing for performance improvement when handling large volumes of techniques
- Test code: Need to add unit tests and integration tests
## 6. Conclusion
This system effectively links the MITRE ATT&CK framework with Suricata IDS to automatically generate rules for responding to the latest cyber threats. Rule generation using the GPT model and multi-stage validation process ensure high-quality Suricata rules. However, performance verification in real environments and continuous updates are necessary.



---

# AI기반의 MITRE ATT&CK와 Suricat 보안룰셋 워크 플로우 자동화

## 1. 개요

이 코드는 MITRE ATT&CK 프레임워크의 기술들을 Suricata 침입 탐지 시스템(IDS)의 규칙으로 자동 변환하는 시스템을 구현하고 있습니다. 이 시스템은 다음과 같은 주요 기능을 수행합니다:

1. MITRE ATT&CK 데이터베이스에서 네트워크 관련 기술을 추출
2. 각 기술에 대한 Suricata 규칙을 자동 생성
3. 생성된 규칙의 유효성을 검증
4. 결과를 보고서로 정리

## 2. 주요 클래스 및 기능

### 2.1 SuricataRule 클래스
- Suricata 규칙의 구조를 표현
- 헤더와 옵션으로 구성

### 2.2 SuricataRuleValidator 클래스
- 생성된 Suricata 규칙의 유효성을 검사
- 규칙의 구문, 필수 옵션, 성능 영향 등을 검증

### 2.3 SuricataSimulator 클래스
- 생성된 규칙을 시뮬레이션하여 실제 동작을 테스트
- 가상의 네트워크 패킷을 생성하여 규칙 적용 결과를 확인

### 2.4 MitreAttackSuricataSystem 클래스
- 전체 시스템의 핵심 클래스
- MITRE ATT&CK 데이터베이스 연동, OpenAI GPT 모델 사용, Suricata 규칙 생성 및 검증 등 모든 프로세스를 관리

## 3. 주요 프로세스 분석

### 3.1 데이터베이스 초기화 및 연결
- SQLite 데이터베이스를 사용하여 MITRE ATT&CK 기술 정보와 생성된 Suricata 규칙을 저장

### 3.2 네트워크 관련 기술 필터링
- MITRE ATT&CK 데이터베이스에서 네트워크 관련 키워드를 포함하는 기술들을 추출

### 3.3 Suricata 규칙 생성
- OpenAI의 GPT-4o-mini 모델을 사용하여 각 기술에 대한 Suricata 규칙을 자동 생성
- 생성된 규칙은 후처리 과정을 거쳐 형식과 내용을 정제

### 3.4 규칙 유효성 검증
1. Suricata 명령줄 도구를 사용한 구문 검증
2. SuricataRuleValidator를 통한 유연한 검증
3. SuricataSimulator를 사용한 동작 시뮬레이션

### 3.5 결과 보고서 생성
- 각 기술별 상세 보고서 생성
- 전체 프로세스에 대한 요약 보고서 생성

## 4. 주요 기술 및 라이브러리

- Python 3.x
- SQLite3: 로컬 데이터베이스 관리
- OpenAI API: GPT 모델을 통한 규칙 생성
- Suricata: IDS 규칙 검증
- 정규표현식 (re 모듈): 문자열 처리 및 패턴 매칭
- 로깅 (logging 모듈): 디버깅 및 프로세스 추적

## 5. 코드 품질 및 개선 사항

### 5.1 장점
- 모듈화가 잘 되어 있어 각 기능이 명확히 분리됨
- 상세한 로깅을 통해 디버깅 및 모니터링이 용이
- 다양한 검증 단계를 통해 생성된 규칙의 신뢰성을 높임

### 5.2 개선 가능한 부분
- 에러 처리: 일부 예외 상황에 대한 처리가 부족함
- 설정 관리: 하드코딩된 값들을 설정 파일로 분리하면 좋을 것
- 병렬 처리: 대량의 기술 처리 시 성능 향상을 위해 병렬 처리 고려
- 테스트 코드: 단위 테스트 및 통합 테스트 추가 필요

## 6. 결론

이 시스템은 MITRE ATT&CK 프레임워크와 Suricata IDS를 효과적으로 연계하여 최신 사이버 위협에 대응할 수 있는 규칙을 자동으로 생성합니다. GPT 모델을 활용한 규칙 생성과 다단계 검증 프로세스는 높은 품질의 Suricata 규칙을 보장합니다. 그러나 실제 환경에서의 성능 검증과 지속적인 업데이트가 필요합니다.
