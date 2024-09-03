# WasabiBucket
- CVE를 LLM으로 분석해보자!

## 개요
- 이 프로젝트는 CVE 데이터를 수집하고 분석하며, API를 통해 제공하는 Go 언어 기반의 애플리케이션입니다. 각 컴포넌트(collector, analyzer, server)는 독립적으로 실행될 수 있으며, 공통 기능은 internal/common 패키지에 구현되어 있습니다.

## 향후 계획
1. Analyzer 컴포넌트 구현: SQS에서 메시지를 수신하고 LLM을 활용하여 CVE 데이터 분석
2. Frontend 개발: Vue.js를 사용하여 사용자 인터페이스 구현
3. API 개발: AWS API Gateway와 Lambda를 활용한 백엔드 API 구현
4. 테스트 커버리지 확대: 단위 테스트 및 통합 테스트 추가
5. 문서화: API 문서 및 사용자 가이드 작성

## 작업 목록
### Project
- [x] 프로젝트 기본 구조 설정
- [x] 데이터베이스 구축 => AWS PostgreSQL
- [x] 환경 변수 관리 및 로깅 기능 

### Collector
- [x] NVD API를 통한 CVE 데이터 수집
- [x] CVE 데이터 저장 로직 최적화 (upsert 구현)
- [x] AWS SQS publish 구현 및 테스트 완료
- [x] 데이터 수집 - 메시지 발행 프로세스 통합

### Analyzer
- [ ] SQS polling 구현
- [ ] LLM을 활용한 분석 구현

### etc
- Frontend :  vuejs (구현 예정)
- API : API Gateway & Lambda (구현 예정)

## 최근 업데이트
- CVE 데이터 저장 로직 개선: 데이터베이스 레벨에서 upsert 로직을 구현하여 효율성과 정확성 향상
- AWS SQS 연동: 새로운 CVE 데이터 또는 업데이트된 CVE 데이터에 대한 메시지 발행 기능 구현

## 구조
```
/WasabiBucket/
├── cmd/
│   └── collector/
│       └── main.go
├── internal/
│   ├── collector/
│   │   ├── collector.go
│   │   ├── database.go
│   │   └── sqs.go
│   └── common/
│       ├── config.go
│       ├── database.go
│       └── logger.go
├── pkg/
│   └── models/
│       └── cve.go
├── .env
├── .gitignore
├── go.mod
├── go.sum
└── README.md
```

## 주요 컴포넌트 설명
1. cmd/: 실행 가능한 애플리케이션의 메인 패키지들을 포함합니다.
   - collector/main.go: CVE 데이터 수집 프로세스의 진입점
2. internal/: 프로젝트 내부에서만 사용되는 패키지들을 포함합니다.
   - collector/: CVE 데이터 수집 및 저장 관련 로직
   - common/: 공통으로 사용되는 유틸리티 함수들
3. pkg/: 외부에서도 사용할 수 있는 패키지를 포함합니다.
   - models/cve.go: CVE 데이터 구조체 정의
4. .env: 환경 변수 설정 파일
5. README.md: 프로젝트 설명 및 사용 방법
