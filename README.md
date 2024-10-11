# WasabiBucket

CVE(Common Vulnerabilities and Exposures) 데이터를 LLM(Large Language Model)을 활용하여 분석

## 프로젝트 구조
```
/WasabiBucket/
├── api/ # AWS Lambda 기반 API
│ ├── getCVEList/ # CVE 목록 조회 API
│ └── getCVEDetail/ # CVE 상세 정보 조회 API
├── frontend/ # Vue.js 기반 프론트엔드
├── backend/ # Go 애플리케이션
│ ├── cmd/
│ │ ├── collector/ # CVE 데이터 수집기
│ │ └── analyzer/ # CVE 데이터 분석기
│ └── internal/
│   ├── collector/ # 수집기 내부 로직
│   ├── analyzer/ # 분석기 내부 로직
│   ├── common/ # 공통 유틸리티
│   └── models/ # 데이터 모델
├── scripts/ # 빌드 및 실행 스크립트
├── docs/ # 프로젝트 문서
├── .github/workflows/ # CI/CD 설정
├── .gitignore
├── go.mod
├── go.sum
└── README.md
```

## 프로젝트 구성 및 설명

1. **API (backend)**
   - AWS Lambda 함수로 구현된 백엔드 API
   - CVE 데이터 조회 기능 제공

2. **Frontend**
   - Vue.js로 구현된 사용자 인터페이스
   - CVE 데이터 조회 및 분석 결과 표시

3. **Backend (Go Applications)**
   - Collector: NVD API에서 CVE 데이터를 수집하여 AWS SQS에 게시
   - Analyzer: SQS에서 메시지를 소비하고 LLM을 사용하여 CVE 데이터 분석

4. **Infrastructure**
   - AWS RDS: CVE 데이터 저장
   - AWS SQS: Collector와 Analyzer 간의 메시지 큐
   - AWS API Gateway: API 엔드포인트 제공
   - AWS Lambda: API 함수 실행
