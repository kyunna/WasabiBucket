# WasabiBucket

CVE(Common Vulnerabilities and Exposures) 데이터를 LLM(Large Language Model)을 활용하여 분석

## 📁 프로젝트 구조
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
├── exploitdb/ # PoC 데이터 검색을 위한 서브모듈
├── scripts/ # 빌드 및 실행 스크립트
└── README.md
```

## ⚙️ 주요 구성 요소

### Backend
- **Collector**: NVD API에서 최신 CVE 데이터를 수집하여 DB 저장 및 SQS 전송
- **Analyzer**: SQS 메시지를 수신해 LLM 분석 및 PoC 정보 수집 후 DB에 저장

#### PoC 수집
- Analyzer에서 CVE 분석 시 관련 PoC 코드 검색
- 내부 로컬에 저장된 Exploit-db 검색
- Github에 공개된 PoC 검색

#### CWE 조회
- CVE 분석을 위한 CWE 관련 정보 조회
- DB에 저장된 데이터가 없을 경우 MITRE에서 CWE 정보 수집 및 요약(한/영)
- 한글은 프론트엔드 출력용, 영문은 프롬프트 및 RAG 구축용

#### 기타 수집 요소(구현검토)
- 기술 문서
- 블로그
- 뉴스
- 벤더 공지 등

### Frontend
- Vue.js 기반 UI로 CVE 및 분석 결과 조회 제공

### API
- AWS Lambda로 구현된 RESTful API
- AWS API Gateway를 통해 외부 서비스에 연결

### 데이터 저장소
- **PostgreSQL**: CVE, 분석 결과, PoC, 참조 링크 등 모든 구조화 데이터 저장
- **ExploitDB**: 외부 PoC 수집용 GitLab 서브모듈

### AWS stack
| 구성 요소 | 서비스 | 설명 |
|-----------|--------|------|
| **API 엔드포인트** | API Gateway + Lambda | REST API를 AWS Lambda 함수로 구현 |
| **메시지 브로커** | SQS (Simple Queue Service) | Collector → Analyzer 간 비동기 메시지 전달 |
| **데이터 수집 파이프라인** | Lambda + SQS + RDS | Collector가 CVE 수집 → SQS 전송 → Analyzer가 수신 및 분석 |
| **데이터베이스** | Amazon RDS (PostgreSQL) | 구조화된 CVE, 분석 결과, PoC 정보 저장소 |
| **프론트엔드** | S3 | CVE 검색 및 조회 제공 웹사이트 호스팅 |

