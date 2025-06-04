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


## ✅ 개발 현황 및 향후 계획

### 🎯 목표
- CVE 관련 데이터를 구조화하여 수집 및 분석
- 이 데이터를 기반으로 RAG(Retrieval-Augmented Generation) 챗봇 시스템 구현

### 🧱 아키텍처 개요

1. **PostgreSQL**  
   - `cve_data`, `analysis_data`, `poc_info`, `poc_file` 등 중심 테이블
   - 향후 `reference_summary` 테이블 추가 예정 (링크 요약 저장용)

2. **LLM (GPT-4 기반)**  
   - CVE 요약, 기술 설명, 대응 방안 등 분석 자동화
   - 향후: PoC 코드 요약, 참조 링크 요약에도 적용 예정

3. **Vector DB (예정)**  
   - 구조화된 데이터를 자연어 문장으로 변환해 벡터 임베딩
   - 유사도 기반 검색으로 LLM 응답 품질 향상

4. **챗봇 (예정)**  
   - 사용자의 질문 + Vector DB 검색 결과 → GPT-4 프롬프트로 조합하여 응답 생성

---

### 🔧 현재 집중 과제

#### 1. PoC 코드 본문 수집 및 저장
- `poc_file` 테이블에 실제 코드 본문 또는 요약 저장 기능 설계
- 핵심 블록만 추출하거나 LLM을 활용한 요약도 고려

#### 2. Reference 링크 콘텐츠 요약
- CVE의 공식 reference 링크를 크롤링하여 콘텐츠 요약
- `reference_summary` 테이블 신설 예정

---

### 🔄 향후 계획

- 위 데이터를 기반으로 임베딩 파이프라인 구축
- Qdrant 또는 Weaviate 기반 Vector DB와 연동
- 자연어 질의 응답이 가능한 RAG 챗봇 MVP 완성