# WasabiBucket
CVE를 LLM으로 분석해보자!

## 개요
이 프로젝트는 CVE 데이터를 수집하고 분석하며, API를 통해 제공하는 Go 언어 기반의 애플리케이션입니다. 각 컴포넌트(collector, analyzer, server)는 독립적으로 실행될 수 있으며, 공통 기능은 internal/common 패키지에 구현되어 있습니다.

##구조
/WasabiBucket/
├── cmd/
│   ├── collector/
│   │   └── main.go
│   ├── analyzer/
│   │   └── main.go
│   └── server/
│       └── main.go
├── internal/
│   ├── collector/
│   │   ├── nvd.go
│   │   └── database.go
│   ├── analyzer/
│   ├── server/
│   └── common/
│       ├── config.go
│       ├── database.go
│       └── logger.go
├── pkg/
│   └── models/
│       └── cve.go
├── frontend/
├── scripts/
│   └── build.sh
├── bin/
├── .env
├── .gitignore
├── go.mod
├── go.sum
├── README.md
└── Makefile

1. cmd/: 실행 가능한 애플리케이션의 메인 패키지들을 포함합니다.
- collector/main.go: CVE 데이터 수집 프로세스의 진입점
- analyzer/main.go: CVE 데이터 분석 프로세스의 진입점
- server/main.go: API 서버의 진입점
2. internal/: 프로젝트 내부에서만 사용되는 패키지들을 포함합니다.
- collector/: CVE 데이터 수집 관련 로직
- analyzer/: CVE 데이터 분석 관련 로직
- server/: API 서버 관련 로직
- common/: 공통으로 사용되는 유틸리티 함수들
3. pkg/: 외부에서도 사용할 수 있는 패키지를 포함합니다.
- models/cve.go: CVE 데이터 구조체 정의
4. frontend/: Vue.js 기반의 프론트엔드 코드 (아직 구현되지 않음)
5. bin/: 컴파일된 실행 파일들이 위치하는 디렉토리
6. scripts/: 빌드 및 배포 스크립트
7. .env: 환경 변수 설정 파일
8. Makefile: 프로젝트 빌드 및 관리를 위한 make 명령어들을 정의
9. README.md: 프로젝트 설명 및 사용 방법
