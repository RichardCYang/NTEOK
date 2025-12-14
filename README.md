# NTEOK

셀프 호스팅 가능한 웹 기반 노트 애플리케이션

---

**한국어** | **[English](README.en.md)**

---

<img src="./example.png" width="100%" title="NTEOK_Screenshot"/>

## 개요

**NTEOK**는 한국어 넋(NEOK)과 노트(NOTE)의 합성어입니다. Node.js와 MySQL 기반의 다중 사용자 노트 웹 애플리케이션으로, 블록 기반 마크다운 편집과 End-to-End 암호화를 지원합니다.

### 주요 특징

- **마크다운 편집기**: Tiptap 기반 블록 에디터 (체크리스트 지원)
- **End-to-End 암호화**: AES-256-GCM 방식의 클라이언트 측 암호화
- **컬렉션 공유**: 사용자 간 협업 및 링크 공유
- **계층적 구조**: 페이지 부모-자식 관계 지원
- **2단계 인증**: TOTP 기반 보안 강화
- **HTTPS 자동 인증서**: Let's Encrypt + DuckDNS 연동
- **반응형 디자인**: 모바일, 태블릿, 데스크탑 최적화
- **셀프 호스팅**: 독립적인 서버 운영 가능

---

## 핵심 기능

### 사용자 관리
- 회원가입 및 로그인 시스템
- TOTP 2단계 인증 (Google Authenticator, Authy 등)
- 세션 기반 인증
- 계정 삭제 기능

### 노트 편집
- **블록 타입**: 문단, 제목(H1-H6), 목록(글머리/번호), 체크리스트, 인용구, 코드 블록, 구분선, LaTeX 수식
- **인라인 서식**: 굵게, 기울임, 취소선, 텍스트 색상
- **정렬 옵션**: 왼쪽, 가운데, 오른쪽, 양쪽
- **슬래시 명령**: `/` 입력으로 블록 타입 전환
- **단축키**: `Ctrl+S` / `Cmd+S` 저장

### 컬렉션 및 페이지
- 컬렉션별 페이지 그룹화
- 계층적 페이지 구조 (부모-자식 관계)
- 페이지 아이콘 설정 (170개 Font Awesome 아이콘, 400개 이모지)
- 최근 수정 시각 기준 자동 정렬
- 드래그 앤 드롭 정렬 (예정)

### 보안 기능
- **E2EE 암호화**: AES-256-GCM 방식
- **클라이언트 측 암호화**: 서버에 암호화된 데이터만 전송
- **TOTP 2FA**: 시간 기반 일회용 비밀번호
- **CSRF 보호**: SameSite 쿠키 설정
- **세션 관리**: 안전한 쿠키 기반 인증

### 협업 기능
- **사용자 공유**: 특정 사용자에게 컬렉션 공유
- **링크 공유**: 링크를 통한 컬렉션 접근
- **권한 관리**: READ, EDIT, OWNER 권한 레벨
- **암호화 페이지 공유**: 공유 허용 설정 옵션

---

## 기술 스택

### 백엔드
- **런타임**: Node.js 18+
- **프레임워크**: Express 5.x
- **데이터베이스**: MySQL 8.x
- **인증**: bcrypt (비밀번호 해싱), speakeasy (TOTP)
- **보안**: cookie-parser, CSRF 토큰, SameSite 쿠키
- **HTTPS**: acme-client (Let's Encrypt), dotenv (환경 변수)

### 프론트엔드
- **코어**: 바닐라 JavaScript (ES6+ 모듈)
- **에디터**: Tiptap v2 (StarterKit, TextAlign, Color, Mathematics)
- **수식 렌더링**: KaTeX
- **암호화**: Web Crypto API (AES-256-GCM)
- **아이콘**: Font Awesome 6
- **스타일**: 순수 CSS (반응형 디자인)

---

## 설치 및 실행

### 사전 요구사항

- Node.js 18 LTS 이상
- MySQL 8.x 서버
- npm 패키지 관리자

### 1. 데이터베이스 생성

```sql
CREATE DATABASE nteok
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
```

### 2. 환경 변수 설정

`.env` 파일 생성 또는 환경 변수 설정:

```bash
# 기본 설정
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=nteok
PORT=3000
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password
BCRYPT_SALT_ROUNDS=12

# HTTPS 자동 인증서 설정 (선택 사항)
# DuckDNS 도메인과 토큰을 설정하면 Let's Encrypt 인증서가 자동으로 발급됩니다.
DUCKDNS_DOMAIN=your-domain.duckdns.org
DUCKDNS_TOKEN=your-duckdns-token
CERT_EMAIL=admin@example.com
ENABLE_HTTP_REDIRECT=true
```

자세한 환경 변수 설명은 `.env.example` 파일을 참조하세요.

### 3. 의존성 설치 및 실행

```bash
npm install
npm start
```

서버가 `http://localhost:3000`에서 실행됩니다.

### 4. 초기 로그인

기본 관리자 계정으로 로그인 후 비밀번호를 변경하세요.
- 아이디: `admin` (또는 설정한 값)
- 비밀번호: `admin` (또는 설정한 값)

---

## HTTPS 자동 인증서 설정

NTEOK는 DuckDNS와 Let's Encrypt를 연동하여 HTTPS 인증서를 자동으로 발급하고 관리합니다.

### 특징

- ✅ **자동 인증서 발급**: Let's Encrypt DNS-01 Challenge
- ✅ **자동 갱신**: 만료 30일 전 자동 갱신 (24시간 주기 체크)
- ✅ **DuckDNS 연동**: TXT 레코드 기반 도메인 검증
- ✅ **HTTP/HTTPS 자동 전환**: 설정에 따라 자동으로 프로토콜 선택
- ✅ **순수 npm 라이브러리**: Certbot 등 외부 데몬 불필요

### 설정 방법

#### 1. DuckDNS 계정 생성

1. [DuckDNS](https://www.duckdns.org)에 접속하여 계정 생성
2. 원하는 도메인 등록 (예: `mynteok.duckdns.org`)
3. 서버의 공개 IP 주소를 도메인에 연결
4. API 토큰 복사

#### 2. 환경 변수 설정

`.env` 파일에 다음 내용 추가:

```bash
# DuckDNS 도메인 (반드시 .duckdns.org로 끝나야 함)
DUCKDNS_DOMAIN=mynteok.duckdns.org

# DuckDNS API 토큰
DUCKDNS_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Let's Encrypt 인증서 이메일 (선택 사항)
CERT_EMAIL=admin@example.com

# HTTPS 포트 (기본값: 3000, 권장: 443)
PORT=443

# HTTP -> HTTPS 자동 리다이렉트 (선택 사항)
ENABLE_HTTP_REDIRECT=true
```

#### 3. 서버 실행

```bash
npm start
```

서버가 시작되면 자동으로 다음 작업을 수행합니다:

1. **기존 인증서 확인**: 유효한 인증서가 있으면 재사용
2. **인증서 발급**: 없거나 만료된 경우 Let's Encrypt에서 새로 발급
3. **DNS Challenge**: DuckDNS API를 통해 TXT 레코드 설정
4. **HTTPS 서버 시작**: 발급된 인증서로 HTTPS 서버 실행

#### 4. 인증서 저장 위치

발급된 인증서는 `certs/` 디렉토리에 저장됩니다:

```
certs/
├── account-key.pem       # ACME 계정 개인키
├── domain-key.pem        # 도메인 개인키
├── certificate.pem       # 인증서
├── fullchain.pem         # 전체 체인 (인증서 + 중간 인증서)
└── chain.pem             # 중간 인증서 체인
```

### 주의사항

- **공개 IP 필요**: Let's Encrypt DNS Challenge는 공개 IP에서만 작동합니다.
- **도메인 형식**: DuckDNS 도메인은 반드시 `.duckdns.org`로 끝나야 합니다.
- **포트 권한**: 포트 80/443 사용 시 관리자 권한이 필요할 수 있습니다.
- **DNS 전파 시간**: 최초 인증서 발급 시 약 2-3분 소요됩니다.
- **자동 갱신**: 서버가 실행 중이면 만료 30일 전 자동으로 갱신됩니다.

### 폴백 모드

HTTPS 인증서 발급에 실패하면 자동으로 HTTP 모드로 폴백됩니다:

```
❌ HTTPS 인증서 발급 실패. HTTP 모드로 폴백합니다.
⚠️  NTEOK 앱이 HTTP로 실행 중: http://localhost:3000
```

---

## API 엔드포인트

### 인증
- `POST /api/auth/login` - 로그인
- `POST /api/auth/logout` - 로그아웃
- `POST /api/auth/register` - 회원가입
- `GET /api/auth/me` - 현재 사용자 정보
- `DELETE /api/auth/delete-account` - 계정 삭제

### 2단계 인증
- `POST /api/auth/totp/setup` - TOTP 설정
- `POST /api/auth/totp/verify` - TOTP 인증
- `DELETE /api/auth/totp/disable` - TOTP 비활성화

### 컬렉션
- `GET /api/collections` - 컬렉션 목록 조회
- `POST /api/collections` - 컬렉션 생성
- `DELETE /api/collections/:id` - 컬렉션 삭제

### 컬렉션 공유
- `POST /api/collections/:id/share` - 사용자에게 공유
- `DELETE /api/collections/:id/share/:shareId` - 공유 해제
- `POST /api/collections/:id/share-link` - 공유 링크 생성
- `POST /api/share-link/:token` - 공유 링크로 접근

### 페이지
- `GET /api/pages` - 페이지 목록 조회
- `GET /api/pages/:id` - 페이지 조회
- `POST /api/pages` - 페이지 생성
- `PUT /api/pages/:id` - 페이지 수정
- `DELETE /api/pages/:id` - 페이지 삭제
- `PUT /api/pages/:id/share-permission` - 암호화 페이지 공유 설정

---

## 보안 고려사항

### End-to-End 암호화
- 클라이언트 측에서 AES-256-GCM으로 암호화
- 암호화 키는 사용자만 소유
- 서버는 암호화된 데이터만 저장

### 2단계 인증
- TOTP 기반 시간 동기화 인증
- QR 코드를 통한 간편한 설정
- 백업 코드 제공 (예정)

### 세션 보안
- SameSite=Strict 쿠키 설정
- CSRF 토큰 검증
- 세션 타임아웃 관리

---

## 디자인 컨셉

한국 전통 한지의 미니멀한 감성을 현대적으로 재해석한 디자인입니다.

### 색상 팔레트
- **배경**: 한지 느낌의 크림/베이지 계열 (#faf8f3, #f5f2ed)
- **사이드바**: 어두운 베이지 계열 (#ebe8e1)
- **텍스트**: 먹색 계열 (#1a1a1a, #2d2d2d)
- **포인트**: 어두운 청록색 (#2d5f5d)

### 디자인 원칙
- 절제된 여백과 깔끔한 레이아웃
- 직선 위주의 미니멀한 인터페이스
- 반응형 디자인으로 모든 기기 지원
- 가독성을 위한 충분한 line-height (1.7)

---

## 프로젝트 구조

```
NTEOK/
├── server.js              # Express 서버 엔트리포인트
├── cert-manager.js        # HTTPS 인증서 자동 발급 모듈
├── package.json           # 프로젝트 의존성
├── .env.example           # 환경 변수 예시
├── certs/                 # SSL/TLS 인증서 저장 (자동 생성)
├── public/                # 클라이언트 파일
│   ├── index.html         # 메인 애플리케이션
│   ├── login.html         # 로그인 페이지
│   ├── register.html      # 회원가입 페이지
│   ├── css/
│   │   ├── main.css       # 메인 스타일
│   │   └── login.css      # 로그인 스타일
│   └── js/
│       ├── app.js         # 메인 로직
│       ├── editor.js      # 에디터 초기화
│       ├── pages-manager.js    # 페이지 관리
│       ├── encryption-manager.js  # 암호화 관리
│       ├── share-manager.js       # 공유 관리
│       ├── settings-manager.js    # 설정 관리
│       ├── crypto.js      # E2EE 암호화
│       └── ui-utils.js    # UI 유틸리티
└── README.md
```

---

## 키워드

노트 앱, 마크다운 에디터, 웹 노트, E2EE, End-to-End 암호화, 암호화 노트, 셀프 호스팅, 오픈소스 노트, Node.js 노트 앱, MySQL 노트 앱, 협업 노트, 공유 노트, Tiptap 에디터, 2단계 인증, TOTP, 반응형 노트 앱, 웹 기반 노트, 개인 노트 서버

---

## 라이선스

MIT License

---

## 개발자

RichardCYang
