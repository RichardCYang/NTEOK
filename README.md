# NTEOK

셀프 호스팅 가능한 웹 기반 노트 애플리케이션

---

**한국어** | **[日本語](README.jp.md)** | **[English](README.en.md)**

---

<img src="./example.png" width="100%" title="NTEOK_Screenshot"/>

## 개요

**NTEOK**는 한국어 넋(NEOK)과 노트(NOTE)의 합성어입니다. Node.js와 MySQL 기반의 다중 사용자 노트 웹 애플리케이션으로, 블록 기반 마크다운 편집과 End-to-End 암호화를 지원합니다.

### 주요 특징

- **마크다운 편집기**: Tiptap 기반 블록 에디터 (다양한 블록 타입 지원)
- **다양한 블록 타입**: 문단, 제목, 리스트, 체크리스트, 이미지, 코드, 수식, 보드, 콜아웃, 토글, 탭, 파일, 캘린더, YouTube 임베드 등
- **End-to-End 암호화**: AES-256-GCM 방식의 클라이언트 측 암호화
- **저장소 공유**: 사용자 간 협업 및 링크 공유
- **계층적 구조**: 페이지 부모-자식 관계 지원
- **다양한 인증**: TOTP 2단계 인증 및 Passkey (WebAuthn/FIDO2) 지원
- **백업/복구**: 데이터 전체 백업 및 복구 기능 (ZIP 포맷)
- **페이지 동기화**: 실시간 페이지 내용 동기화 (WebSocket + Yjs)
- **페이지 댓글**: 페이지별 댓글 기능으로 협업 의사소통 강화
- **커버 이미지**: 페이지별 커버 이미지 설정 및 정렬
- **HTTPS 자동 인증서**: Let's Encrypt + DuckDNS 연동
- **반응형 디자인**: 모바일, 태블릿, 데스크탑 최적화
- **셀프 호스팅**: 독립적인 서버 운영 가능

---

## 핵심 기능

### 사용자 관리
- 회원가입 및 로그인 시스템
- TOTP 2단계 인증 (Google Authenticator, Authy 등)
- **Passkey 인증** (WebAuthn/FIDO2 - 생체 인식, 하드웨어 토큰)
- 세션 기반 인증
- 계정 삭제 기능

### 노트 편집
- **블록 타입**: 문단, 제목(H1-H6), 목록(글머리/번호), 체크리스트, 이미지, 인용구, 코드 블록, 구분선, LaTeX 수식, 보드, 콜아웃, 토글, 탭, 파일, 캘린더, YouTube 임베드 등
- **인라인 서식**: 굵게, 기울임, 취소선, 텍스트 색상
- **정렬 옵션**: 왼쪽, 가운데, 오른쪽, 양쪽
- **이미지 기능**: 이미지 블록 정렬 및 캡션 지원 (캡션 포함 이미지 블록)
- **특수 블록**:
  - **보드 뷰**: 카드 형식의 페이지 그룹 표시
  - **콜아웃**: 강조 메시지 및 알림 표시
  - **토글**: 펼치고 접을 수 있는 콘텐츠
  - **탭**: 여러 탭으로 구성된 콘텐츠 표시
  - **파일**: 파일 첨부 및 다운로드
  - **캘린더**: 달력 형식의 데이터 표시
  - **YouTube**: 유튜브 비디오 직접 임베드
  - **수식**: LaTeX 형식의 수학 수식 렌더링 (KaTeX)
- **슬래시 명령**: `/` 입력으로 블록 타입 전환
- **단축키**: `Ctrl+S` / `Cmd+S` 저장

### 저장소 및 페이지
- 저장소별 페이지 그룹화
- 계층적 페이지 구조 (부모-자식 관계)
- 페이지 아이콘 설정 (170개 Font Awesome 아이콘, 400개 이모지)
- **페이지 커버 이미지**: 기본 이미지 또는 사용자 업로드 이미지 설정
- 최근 수정 시각 기준 자동 정렬
- 드래그 앤 드롭 정렬 (예정)

### 보안 기능
- **E2EE 암호화**: AES-256-GCM 방식
- **클라이언트 측 암호화**: 서버에 암호화된 데이터만 전송
- **TOTP 2FA**: 시간 기반 일회용 비밀번호
- **Passkey 보안**: WebAuthn 표준 기반 강력한 인증
- **CSRF 보호**: SameSite 쿠키 설정
- **세션 관리**: 안전한 쿠키 기반 인증

### 데이터 관리
- **백업/복구**: 전체 컬렉션 및 페이지 데이터 ZIP 포맷 백업 및 복구
- **데이터 내보내기**: HTML 형식으로 페이지 내용 변환
- **데이터 불러오기**: 이전 백업 데이터 복구 및 복원
- **PDF 내보내기**: 페이지 콘텐츠를 PDF 형식으로 변환
- **페이지 발행**: 공개 링크를 통한 페이지 공유 (읽기 전용)

### 실시간 동기화
- **WebSocket 기반 동기화**: 페이지 변경사항 실시간 동기화
- **협업 편집**: 여러 사용자의 동시 편집 지원 (Yjs 기반)
- **데이터 일관성**: 변경사항 충돌 해결 및 동기화 정확도 향상

### 협업 기능
- **사용자 공유**: 특정 사용자에게 컬렉션 공유
- **링크 공유**: 링크를 통한 컬렉션 접근
- **권한 관리**: READ, EDIT, OWNER 권한 레벨
- **암호화 페이지 공유**: 공유 허용 설정 옵션
- **페이지 댓글**: 페이지에 댓글을 달아 협업 의사소통
- **로그인 로그**: 계정 보안을 위한 로그인 기록 추적

---

## 기술 스택

### 백엔드
- **런타임**: Node.js 18+
- **프레임워크**: Express 5.x
- **데이터베이스**: MySQL 8.x
- **인증**: bcrypt (비밀번호 해싱), speakeasy (TOTP), @simplewebauthn (Passkey)
- **보안**: cookie-parser, CSRF 토큰, SameSite 쿠키
- **백업**: archiver (ZIP 생성), adm-zip (ZIP 추출)
- **실시간**: WebSocket (ws), Yjs (CRDT 기반 동기화)
- **HTTPS**: acme-client (Let's Encrypt), dotenv (환경 변수)

### 프론트엔드
- **코어**: 바닐라 JavaScript (ES6+ 모듈)
- **에디터**: Tiptap v2 (StarterKit, TextAlign, Color, Mathematics, ImageWithCaption)
- **수식 렌더링**: KaTeX
- **암호화**: Web Crypto API (AES-256-GCM)
- **Passkey**: @simplewebauthn/browser (WebAuthn)
- **실시간 동기화**: Yjs, WebSocket
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

### 2. 환경 설정 (setup 스크립트)

Windows:
```bash
setup.bat
```

Linux/macOS:
```bash
chmod +x setup.sh
./setup.sh
```

스크립트가 다음 정보를 대화형으로 입력받습니다:
- 데이터베이스 호스트, 포트, 사용자명, 비밀번호
- 관리자 계정 아이디/비밀번호 (미입력 시 자동 생성)
- HTTPS 설정 여부 (DuckDNS)

### 3. 의존성 설치 및 실행

```bash
npm install
npm start
```

서버가 `http://localhost:3000`에서 실행됩니다.

### 4. 초기 로그인

setup 스크립트에서 설정한 관리자 계정으로 로그인하세요.

> 보안 권장: 강력한 비밀번호를 설정하고, 초기 로그인 후 필요시 변경하세요.

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

### Passkey (WebAuthn)
- `GET /api/passkey/status` - Passkey 활성화 상태 조회
- `POST /api/passkey/register/options` - 등록 옵션 생성
- `POST /api/passkey/register/verify` - 등록 검증
- `POST /api/passkey/authenticate/options` - 인증 옵션 생성
- `POST /api/passkey/authenticate/verify` - Passkey 인증 검증

### 저장소
- `GET /api/storages` - 저장소 목록 조회
- `POST /api/storages` - 저장소 생성
- `PUT /api/storages/:id` - 저장소 이름 수정
- `DELETE /api/storages/:id` - 저장소 삭제
- `GET /api/storages/:id/collaborators` - 참여자 목록 조회
- `POST /api/storages/:id/collaborators` - 참여자 추가
- `DELETE /api/storages/:id/collaborators/:userId` - 참여자 삭제

### 페이지
- `GET /api/pages` - 페이지 목록 조회
- `GET /api/pages/:id` - 페이지 조회
- `POST /api/pages` - 페이지 생성
- `PUT /api/pages/:id` - 페이지 수정
- `DELETE /api/pages/:id` - 페이지 삭제
- `PUT /api/pages/:id/share-permission` - 암호화 페이지 공유 설정
- `GET /api/pages/covers/user` - 사용자 커버 이미지 목록 조회

### 백업/복구
- `POST /api/backup/export` - 데이터 내보내기 (ZIP)
- `POST /api/backup/import` - 데이터 불러오기 (ZIP)

### 페이지 댓글
- `GET /api/comments` - 댓글 목록 조회
- `POST /api/comments` - 댓글 작성
- `DELETE /api/comments/:id` - 댓글 삭제

### 테마 설정
- `GET /api/themes` - 사용자 테마 조회
- `PUT /api/themes` - 테마 설정 변경

### 발행된 페이지
- `GET /api/pages/:id/publish-link` - 발행 링크 조회
- `POST /api/pages/:id/publish-link` - 발행 링크 생성

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

### Passkey 보안
- WebAuthn/FIDO2 표준 기반 강력한 인증
- 생체 인식 (지문, 얼굴인식) 및 하드웨어 토큰 지원
- 피싱 공격 방지 및 강력한 암호화

### 세션 보안
- SameSite=Strict 쿠키 설정
- CSRF 토큰 검증
- 세션 타임아웃 관리

### 데이터 백업 보안
- 백업 파일 암호화 저장
- 데이터 무결성 검증
- 접근 권한 제한

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
├── websocket-server.js    # WebSocket 서버 (실시간 동기화)
├── cert-manager.js        # HTTPS 인증서 자동 발급 모듈 (Let's Encrypt)
├── network-utils.js       # 네트워크 유틸리티 (IP, 지역 정보)
├── security-utils.js      # 보안 유틸리티
├── package.json           # 프로젝트 의존성
├── .env.example           # 환경 변수 예시
├── icon.png               # 애플리케이션 아이콘
├── example.png            # README 예제 스크린샷
├── LICENSE                # ISC 라이선스
├── certs/                 # SSL/TLS 인증서 저장 (자동 생성)
├── data/                  # 데이터 저장소
├── covers/                # 커버 이미지 저장소
│   ├── default/           # 기본 커버 이미지
│   └── [userId]/          # 사용자 커버 이미지
├── themes/                # CSS 테마
│   ├── default.css        # 기본 밝은 테마
│   └── dark.css           # 다크 테마
├── languages/             # i18n 다국어 파일
│   ├── ko-KR.json         # 한국어
│   ├── en.json            # 영어
│   └── ja-JP.json         # 일본어
├── public/                # 클라이언트 파일
│   ├── index.html         # 메인 애플리케이션 (로그인 후)
│   ├── login.html         # 로그인 페이지
│   ├── register.html      # 회원가입 페이지
│   ├── shared-page.html   # 공개 페이지 뷰
│   ├── css/
│   │   ├── main.css       # 메인 스타일 (약 90KB)
│   │   ├── login.css      # 로그인 스타일
│   │   └── comments.css   # 댓글 기능 스타일
│   └── js/                # 프론트엔드 JavaScript 모듈 (약 600KB)
│       ├── app.js         # 메인 애플리케이션 로직
│       ├── editor.js      # Tiptap 에디터 초기화
│       ├── pages-manager.js         # 페이지 관리
│       ├── encryption-manager.js    # E2EE 암호화 관리
│       ├── storages-manager.js      # 저장소 관리
│       ├── settings-manager.js      # 사용자 설정 관리
│       ├── backup-manager.js        # 백업/복구 관리
│       ├── sync-manager.js          # WebSocket 실시간 동기화
│       ├── passkey-manager.js       # Passkey/WebAuthn 관리
│       ├── totp-manager.js          # TOTP 2FA 관리
│       ├── login.js                 # 로그인 페이지 로직
│       ├── register.js              # 회원가입 페이지 로직
│       ├── crypto.js                # Web Crypto API 래퍼
│       ├── pdf-export.js            # PDF 내보내기
│       ├── comments-manager.js      # 페이지 댓글 기능
│       ├── account-manager.js       # 계정 관리
│       ├── cover-manager.js         # 커버 이미지 관리
│       ├── drag-handle-extension.js # 드래그 확장 기능
│       ├── publish-manager.js       # 페이지 발행 관리
│       ├── subpages-manager.js      # 페이지 계층 관리
│       ├── shared-page.js           # 공개 페이지 뷰 로직
│       ├── login-logs-manager.js    # 로그인 로그 관리
│       ├── board-node.js            # 보드 뷰 블록
│       ├── callout-node.js          # 콜아웃 블록
│       ├── image-with-caption-node.js  # 캡션 포함 이미지 블록
│       ├── math-node.js             # LaTeX 수식 블록
│       ├── toggle-node.js           # 토글 블록
│       ├── tab-node.js              # 탭 뷰 블록
│       ├── file-node.js             # 파일 첨부 블록
│       ├── calendar-node.js         # 캘린더 블록
│       ├── youtube-node.js          # YouTube 임베드 블록
│       ├── modal-parent-manager.js  # 모달 관리
│       ├── ui-utils.js              # UI 유틸리티
│       └── csrf-utils.js            # CSRF 토큰 유틸리티
├── routes/                # API 라우트
│   ├── index.js           # 정적 페이지 및 공개 페이지
│   ├── auth.js            # 인증 API (회원가입, 로그인, 계정 삭제)
│   ├── pages.js           # 페이지 CRUD 및 동기화 API
│   ├── storages.js        # 저장소 관리 API
│   ├── totp.js            # TOTP 2FA 설정/인증 API
│   ├── passkey.js         # Passkey/WebAuthn API
│   ├── backup.js          # 백업/복구 API
│   ├── comments.js        # 페이지 댓글 API
│   ├── themes.js          # 테마 설정 API
│   └── bootstrap.js       # 초기 데이터베이스 설정
└── README.md
```

---

## 키워드

노트 앱, 마크다운 에디터, 웹 노트, E2EE, End-to-End 암호화, 암호화 노트, 셀프 호스팅, 오픈소스 노트, Node.js 노트 앱, MySQL 노트 앱, 협업 노트, 공유 노트, Tiptap 에디터, 2단계 인증, TOTP, Passkey, WebAuthn, 실시간 동기화, 백업/복구, 반응형 노트 앱, 웹 기반 노트, 개인 노트 서버, 커버 이미지, Yjs

---

---

## 최근 보안 패치 및 업데이트

### 2026-02-27 기능 추가

- **탭 뷰 블록** - 여러 탭으로 구성된 콘텐츠 표시
- **파일 블록** - 파일 첨부 및 다운로드 기능
- **캘린더 블록** - 달력 형식의 데이터 표시
- **WebRTC 기반 실시간 동기화** - 암호화 저장소에서도 Yjs 동기화 지원
- **.env 설정 편의** - 배치파일/쉘스크립트로 간편한 환경 설정

### 2026-01-19 보안 패치

- **임의 파일 삭제 취약점 수정** - 파일 시스템 접근 제어 강화
- **SVG 스크립트 실행 취약점 방지** - 이미지 업로드 시 SVG 포맷 금지
- **CDN/ESM 모듈 무결성 검증** - SRI(Subresource Integrity) 추가하여 공급망 취약점 방어
- **테마파일 업로드 검증 강화** - 중복 검증 로직 구현

---

## 라이선스

MIT License

---

## 개발자

RichardCYang
