# NTEOK

셀프 호스팅 가능한 웹 기반 노트 애플리케이션

---

**한국어** | **[日本語](README.jp.md)** | **[English](README.en.md)**

---

## 주요 기능

- **강력한 블록 에디터**: Tiptap 기반의 유연한 에디터 (텍스트, 이미지, 수식, 코드 블록 등 지원)
- **계층형 페이지 관리**: 무제한 하위 페이지 생성 및 드래그 앤 드롭 정렬
- **종단간 암호화 (E2EE)**: 민감한 저장소를 위한 브라우저 기반 암호화 (AES-GCM)
- **이미지 및 파일 첨부**: 드래그 앤 드롭으로 이미지와 파일 업로드
- **실시간 협업**: Yjs를 이용한 다중 사용자 실시간 편집
- **커버 및 아이콘**: 페이지별 커버 이미지와 아이콘 설정
- **모바일 대응**: 반응형 디자인으로 모바일 기기에서도 원활하게 사용 가능

### 데이터 관리
- **저장소별 권한 관리**: 컬렉션 단위로 권한 부여 및 관리
- **백업 및 복구**: 전체 데이터를 ZIP 형식으로 내보내기 및 가져오기
- **PDF 내보내기**: 페이지 콘텐츠를 PDF 형식으로 변환

### 실시간 동기화
- WebSocket을 이용한 실시간 업데이트
- 오프라인 지원 (Local Storage 캐싱)

---

## 기술 스택

- **Frontend**: React (Tiptap, Yjs, Lucide-react), Vanilla CSS
- **Backend**: Node.js (Express), WebSocket
- **Database**: MySQL, Redis (세션 및 속도 제한)

---

## 프로젝트 구조

```text
C:\Users\user\Downloads\PROJECT\NTEOK\
├── server.js              # 메인 서버 (Express & WebSocket)
├── websocket-server.js    # 실시간 동기화 서버 로직
├── cert-manager.js        # SSL 인증서 관리
├── network-utils.js       # 네트워크 유틸리티
├── security-utils.js      # 보안 유틸리티
├── authz/                 # 권한 부여 (Authorization) 정책
├── data/                  # 데이터 저장소 (기본 페이지 JSON)
├── lib/                   # 서버측 라이브러리 (Redis, 세션 등)
├── middlewares/           # Express 미들웨어
├── public/                # 클라이언트 파일
│   ├── index.html         # 메인 애플리케이션 (로그인 후)
│   ├── login.html         # 로그인 페이지
│   ├── register.html      # 회원가입 페이지
│   ├── css/
│   │   ├── main.css       # 메인 스타일
│   │   ├── login.css      # 로그인 스타일
│   │   └── comments.css   # 댓글 기능 스타일
│   └── js/                # 프론트엔드 JavaScript 모듈
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
│       ├── subpages-manager.js      # 페이지 계층 관리
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
├── repositories/          # 데이터베이스 접근 계층 (Repository)
├── routes/                # Express 라우터 (API 엔드포인트)
├── scripts/               # 유틸리티 스크립트
├── themes/                # 사용자 정의 CSS 테마
└── utils/                 # 기타 유틸리티
```

---

## API 엔드포인트

### 인증
- `POST /api/auth/register` - 회원가입
- `POST /api/auth/login` - 로그인
- `POST /api/auth/logout` - 로그아웃

### 페이지 관리
- `GET /api/pages` - 전체 페이지 목록 조회
- `POST /api/pages` - 새 페이지 생성
- `GET /api/pages/:id` - 특정 페이지 상세 정보 조회
- `PUT /api/pages/:id` - 페이지 내용 수정
- `DELETE /api/pages/:id` - 페이지 삭제

### 저장소 관리
- `GET /api/storages` - 사용자 저장소 목록
- `POST /api/storages` - 새 저장소 생성

### 댓글
- `GET /api/comments/:pageId` - 댓글 목록 조회
- `POST /api/comments/:pageId` - 새 댓글 작성

### 테마 설정
- `GET /api/themes` - 사용자 테마 조회
- `PUT /api/themes` - 테마 설정 변경

---

## 보안 고려사항

- **E2EE 암호화**: 저장소 암호화 키는 서버로 전송되지 않으며 브라우저 내에서만 사용됩니다.
- **CSRF 보호**: 모든 변조 요청은 CSRF 토큰 검증을 통과해야 합니다.
- **비밀번호 해싱**: bcrypt를 사용하여 비밀번호를 안전하게 저장합니다.
- **Rate Limiting**: 무차별 대입 공격을 방지하기 위해 요청 제한이 적용됩니다.

---

## 라이선스

MIT License

---

## 개발자

RichardCYang
