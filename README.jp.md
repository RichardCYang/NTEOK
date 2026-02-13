# NTEOK

自分でホストできるウェブベースのノートアプリケーション

---

**[한국어](README.md)** | **[日本語](README.jp.md)** | **[English](README.en.md)**

---

<img src="./example.png" width="100%" title="NTEOK_Screenshot"/>

## 概要

**NTEOK**は、韓国語の「Neok(넋、魂)」と「Note」を組み合わせた言葉です。Node.jsとMySQLに基づいた多機能のメモ取りウェブアプリケーションで、ブロックベースのマークダウン編集とエンドツーエンド暗号化をサポートしています。

### 主な機能

- **マークダウンエディタ**: 様々なブロックタイプに対応したTiptapベースのブロックエディタ
- **多様なブロックタイプ**: 段落、見出し、リスト、チェックリスト、画像、コード、数式、ボード、ブックマーク、コールアウト、トグル、YouTube埋め込みなど
- **エンドツーエンド暗号化**: AES-256-GCMクライアント側暗号化
- **ストレージ共有**: ユーザー間のコラボレーションとリンク共有
- **階層構造**: 親子ページの関係をサポート
- **複数認証**: TOTP 2段階認証とPasskey (WebAuthn/FIDO2)対応
- **バックアップ/復元**: 完全なデータバックアップと復元 (ZIP形式)
- **リアルタイム同期**: WebSocket + Yjsによるページ内容のリアルタイム同期
- **ページコメント**: ページ別のコメント機能で協業コミュニケーションを強化
- **カバー画像**: ページのカバー画像設定とソート
- **HTTPS自動証明書**: Let's Encrypt + DuckDNS連携
- **レスポンシブデザイン**: モバイル、タブレット、デスクトップに最適化
- **セルフホスティング**: 独立したサーバー運用が可能

---

## コア機能

### ユーザー管理
- 登録とログインシステム
- TOTP 2段階認証 (Google Authenticator, Authy等)
- **Passkey認証** (WebAuthn/FIDO2 - 生体認証、ハードウェアトークン)
- セッションベースの認証
- アカウント削除機能

### ノート編集
- **ブロックタイプ**: 段落、見出し(H1-H6)、リスト(箇条書き/番号)、画像、引用、コードブロック、水平線、LaTeX数式、ボード、ブックマーク、コールアウト、トグル、YouTube埋め込みなど
- **インライン形式**: 太字、斜体、打消し線、テキスト色
- **配置オプション**: 左、中央、右、両端揃え
- **画像機能**: 画像ブロックの配置とキャプション対応 (キャプション付き画像ブロック)
- **特殊なブロック**:
  - **ボードビュー**: カード形式でページを表示
  - **ブックマーク**: 外部リンクとプレビューを保存
  - **コールアウト**: メッセージと通知を強調表示
  - **トグル**: 展開・折りたたみ可能なコンテンツ
  - **YouTube**: YouTubeビデオを直接埋め込み
  - **数式**: LaTeX形式の数学公式 (KaTeXでレンダリング)
- **スラッシュコマンド**: `/`入力でブロックタイプを切り替え
- **キーボードショートカット**: `Ctrl+S` / `Cmd+S`で保存

### ストレージとページ
- ストレージ別にページを分類
- 階層的なページ構造 (親子関係)
- ページアイコン設定 (170個のFont Awesomeアイコン、400個の絵文字)
- **ページカバー画像**: デフォルト画像またはユーザーアップロード画像の設定
- 最後の変更時刻でソート
- ドラッグアンドドロップソート (予定)

### セキュリティ機能
- **E2EE暗号化**: AES-256-GCM暗号化
- **クライアント側暗号化**: サーバーに送信される暗号化データのみ
- **TOTP 2FA**: 時間ベースのワンタイムパスワード
- **Passkey セキュリティ**: WebAuthn標準ベースの強力な認証
- **CSRF保護**: SameSiteクッキー設定
- **セッション管理**: 安全なクッキーベースの認証

### データ管理
- **バックアップ/復元**: ストレージとページの全データバックアップと復元 (ZIP形式)
- **データエクスポート**: ページ内容をHTML形式に変換
- **データインポート**: 前回のバックアップデータを復元
- **PDFエクスポート**: ページ内容をPDF形式に変換
- **ページ発行**: 公開リンクを通じたページ共有 (読み取り専用)

### リアルタイム同期
- **WebSocket同期**: ページの変更内容をリアルタイム同期
- **共同編集**: 複数ユーザーの同時編集対応 (Yjsベース)
- **データの一貫性**: 変更の競合を解決し、同期精度を向上

### コラボレーション機能
- **ユーザー共有**: 特定のユーザーとストレージを共有
- **権限管理**: READ、EDIT、ADMIN 権限レベル
- **暗号化ページ共有**: 共有許可設定
- **ページコメント**: ページにコメントを投稿して協業コミュニケーション
- **ログイン履歴**: アカウントセキュリティのためのログイン記録追跡

---

## 技術スタック

### バックエンド
- **ランタイム**: Node.js 18+
- **フレームワーク**: Express 5.x
- **データベース**: MySQL 8.x
- **認証**: bcrypt (パスワードハッシング)、speakeasy (TOTP)、@simplewebauthn (Passkey)
- **セキュリティ**: cookie-parser、CSRFトークン、SameSiteクッキー
- **백업**: archiver (ZIP作成)、adm-zip (ZIP抽出)
- **リアルタイム**: WebSocket (ws)、Yjs (CRDT同期)
- **HTTPS**: acme-client (Let's Encrypt)、dotenv (環境変数)

### フロントエンド
- **コア**: Vanilla JavaScript (ES6+モジュール)
- **エディタ**: Tiptap v2 (StarterKit、TextAlign、Color、Mathematics、ImageWithCaption)
- **数式レンダリング**: KaTeX
- **暗号化**: Web Crypto API (AES-256-GCM)
- **Passkey**: @simplewebauthn/browser (WebAuthn)
- **リアルタイム同期**: Yjs、WebSocket
- **アイコン**: Font Awesome 6
- **スタイル**: 純CSS (レスポンシブデザイン)

---

## インストール手順

### 必須要件

- Node.js 18 LTS以上
- MySQL 8.xサーバー
- npmパッケージマネージャー

### 1. データベースの作成

```sql
CREATE DATABASE nteok
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
```

### 2. 環境設定

`.env`ファイルを作成するか、環境変数を設定します:

```bash
# 基本設定
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=nteok
PORT=3000
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password
BCRYPT_SALT_ROUNDS=12

# HTTPS自動証明書設定 (オプション)
# DuckDNSドメインとトークンを設定すると、Let's Encrypt証明書が自動発行されます
DUCKDNS_DOMAIN=your-domain.duckdns.org
DUCKDNS_TOKEN=your-duckdns-token
CERT_EMAIL=admin@example.com
ENABLE_HTTP_REDIRECT=true
```

詳しい環境変数の説明は`.env.example`ファイルを参照してください。

### 3. 依存関係のインストールと実行

```bash
npm install
npm start
```

サーバーが`http://localhost:3000`で実行されます。

### 4. 初期ログイン

デフォルト管理者アカウントでログインしてから、パスワードを変更してください:
- ユーザー名: `admin` (または設定した値)
- パスワード: `admin` (または設定した値)

---

## HTTPS自動証明書設定

NTEOKはDuckDNSとLet's Encryptを連携してHTTPS証明書を自動発行・管理します。

### 特徴

- ✅ **自動証明書発行**: Let's Encrypt DNS-01チャレンジ
- ✅ **自動更新**: 失効30日前に自動更新 (24時間周期チェック)
- ✅ **DuckDNS連携**: TXTレコードベースのドメイン検証
- ✅ **HTTP/HTTPS自動切り替え**: 設定に基づいて自動的にプロトコル選択
- ✅ **純粋なnpmライブラリ**: Certbotなどの外部デーモンは不要

### 設定方法

#### 1. DuckDNSアカウント作成

1. [DuckDNS](https://www.duckdns.org)にアクセスしてアカウント作成
2. 目的のドメインを登録 (例: `mynteok.duckdns.org`)
3. サーバーの公開IPアドレスをドメインに接続
4. APIトークンをコピー

#### 2. 環境変数設定

`.env`ファイルに以下を追加:

```bash
# DuckDNSドメイン (.duckdns.orgで終わる必須)
DUCKDNS_DOMAIN=mynteok.duckdns.org

# DuckDNS APIトークン
DUCKDNS_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Let's Encrypt証明書メールアドレス (オプション)
CERT_EMAIL=admin@example.com

# HTTPSポート (デフォルト: 3000、推奨: 443)
PORT=443

# HTTP → HTTPS自動リダイレクト (オプション)
ENABLE_HTTP_REDIRECT=true
```

#### 3. サーバー実行

```bash
npm start
```

サーバーが起動すると自動的に以下の処理が実行されます:

1. **既存の証明書の確認**: 有効な証明書があれば再利用
2. **証明書発行**: ない場合や失効している場合はLet's Encryptから新規発行
3. **DNSチャレンジ**: DuckDNS APIを通じてTXTレコードを設定
4. **HTTPSサーバー起動**: 発行された証明書でHTTPSサーバーを実行

#### 4. 証明書保存場所

発行された証明書は`certs/`ディレクトリに保存されます:

```
certs/
├── account-key.pem       # ACMEアカウント秘密鍵
├── domain-key.pem        # ドメイン秘密鍵
├── certificate.pem       # 証明書
├── fullchain.pem         # 全チェーン (証明書 + 中間証明書)
└── chain.pem             # 中間証明書チェーン
```

### 注意事項

- **公開IP必要**: Let's Encrypt DNSチャレンジは公開IPでのみ機能します
- **ドメイン形式**: DuckDNSドメインは必ず`.duckdns.org`で終わる必要があります
- **ポート権限**: ポート80/443使用時は管理者権限が必要な場合があります
- **DNS伝播時間**: 初回証明書発行時は約2～3分かかります
- **自動更新**: サーバーが実行中なら失効30日前に自動更新されます

### フォールバックモード

HTTPS証明書発行に失敗した場合は自動的にHTTPモードにフォールバックします:

```
❌ HTTPS証明書発行失敗。HTTPモードにフォールバックします。
⚠️  NTEOKアプリがHTTPで実行中: http://localhost:3000
```

---

## APIエンドポイント

### 認証
- `POST /api/auth/login` - ログイン
- `POST /api/auth/logout` - ログアウト
- `POST /api/auth/register` - 登録
- `GET /api/auth/me` - 現在のユーザー情報
- `DELETE /api/auth/delete-account` - アカウント削除

### 2段階認証
- `POST /api/auth/totp/setup` - TOTP設定
- `POST /api/auth/totp/verify` - TOTP検証
- `DELETE /api/auth/totp/disable` - TOTP無効化

### Passkey (WebAuthn)
- `GET /api/passkey/status` - Passkey有効状態確認
- `POST /api/passkey/register/options` - 登録オプション生成
- `POST /api/passkey/register/verify` - 登録検証
- `POST /api/passkey/authenticate/options` - 認証オプション生成
- `POST /api/passkey/authenticate/verify` - Passkey認証検証

### ストレージ
- `GET /api/storages` - ストレージ一覧
- `POST /api/storages` - ストレージ作成
- `PUT /api/storages/:id` - ストレージ名の変更
- `DELETE /api/storages/:id` - ストレージ削除
- `GET /api/storages/:id/collaborators` - 参加者一覧
- `POST /api/storages/:id/collaborators` - 参加者の追加
- `DELETE /api/storages/:id/collaborators/:userId` - 参加者の削除

### ページ
- `GET /api/pages` - ページ一覧
- `GET /api/pages/:id` - ページ取得
- `POST /api/pages` - ページ作成
- `PUT /api/pages/:id` - ページ更新
- `DELETE /api/pages/:id` - ページ削除
- `GET /api/pages/covers/user` - ユーザーカバー画像一覧

### バックアップ/復元
- `POST /api/backup/export` - データエクスポート (ZIP)
- `POST /api/backup/import` - データインポート (ZIP)

### ページコメント
- `GET /api/comments` - コメント一覧
- `POST /api/comments` - コメント投稿
- `DELETE /api/comments/:id` - コメント削除

### テーマ設定
- `GET /api/themes` - ユーザーテーマ取得
- `PUT /api/themes` - テーマ設定変更

### 発行されたページ
- `GET /api/pages/:id/publish` - 発行状態取得
- `POST /api/pages/:id/publish` - 発行リンク作成

---

## セキュリティ上の考慮事項

### エンドツーエンド暗号化
- クライアント側でAES-256-GCM暗号化
- 暗号化キーはユーザーのみが所有
- サーバーは暗号化されたデータのみ保存

### 2段階認証
- TOTP時間同期認証
- QRコード経由での簡単設定
- バックアップコード提供 (予定)

### Passkey セキュリティ
- WebAuthn/FIDO2標準ベースの強力な認証
- 生体認証 (指紋認証、顔認証) とハードウェアトークン対応
- フィッシング攻撃防止と強力な暗号化

### セッションセキュリティ
- SameSite=Strictクッキー設定
- CSRFトークン検証
- セッションタイムアウト管理

### データバックアップセキュリティ
- バックアップファイル暗号化保存
- データ整合性検証
- アクセス権限制限

---

## デザインコンセプト

韓国の伝統的な韓紙(ハンジ)のミニマリストな美学を現代的に再解釈したデザイン。

### カラーパレット
- **背景**: 韓紙風のクリーム/ベージュ調 (#faf8f3、#f5f2ed)
- **サイドバー**: 濃いベージュ調 (#ebe8e1)
- **テキスト**: 墨色 (#1a1a1a、#2d2d2d)
- **アクセント**: 濃い青緑色 (#2d5f5d)

### デザイン原則
- 控えめな余白とクリーンなレイアウト
- 直線中心のミニマリストなインターフェース
- すべてのデバイスに対応するレスポンスブデザイン
- 読みやすさのための充分なline-height (1.7)

---

## プロジェクト構造

```
NTEOK/
├── server.js              # Expressサーバーエントリポイント
├── websocket-server.js    # WebSocketサーバー (リアルタイム同期)
├── cert-manager.js        # HTTPS証明書自動発行モジュール (Let's Encrypt)
├── network-utils.js       # ネットワークユーティリティ (IP、ロケーション情報)
├── security-utils.js      # セキュリティユーティリティ
├── package.json           # プロジェクト依存関係
├── .env.example           # 環境変数例
├── icon.png               # アプリケーションアイコン
├── example.png            # READMEスクリーンショット
├── LICENSE                # ISCライセンス
├── certs/                 # SSL/TLS証明書保存 (自動生成)
├── data/                  # データリポジトリ
├── covers/                # カバー画像リポジトリ
│   ├── default/           # デフォルトカバー画像
│   └── [userId]/          # ユーザーカバー画像
├── themes/                # CSSテーマ
│   ├── default.css        # デフォルトライトテーマ
│   └── dark.css           # ダークテーマ
├── languages/             # i18n多言語ファイル
│   ├── ko-KR.json         # 韓国語
│   ├── en.json            # 英語
│   └── ja-JP.json         # 日本語
├── public/                # クライアントファイル
│   ├── index.html         # メインアプリケーション (ログイン後)
│   ├── login.html         # ログインページ
│   ├── register.html      # 登録ページ
│   ├── shared-page.html   # 公開ページビュー
│   ├── css/
│   │   ├── main.css       # メインスタイル
│   │   ├── login.css      # ログインスタイル
│   │   └── comments.css   # コメント機能スタイル
│   └── js/                # フロントエンドJavaScriptモジュール
│       ├── app.js         # メインアプリケーションロジック
│       ├── editor.js      # Tiptapエディター初期化
│       ├── pages-manager.js         # ページ管理
│       ├── encryption-manager.js    # E2EE暗号化管理
│       ├── storages-manager.js      # ストレージ管理
│       ├── settings-manager.js      # ユーザー設定管理
│       ├── backup-manager.js        # バックアップ/復元管理
│       ├── sync-manager.js          # WebSocketリアルタイム同期
│       ├── passkey-manager.js       # Passkey/WebAuthn管理
│       ├── totp-manager.js          # TOTP 2FA管理
│       ├── login.js                 # ログインページロジック
│       ├── register.js              # 登録ページロジック
│       ├── crypto.js                # Web Crypto APIラッパー
│       ├── pdf-export.js            # PDFエクスポート
│       ├── comments-manager.js      # ページコメント機能
│       ├── account-manager.js       # アカウント管理
│       ├── cover-manager.js         # カバー画像管理
│       ├── drag-handle-extension.js # ドラッグハンドル拡張
│       ├── publish-manager.js       # ページ発行管理
│       ├── subpages-manager.js      # ページ階層管理
│       ├── shared-page.js           # 公開ページビューロジック
│       ├── login-logs-manager.js    # ログイン履歴管理
│       ├── board-node.js            # ボードビューブロック
│       ├── bookmark-node.js         # ブックマークブロック
│       ├── callout-node.js          # コールアウトブロック
│       ├── image-with-caption-node.js  # キャプション付き画像ブロック
│       ├── math-node.js             # LaTeX数式ブロック
│       ├── toggle-node.js           # トグルブロック
│       ├── youtube-node.js          # YouTube埋め込みブロック
│       ├── modal-parent-manager.js  # モーダル管理
│       ├── ui-utils.js              # UIユーティリティ
│       └── csrf-utils.js            # CSRFトークンユーティリティ
├── routes/                # APIルート
│   ├── index.js           # 静的ページと公開ページ
│   ├── auth.js            # 認証API
│   ├── pages.js           # ページCRUD同期API
│   ├── storages.js        # ストレージ管理API
│   ├── totp.js            # TOTP 2FA設定/検証API
│   ├── passkey.js         # Passkey/WebAuthn API
│   ├── backup.js          # バックアップ/復元API
│   ├── comments.js        # ページコメントAPI
│   ├── themes.js          # テーマ設定API
│   └── bootstrap.js       # 初期データベース設定
└── README.md
```

---

## キーワード

ノートアプリ、マークダウンエディタ、ウェブノート、E2EE、エンドツーエンド暗号化、暗号化ノート、セルフホスティング、オープンソースノート、Node.jsノートアプリ、MySQLノートアプリ、コラボレーティブノート、共有ノート、Tiptapエディタ、2段階認証、TOTP、Passkey、WebAuthn、リアルタイム同期、バックアップ/復元、レスポンシブノートアプリ、ウェブベースのノート、個人ノートサーバー、プライバシー重視のノート、セキュアなノート、カバー画像、Yjs

---

---

## 最近のセキュリティパッチおよびアップデート

### 2026-01-19 セキュリティパッチ

- **任意ファイル削除脆弱性の修正** - ファイルシステムアクセス制御の強化
- **SVGスクリプト実行脆弱性の防止** - 画像アップロード時のSVG形式を禁止
- **CDN/ESMモジュール完全性検証** - SRI(Subresource Integrity)を追加して供給チェーン脆弱性を防御
- **テーマファイルアップロード検証の強化** - 重複検証ロジックの実装

### 2026-01-18 バグ修正

- ブックマーク情報保存機能の復旧

---

## ライセンス

MIT License

---

## 開発者

RichardCYang
