#!/bin/bash

echo "==================================================="
echo "  NTEOK 운영 환경 설정 도우미 (Linux/macOS)"
echo "==================================================="
echo ""

read -p "[1/10] 운영 모드 (production/development, 기본: production): " NODE_ENV
NODE_ENV=${NODE_ENV:-production}

read -p "[2/10] 데이터베이스 호스트 (기본: localhost): " DB_HOST
DB_HOST=${DB_HOST:-localhost}

read -p "[3/10] 데이터베이스 포트 (기본: 3306): " DB_PORT
DB_PORT=${DB_PORT:-3306}

read -p "[4/10] 데이터베이스 사용자명: " DB_USER
read -s -p "[5/10] 데이터베이스 비밀번호: " DB_PASSWORD
echo ""

read -p "[6/10] 데이터베이스 이름 (기본: nteok): " DB_NAME
DB_NAME=${DB_NAME:-nteok}

read -p "[7/10] 관리자 계정 아이디 (기본: admin): " ADMIN_USERNAME
ADMIN_USERNAME=${ADMIN_USERNAME:-admin}

echo "[!] 비밀번호를 입력하지 않고 엔터를 누르면 보안 비밀번호가 자동 생성됩니다."
read -s -p "[8/10] 관리자 계정 비밀번호: " ADMIN_PASSWORD
echo ""

if [ -z "$ADMIN_PASSWORD" ]; then
    if command -v openssl >/dev/null 2>&1; then
        ADMIN_PASSWORD=$(openssl rand -base64 16)
    else
        ADMIN_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
    fi
    echo "[정보] 관리자 비밀번호가 자동으로 생성되었습니다: $ADMIN_PASSWORD"
fi

# HTTPS 설정 여부 확인
read -p "[9/10] DuckDNS를 통한 HTTPS를 사용하시겠습니까? (Y/N, 기본: N): " USE_HTTPS
if [[ "$USE_HTTPS" =~ ^[Yy]$ ]]; then
    read -p "   - DuckDNS 도메인 (예: myapp.duckdns.org): " DUCKDNS_DOMAIN
    read -p "   - DuckDNS API 토큰: " DUCKDNS_TOKEN
    read -p "   - Let's Encrypt 알림 이메일: " CERT_EMAIL
    PORT=443
    BASE_URL="https://$DUCKDNS_DOMAIN"
    ENABLE_HTTP_REDIRECT=true
else
    read -p "[10/10] 서비스 URL (예: http://localhost:3000): " BASE_URL
    BASE_URL=${BASE_URL:-http://localhost:3000}
    PORT=3000
    ENABLE_HTTP_REDIRECT=false
fi

# TOTP 암호화 키 생성 (CSPRNG)
if command -v openssl >/dev/null 2>&1; then
    TOTP_KEY=$(openssl rand -base64 32)
else
    TOTP_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
fi

echo ""
echo ".env 파일을 생성 중입니다..."

cat <<EOF > .env
# 자동 생성된 환경 설정
NODE_ENV=$NODE_ENV
PORT=$PORT

DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_NAME=$DB_NAME

ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD=$ADMIN_PASSWORD

BASE_URL=$BASE_URL

$(if [[ "$USE_HTTPS" =~ ^[Yy]$ ]]; then
echo "# HTTPS (DuckDNS) 설정"
echo "DUCKDNS_DOMAIN=$DUCKDNS_DOMAIN"
echo "DUCKDNS_TOKEN=$DUCKDNS_TOKEN"
echo "CERT_EMAIL=$CERT_EMAIL"
echo "ENABLE_HTTP_REDIRECT=$ENABLE_HTTP_REDIRECT"
echo ""
fi)
# 보안을 위해 자동 생성된 TOTP 암호화 키
TOTP_SECRET_ENC_KEY=$TOTP_KEY
EOF

echo ""
echo "[성공] .env 파일이 생성되었습니다! (모드: $NODE_ENV, 포트: $PORT)"
echo ""
echo "---------------------------------------------------"
echo "  백그라운드 실행 및 종료 방법 (Linux/macOS)"
echo "---------------------------------------------------"
echo ""
echo "방법 1: nohup (종료: pkill -f \"node server.js\")"
echo "방법 2: tmux (종료: tmux kill-session -t nteok)"
echo "방법 3: PM2 (종료: pm2 delete nteok)"
echo "---------------------------------------------------"
echo ""
