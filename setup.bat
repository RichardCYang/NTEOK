@echo off
:: UTF-8 인코딩으로 설정하여 한글 깨짐 방지
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ===================================================
echo   NTEOK 운영 환경 설정 도우미 (Windows)
echo ===================================================
echo.
echo 이 스크립트는 운영에 필요한 정보를 입력받아 
echo .env 파일을 생성합니다.
echo.

set /p NODE_ENV="[1/10] 운영 모드 (production/development, 기본: production): "
if "!NODE_ENV!"=="" set NODE_ENV=production

set /p DB_HOST="[2/10] 데이터베이스 호스트 (기본: localhost): "
if "!DB_HOST!"=="" set DB_HOST=localhost

set /p DB_PORT="[3/10] 데이터베이스 포트 (기본: 3306): "
if "!DB_PORT!"=="" set DB_PORT=3306

set /p DB_USER="[4/10] 데이터베이스 사용자명: "
set /p DB_PASSWORD="[5/10] 데이터베이스 비밀번호: "
set /p DB_NAME="[6/10] 데이터베이스 이름 (기본: nteok): "
if "!DB_NAME!"=="" set DB_NAME=nteok

set /p ADMIN_USERNAME="[7/10] 관리자 계정 아이디 (기본: admin): "
if "!ADMIN_USERNAME!"=="" set ADMIN_USERNAME=admin

echo [!] 비밀번호를 입력하지 않고 엔터를 누르면 보안 비밀번호가 자동 생성됩니다.
set /p ADMIN_PASSWORD="[8/10] 관리자 계정 비밀번호: "
if "!ADMIN_PASSWORD!"=="" (
    for /f "delims=" %%a in ('powershell -NoProfile -Command "$bytes = New-Object Byte[] 16; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes); [Convert]::ToBase64String($bytes)"') do set "ADMIN_PASSWORD=%%a"
    echo [정보] 관리자 비밀번호가 자동으로 생성되었습니다: !ADMIN_PASSWORD!
)

:: HTTPS 설정 여부 확인
set /p USE_HTTPS="[9/10] DuckDNS를 통한 HTTPS를 사용하시겠습니까? (Y/N, 기본: N): "
if /i "!USE_HTTPS!"=="Y" (
    set /p DUCKDNS_DOMAIN="   - DuckDNS 도메인 (예: myapp.duckdns.org): "
    set /p DUCKDNS_TOKEN="   - DuckDNS API 토큰: "
    set /p CERT_EMAIL="   - Let's Encrypt 알림 이메일: "
    set PORT=443
    set BASE_URL=https://!DUCKDNS_DOMAIN!
    set ENABLE_HTTP_REDIRECT=true
) else (
    set /p BASE_URL="[10/10] 서비스 URL (예: http://localhost:3000): "
    if "!BASE_URL!"=="" set BASE_URL=http://localhost:3000
    set PORT=3000
    set ENABLE_HTTP_REDIRECT=false
)

:: TOTP 암호화 키 생성 (CSPRNG 사용)
for /f "delims=" %%a in ('powershell -NoProfile -Command "$bytes = New-Object Byte[] 32; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes); [Convert]::ToBase64String($bytes)"') do set "TOTP_KEY=%%a"

echo.
echo .env 파일을 생성 중입니다...

:: 파일 생성 (괄호 문제를 피하기 위해 한 줄씩 출력)
echo # 자동 생성된 환경 설정 > .env
echo NODE_ENV=!NODE_ENV! >> .env
echo PORT=!PORT! >> .env
echo. >> .env
echo DB_HOST=!DB_HOST! >> .env
echo DB_PORT=!DB_PORT! >> .env
echo DB_USER=!DB_USER! >> .env
echo DB_PASSWORD=!DB_PASSWORD! >> .env
echo DB_NAME=!DB_NAME! >> .env
echo. >> .env
echo ADMIN_USERNAME=!ADMIN_USERNAME! >> .env
echo ADMIN_PASSWORD=!ADMIN_PASSWORD! >> .env
echo. >> .env
echo BASE_URL=!BASE_URL! >> .env
echo. >> .env

if /i "!USE_HTTPS!"=="Y" (
    echo # HTTPS DuckDNS 설정 >> .env
    echo DUCKDNS_DOMAIN=!DUCKDNS_DOMAIN! >> .env
    echo DUCKDNS_TOKEN=!DUCKDNS_TOKEN! >> .env
    echo CERT_EMAIL=!CERT_EMAIL! >> .env
    echo ENABLE_HTTP_REDIRECT=!ENABLE_HTTP_REDIRECT! >> .env
    echo. >> .env
)

echo # 보안을 위해 자동 생성된 TOTP 암호화 키 >> .env
echo TOTP_SECRET_ENC_KEY=!TOTP_KEY! >> .env

echo.
echo [성공] .env 파일이 생성되었습니다! (모드: !NODE_ENV!, 포트: !PORT!)
echo.
echo ---------------------------------------------------
echo   백그라운드 실행 및 종료 방법 (Windows)
echo ---------------------------------------------------
echo.
echo [실행하기]
echo 1. PM2 설치: npm install -g pm2
echo 2. 서버 시작: pm2 start server.js --name nteok
echo.
echo [종료하기]
echo 1. 서버 중단: pm2 stop nteok
echo 2. 리스트 삭제: pm2 delete nteok
echo.
echo ---------------------------------------------------
echo.
pause
