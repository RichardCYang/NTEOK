/**
 * HTTPS 인증서 자동 발급 및 관리 모듈
 * Let's Encrypt + DuckDNS DNS Challenge
 */

const acme = require('acme-client');
const fs = require('fs').promises;
const path = require('path');
const https = require('https');

// 인증서 저장 디렉토리
const CERT_DIR = path.join(__dirname, 'certs');

// Let's Encrypt 디렉토리 URL (프로덕션)
const ACME_DIRECTORY_URL = acme.directory.letsencrypt.production;
// 테스트용: acme.directory.letsencrypt.staging

/**
 * DuckDNS API를 통해 TXT 레코드 설정
 */
async function setDuckDnsTxtRecord(domain, token, txtValue) {
    return new Promise((resolve, reject) => {
        // DuckDNS 도메인에서 서브도메인만 추출 (예: example.duckdns.org -> example)
        const subdomain = domain.replace('.duckdns.org', '');

        // DuckDNS API URL
        const url = `https://www.duckdns.org/update?domains=${subdomain}&token=${token}&txt=${encodeURIComponent(txtValue)}`;

        console.log(`[DuckDNS] TXT 레코드 설정 중: ${domain}`);

        https.get(url, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                if (data.trim() === 'OK') {
                    console.log(`[DuckDNS] TXT 레코드 설정 성공`);
                    resolve();
                } else {
                    reject(new Error(`DuckDNS API 실패: ${data}`));
                }
            });
        }).on('error', reject);
    });
}

/**
 * DuckDNS TXT 레코드 삭제 (빈 값으로 설정)
 */
async function clearDuckDnsTxtRecord(domain, token) {
    return new Promise((resolve, reject) => {
        const subdomain = domain.replace('.duckdns.org', '');
        const url = `https://www.duckdns.org/update?domains=${subdomain}&token=${token}&txt=&clear=true`;

        console.log(`[DuckDNS] TXT 레코드 삭제 중`);

        https.get(url, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                if (data.trim() === 'OK') {
                    console.log(`[DuckDNS] TXT 레코드 삭제 성공`);
                    resolve();
                } else {
                    reject(new Error(`DuckDNS API 실패: ${data}`));
                }
            });
        }).on('error', reject);
    });
}

/**
 * DNS 전파 대기 (최대 5분)
 */
async function waitForDnsPropagation(seconds = 60) {
    console.log(`[DNS] DNS 전파 대기 중 (${seconds}초)...`);
    await new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

/**
 * Let's Encrypt 인증서 발급
 */
async function obtainCertificate(domain, duckdnsToken, email) {
    console.log('\n' + '='.repeat(80));
    console.log(`🔐 Let's Encrypt 인증서 발급 시작: ${domain}`);
    console.log('='.repeat(80) + '\n');

    try {
        // 인증서 디렉토리 생성
        await fs.mkdir(CERT_DIR, { recursive: true });

        // ACME 클라이언트 개인키 생성 또는 로드
        const accountKeyPath = path.join(CERT_DIR, 'account-key.pem');
        let accountKey;

        try {
            accountKey = await fs.readFile(accountKeyPath);
            console.log('[ACME] 기존 계정 키 로드됨');
        } catch (err) {
            console.log('[ACME] 새 계정 키 생성 중...');
            accountKey = await acme.crypto.createPrivateKey();
            await fs.writeFile(accountKeyPath, accountKey);
            console.log('[ACME] 계정 키 저장 완료');
        }

        // ACME 클라이언트 초기화
        const client = new acme.Client({
            directoryUrl: ACME_DIRECTORY_URL,
            accountKey: accountKey
        });

        // 도메인 개인키 생성 또는 로드
        const domainKeyPath = path.join(CERT_DIR, 'domain-key.pem');
        let domainKey;

        try {
            domainKey = await fs.readFile(domainKeyPath);
            console.log('[인증서] 기존 도메인 키 로드됨');
        } catch (err) {
            console.log('[인증서] 새 도메인 키 생성 중...');
            const [key] = await acme.crypto.createCsr({
                commonName: domain
            });
            domainKey = key;
            await fs.writeFile(domainKeyPath, domainKey);
            console.log('[인증서] 도메인 키 저장 완료');
        }

        // CSR 생성
        console.log('[인증서] CSR 생성 중...');
        const [, csr] = await acme.crypto.createCsr({
            commonName: domain
        }, domainKey);

        // 인증서 발급 요청
        console.log('[ACME] 인증서 주문 시작...');
        const cert = await client.auto({
            csr,
            email: email,
            termsOfServiceAgreed: true,
            challengePriority: ['dns-01'],
            challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                console.log('\n[Challenge] DNS-01 Challenge 시작');

                if (challenge.type === 'dns-01') {
                    // DNS TXT 레코드 값 생성
                    const txtValue = keyAuthorization;

                    // DuckDNS에 TXT 레코드 설정
                    await setDuckDnsTxtRecord(domain, duckdnsToken, txtValue);

                    // DNS 전파 대기
                    await waitForDnsPropagation(90); // 90초 대기
                }
            },
            challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
                console.log('\n[Challenge] DNS-01 Challenge 정리 중');

                if (challenge.type === 'dns-01') {
                    // DuckDNS TXT 레코드 삭제
                    await clearDuckDnsTxtRecord(domain, duckdnsToken);
                }
            }
        });

        // 인증서 저장
        const certPath = path.join(CERT_DIR, 'certificate.pem');
        const chainPath = path.join(CERT_DIR, 'chain.pem');
        const fullchainPath = path.join(CERT_DIR, 'fullchain.pem');

        await fs.writeFile(certPath, cert);
        await fs.writeFile(fullchainPath, cert);

        // 체인 파일 분리 (옵션)
        const certLines = cert.toString().split('\n');
        const firstCertEnd = certLines.indexOf('-----END CERTIFICATE-----');
        if (firstCertEnd !== -1 && firstCertEnd < certLines.length - 1) {
            const chain = certLines.slice(firstCertEnd + 1).join('\n');
            await fs.writeFile(chainPath, chain);
        }

        console.log('\n' + '='.repeat(80));
        console.log('✅ Let\'s Encrypt 인증서 발급 성공!');
        console.log(`   - 인증서: ${certPath}`);
        console.log(`   - 전체 체인: ${fullchainPath}`);
        console.log(`   - 개인키: ${domainKeyPath}`);
        console.log('='.repeat(80) + '\n');

        return {
            cert: cert,
            key: domainKey,
            certPath,
            keyPath: domainKeyPath,
            fullchainPath
        };

    } catch (error) {
        console.error('\n' + '='.repeat(80));
        console.error('❌ 인증서 발급 실패:', error.message);
        console.error('='.repeat(80) + '\n');
        throw error;
    }
}

/**
 * 기존 인증서 로드
 */
async function loadExistingCertificate() {
    try {
        const certPath = path.join(CERT_DIR, 'fullchain.pem');
        const keyPath = path.join(CERT_DIR, 'domain-key.pem');

        const cert = await fs.readFile(certPath);
        const key = await fs.readFile(keyPath);

        // 인증서 만료일 확인
        const certInfo = await acme.crypto.readCertificateInfo(cert);
        const expiryDate = new Date(certInfo.notAfter);
        const daysUntilExpiry = Math.floor((expiryDate - new Date()) / (1000 * 60 * 60 * 24));

        console.log('\n' + '='.repeat(80));
        console.log('📜 기존 인증서 발견');
        console.log(`   - 만료일: ${expiryDate.toISOString()}`);
        console.log(`   - 남은 기간: ${daysUntilExpiry}일`);
        console.log('='.repeat(80) + '\n');

        // 30일 이내 만료 시 갱신 필요
        if (daysUntilExpiry < 30) {
            console.log('⚠️  인증서가 곧 만료됩니다. 갱신이 필요합니다.');
            return null;
        }

        return {
            cert,
            key,
            certPath,
            keyPath,
            expiryDate,
            daysUntilExpiry
        };
    } catch (error) {
        console.log('[인증서] 기존 인증서를 찾을 수 없습니다. 새로 발급합니다.');
        return null;
    }
}

/**
 * HTTPS 인증서 가져오기 (자동 발급/갱신)
 */
async function getCertificate(domain, duckdnsToken, email = 'admin@example.com') {
    // 기존 인증서 확인
    const existing = await loadExistingCertificate();

    if (existing) {
        console.log('✅ 기존 인증서 사용');
        return existing;
    }

    // 새 인증서 발급
    return await obtainCertificate(domain, duckdnsToken, email);
}

/**
 * 인증서 자동 갱신 스케줄러 (매일 체크)
 */
function scheduleRenewal(domain, duckdnsToken, email, renewalCallback) {
    const checkInterval = 24 * 60 * 60 * 1000; // 24시간

    setInterval(async () => {
        console.log('\n[갱신 체크] 인증서 만료일 확인 중...');

        try {
            const existing = await loadExistingCertificate();

            if (!existing || existing.daysUntilExpiry < 30) {
                console.log('[갱신] 인증서 갱신 시작...');
                const newCert = await obtainCertificate(domain, duckdnsToken, email);

                if (renewalCallback) {
                    renewalCallback(newCert);
                }
            } else {
                console.log(`[갱신 체크] 인증서 유효 (만료까지 ${existing.daysUntilExpiry}일)`);
            }
        } catch (error) {
            console.error('[갱신 체크] 오류:', error.message);
        }
    }, checkInterval);

    console.log('[갱신 스케줄러] 자동 갱신 스케줄러 시작 (24시간 주기)');
}

module.exports = {
    getCertificate,
    scheduleRenewal,
    loadExistingCertificate
};
