
const acme = require('acme-client');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const https = require('https');
const semver = require('semver');

const CERT_DIR = path.join(__dirname, 'certs');

function getInstalledPackageVersion(pkgName) {
    try {
        let dir = path.dirname(require.resolve(pkgName));
        for (let i = 0; i < 6; i++) {
            const pkgJson = path.join(dir, 'package.json');
            if (fsSync.existsSync(pkgJson)) {
                const parsed = JSON.parse(fsSync.readFileSync(pkgJson, 'utf8'));
                if (parsed && parsed.name === pkgName && parsed.version) return parsed.version;
            }
            const parent = path.dirname(dir);
            if (parent === dir) break;
            dir = parent;
        }
    } catch (_) {}
    return null;
}

function assertSafeCryptoDeps() {
    const forgeVersion = getInstalledPackageVersion('node-forge');
    const coerced = semver.coerce(forgeVersion || '');
    if (!coerced || semver.lt(coerced, '1.4.0')) throw new Error(`[보안] 취약한 node-forge 버전이 감지되었습니다 (${forgeVersion || '알 수 없음'}). 인증서 자동화 기능을 사용하려면 node-forge 1.4.0 이상의 버전이 필요합니다.`);
}

const ACME_DIRECTORY_URL = acme.directory.letsencrypt.production;

async function setDuckDnsTxtRecord(domain, token, txtValue) {
    return new Promise((resolve, reject) => {
        const subdomain = domain.replace('.duckdns.org', '');

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

async function waitForDnsPropagation(seconds = 60) {
    console.log(`[DNS] DNS 전파 대기 중 (${seconds}초)...`);
    await new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

async function obtainCertificate(domain, duckdnsToken, email) {
    console.log('\n' + '='.repeat(80));
    console.log(`🔐 Let's Encrypt 인증서 발급 시작: ${domain}`);
    console.log('='.repeat(80) + '\n');

    try {
        await fs.mkdir(CERT_DIR, { recursive: true });

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

        const client = new acme.Client({
            directoryUrl: ACME_DIRECTORY_URL,
            accountKey: accountKey
        });

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

        console.log('[인증서] CSR 생성 중...');
        const [, csr] = await acme.crypto.createCsr({
            commonName: domain
        }, domainKey);

        console.log('[ACME] 인증서 주문 시작...');
        const cert = await client.auto({
            csr,
            email: email,
            termsOfServiceAgreed: true,
            challengePriority: ['dns-01'],
            challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                console.log('\n[Challenge] DNS-01 Challenge 시작');

                if (challenge.type === 'dns-01') {
                    const txtValue = keyAuthorization;

                    await setDuckDnsTxtRecord(domain, duckdnsToken, txtValue);

                    await waitForDnsPropagation(90); 
                }
            },
            challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
                console.log('\n[Challenge] DNS-01 Challenge 정리 중');

                if (challenge.type === 'dns-01') {
                    await clearDuckDnsTxtRecord(domain, duckdnsToken);
                }
            }
        });

        const certPath = path.join(CERT_DIR, 'certificate.pem');
        const chainPath = path.join(CERT_DIR, 'chain.pem');
        const fullchainPath = path.join(CERT_DIR, 'fullchain.pem');

        await fs.writeFile(certPath, cert);
        await fs.writeFile(fullchainPath, cert);

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

async function loadExistingCertificate() {
    try {
        const certPath = path.join(CERT_DIR, 'fullchain.pem');
        const keyPath = path.join(CERT_DIR, 'domain-key.pem');

        const cert = await fs.readFile(certPath);
        const key = await fs.readFile(keyPath);

        const certInfo = await acme.crypto.readCertificateInfo(cert);
        const expiryDate = new Date(certInfo.notAfter);
        const daysUntilExpiry = Math.floor((expiryDate - new Date()) / (1000 * 60 * 60 * 24));

        console.log('\n' + '='.repeat(80));
        console.log('📜 기존 인증서 발견');
        console.log(`   - 만료일: ${expiryDate.toISOString()}`);
        console.log(`   - 남은 기간: ${daysUntilExpiry}일`);
        console.log('='.repeat(80) + '\n');

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

async function getCertificate(domain, duckdnsToken, email = 'admin@example.com') {
    assertSafeCryptoDeps();
    const existing = await loadExistingCertificate();

    if (existing) {
        console.log('✅ 기존 인증서 사용');
        return existing;
    }

    return await obtainCertificate(domain, duckdnsToken, email);
}

function scheduleRenewal(domain, duckdnsToken, email, renewalCallback) {
    assertSafeCryptoDeps();
    const checkInterval = 24 * 60 * 60 * 1000; 

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
