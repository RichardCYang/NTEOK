// TipTap TrustedHTML 패치
(function() {
    // TrustedTypes 정책이 없는 경우 생성
    if (window.trustedTypes && !window.__nteokTrustedTypesPolicy) {
        try {
            window.__nteokTrustedTypesPolicy = window.trustedTypes.createPolicy('nteok-sanitize', {
                createHTML: (input) => {
                    // 간단한 sanitization
                    const str = String(input || '');
                    // 기본적인 위험 태그 제거
                    return str.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                              .replace(/javascript:/gi, '')
                              .replace(/on\w+\s*=/gi, '');
                }
            });
        } catch (e) {
            console.warn('TrustedTypes 정책 생성 실패:', e);
        }
    }
    
    // DOMParser.parseFromString을 감싸서 TrustedHTML 사용
    const originalParseFromString = DOMParser.prototype.parseFromString;
    
    DOMParser.prototype.parseFromString = function(string, type) {
        // TrustedHTML 정책이 있고 문자열이 TrustedHTML이 아닌 경우
        if (window.trustedTypes && typeof string === 'string' && !(string instanceof TrustedHTML)) {
            try {
                // 기본 정책 사용 시도
                if (window.__nteokTrustedTypesPolicy) {
                    string = window.__nteokTrustedTypesPolicy.createHTML(string);
                } else if (window.trustedTypes.defaultPolicy) {
                    string = window.trustedTypes.defaultPolicy.createHTML(string);
                } else {
                    // 기본 정책 생성
                    const defaultPolicy = window.trustedTypes.createPolicy('default', {
                        createHTML: (s) => s
                    });
                    string = defaultPolicy.createHTML(string);
                }
            } catch (e) {
                console.warn('TrustedHTML 생성 실패:', e);
            }
        }
        return originalParseFromString.call(this, string, type);
    };
    
    // Element.innerHTML 설정도 패치
    const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    
    if (originalInnerHTML && originalInnerHTML.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                if (window.trustedTypes && typeof value === 'string' && !(value instanceof TrustedHTML)) {
                    try {
                        if (window.__nteokTrustedTypesPolicy) {
                            value = window.__nteokTrustedTypesPolicy.createHTML(value);
                        } else if (window.trustedTypes.defaultPolicy) {
                            value = window.trustedTypes.defaultPolicy.createHTML(value);
                        }
                    } catch (e) {
                        console.warn('innerHTML TrustedHTML 변환 실패:', e);
                    }
                }
                originalInnerHTML.set.call(this, value);
            },
            get: originalInnerHTML.get
        });
    }
    
    console.log('TipTap TrustedHTML 패치 적용됨');
})();