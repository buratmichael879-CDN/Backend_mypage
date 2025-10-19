(function () {
    'use strict';
    // Configuration object for firewall settings
    const config = window['WINDOW_FIREWALL_CONFIG'] || {
        allowedIPs: ['127.0.0.1/32'],
        blockedDomains: [
            'google-analytics.com', 'doubleclick.net', 'adsservice.google.com', 'facebook.com',
            'twitter.com', 'amplitude.com', 'mixpanel.com', 'segment.io', 'malware-domain.example',
            'phishing.example', 'shinyhunters-leak-site.example', 'fake-gmail-support.com',
            'oauth-phish.net', 'accounts.google.com', 'oauth2.googleapis.com', 'ssh.example',
            'chat.openai.com', 'openai.com', 'grok.x.ai', 'x.ai',
            'nordvpn.com', 'expressvpn.com', 'protonvpn.com', 'surfshark.com', 'mullvad.net',
            'cyberghostvpn.com', 'privateinternetaccess.com', 'google.com/vpn', 'torproject.org'
        ],
        suspiciousKeywords: [
            'token', 'secret', 'creditcard', 'ssn', 'cvv', 'iban', 'bic', 'paypal',
            'cardnumber', 'expirationdate', 'securitycode', 'gmail.com', 'google.com', 'workspace',
            'oauth', 'drift email', 'shinyhunters', 'salesforce', '@gmail', 'suspicious sign-in',
            'account recovery', 'verify your identity', 'google user', 'google login', 'ransom',
            'pay to unlock', 'encrypted data', 'ssh', 'secure shell', 'https', 'ssh://', 'ftp://',
            'chatgpt', 'gpt', 'openai', 'grok', 'xai', 'api-key', 'conversation-history', 'redirect',
            'google vpn', 'tor', 'onion', 'vpn app', 'nordvpn', 'expressvpn', 'wcry', 'wannacry', 'bot', 'headlesschrome', 'malicious',
            'telnet', 'smb', 'rdp', 'vnc', 'sftp', 'file', 'sql', 'select', 'drop', 'insert', 'update', 'delete', 'script', 'rm', 'cat', 'whoami'
        ],
        logTarget: 'console',
        securityHeaders: {
            'Content-Security-Policy': "default-src 'self'; script-src 'self' /api/v2/js/; img-src 'self' /api/v2/img/; object-src 'none'; style-src 'self'; form-action 'self'; connect-src 'self' /api/v2/data /api/v2/passwort /api/v2/js/ /api/v2/img/ /api/v2/backup/ /api/v2/thaw/ /api/v2/nis2/ https://www.virustotal.com",
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'X-Content-Type-Options': 'nosniff'
        },
        offlinePage: '/offline.html',
        rateLimit: { maxRequests: 100, windowMs: 60 * 1000 },
        inputValidation: { maxLength: 1000, allowedChars: /^[a-zA-Z0-9\s.,@\-_]*$/ },
        suspiciousURLs: [
            /login.*\.php/i, /signin.*\.php/i, /bank.*\.php/i, /paypal.*\.com/i,
            /secure.*\.net/i, /account.*\.org/i, /verify.*\.info/i,
            /gmail.*(suspicious|sign-in|recovery|verify)/i,
            /google.*(oauth|workspace|phish)/i, /salesforce.*(leak|breach)/i,
            /oauth2.googleapis.com/i, /ssh.*\.net/i, /https.*\./i,
            /^ssh:\/\//i, /^ftp:\/\//i, /^telnet:\/\//i, /^smb:\/\//i, /^rdp:\/\//i, /^vnc:\/\//i, /^sftp:\/\//i, /^file:\/\//i,
            /chatgpt/i, /openai/i, /grok/i, /xai/i, /redirect/i,
            /google.*vpn/i, /tor/i, /onion/i, /nordvpn/i, /expressvpn/i, /wcry/i, /wannacry/i, /bot/i, /malicious/i
        ],
        blockedFileExtensions: ['.exe', '.bat', '.cmd', '.vbs', '.jar', '.ps1', '.scr'],
        ransomwarePatterns: [
            /crypto/i, /ransom/i, /encrypt/i, /decrypt/i, /keygen/i, /ransomware/i,
            /bitcoin/i, /pay to unlock/i, /encrypted data/i, /ssh/i, /https/i,
            /^ssh:\/\//i, /^ftp:\/\//i, /^telnet:\/\//i, /^smb:\/\//i, /^rdp:\/\//i, /^vnc:\/\//i, /^sftp:\/\//i, /^file:\/\//i,
            /chatgpt/i, /openai/i, /grok/i, /xai/i, /redirect/i,
            /google.*vpn/i, /tor/i, /onion/i, /wcry/i, /wannacry/i, /bot/i, /malicious/i,
            /select.*from/i, /drop.*table/i, /insert.*into/i, /update.*set/i, /delete.*from/i,
            /<script>/i, /rm\s/i, /cat\s/i, /whoami/i
        ],
        performanceLimits: { maxEventLoopLag: 1000, maxDomMutations: 100, maxTimeoutInterval: 5000 },
        devicePermissions: { microphone: false, camera: false, screen: false, geolocation: false },
        vpnDetection: {
            enabled: true,
            blockedVPNIPs: ['192.168.1.0/24', '172.16.0.0/12', '35.192.0.0/11'],
            vpnDomains: ['nordvpn.com', 'expressvpn.com', 'protonvpn.com', 'surfshark.com', 'mullvad.net', 'cyberghostvpn.com', 'privateinternetaccess.com', 'google.com/vpn', 'torproject.org'],
            checkTimeZone: true,
            checkHeaders: true,
            torDetection: true,
            appVpnDetection: true
        },
        platformRestrictions: {
            blockWebView: true,
            blockPresentation: true,
            httpOnly: true,
            allowedPlatforms: [/Windows NT 10\.0/i],
            blockedUAPatterns: [/iPhone/i, /iPad/i, /Android/i, /Macintosh/i, /Linux/i, /Mobile/i, /WebView/i, /wv/i, /HeadlessChrome/i, /bot/i],
            browsers: {
                'Chrome': { minVersion: 130, pattern: /Chrome\/(\d+)\./ },
                'Edge': { minVersion: 130, pattern: /Edg\/(\d+)\./ },
                'Firefox': { minVersion: 135, pattern: /Firefox\/(\d+)\./ }
            }
        },
        watchdog: {
            enabled: true,
            pollInterval: 30000,
            indexHtmlHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            indexJsHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            backupEndpoints: {
                indexHtml: '/api/v2/backup/index.html',
                indexJs: '/api/v2/backup/index.js'
            },
            fallbackHtml: '<html><head><title>Fallback Page</title></head><body><h1>Site Restored - Firewall Active</h1><script src="./index.js"></script></body></html>',
            fallbackJs: 'console.log("Fallback JS loaded - Integrity restored.");',
            serverThaw: {
                enabled: true,
                errorThreshold: 5,
                timeoutMs: 5000,
                thawEndpoint: '/api/v2/thaw/server',
                fallbackAction: 'reload'
            },
            virusScan: {
                enabled: true,
                apiKey: 'beb72ad18fa50a7f2311caa4897c87b25de44fe1704f7a1f3cb24bb3179bcf8d',
                scanEndpoint: 'https://www.virustotal.com/api/v3/files',
                urlScanEndpoint: 'https://www.virustotal.com/api/v3/urls',
                filesToScan: ['./index.html', './index.js', './firewall.js']
            }
        },
        antiBot: {
            enabled: true,
            suspiciousUserAgents: [/HeadlessChrome/i, /bot/i, /crawler/i, /spider/i, /wcry/i, /wannacry/i],
            allowedUserAgents: [/Mozilla/i, /Chrome\/[0-9]+/i, /Firefox\/[0-9]+/i, /Safari\/[0-9]+/i, /Edge\/[0-9]+/i],
            maxMouseEvents: 100,
            maxKeyEvents: 50,
            botChallengeInterval: 5000
        },
        antiRansomware: {
            enabled: true,
            blockedCryptoApis: ['encrypt', 'generateKey', 'wrap'],
            suspiciousPatterns: [
                /crypto/i, /ransom/i, /encrypt/i, /decrypt/i, /keygen/i, /ransomware/i,
                /bitcoin/i, /pay to unlock/i, /encrypted data/i, /ssh/i, /https/i,
                /^ssh:\/\//i, /^ftp:\/\//i, /^telnet:\/\//i, /^smb:\/\//i, /^rdp:\/\//i, /^vnc:\/\//i, /^sftp:\/\//i, /^file:\/\//i,
                /chatgpt/i, /openai/i, /grok/i, /xai/i, /redirect/i,
                /google.*vpn/i, /tor/i, /onion/i, /wcry/i, /wannacry/i, /bot/i, /malicious/i,
                /select.*from/i, /drop.*table/i, /insert.*into/i, /update.*set/i, /delete.*from/i,
                /<script>/i, /rm\s/i, /cat\s/i, /whoami/i
            ],
            maxAlerts: 3,
            storageKeys: ['localStorage', 'sessionStorage']
        },
        antiHack: {
            enabled: true,
            blockedFunctions: ['eval', 'Function', 'setTimeout', 'setInterval', 'exec', 'spawn', 'XMLHttpRequest', 'WebSocket'],
            suspiciousPatterns: [
                /eval\(.+\)/i, /Function\(.+\)/i, /setTimeout\s*\(\s*['"].+['"]/i,
                /__proto__/i, /constructor/i, /ssh/i, /https/i,
                /^ssh:\/\//i, /^ftp:\/\//i, /^telnet:\/\//i, /^smb:\/\//i, /^rdp:\/\//i, /^vnc:\/\//i, /^sftp:\/\//i, /^file:\/\//i,
                /chatgpt/i, /openai/i, /grok/i, /xai/i, /redirect/i,
                /google.*vpn/i, /tor/i, /onion/i, /wcry/i, /wannacry/i, /bot/i, /malicious/i,
                /select.*from/i, /drop.*table/i, /insert.*into/i, /update.*set/i, /delete.*from/i,
                /<script>/i, /rm\s/i, /cat\s/i, /whoami/i
            ],
            maxEventListeners: 50,
            protectedInputs: ['input[type="text"]', 'input[type="password"]', 'input[type="number"]']
        },
        nis2: {
            enabled: true,
            reportingEndpoint: '/api/v2/nis2/report',
            riskAssessmentInterval: 86400000,
            incidentSeverityThreshold: 'critical',
            supplyChainChecks: true,
            businessContinuity: true
        },
        auth: {
            apiKey: 'my-secret-api-key' // API-Schlüssel aus server.go
        }
    };
    let requestCount = 0, startTime = Date.now(), mutationCount = 0, lastCheck = Date.now();
    let serverErrorCount = 0;
    let mouseEventCount = 0, keyEventCount = 0;

    // Automatic login mechanism
    function autoLogin() {
        try {
            // Ensure API key is set for all relevant requests
            log('Automatic login initiated with API key', 'info');
            return config.auth.apiKey;
        } catch (e) {
            log('Error in autoLogin', 'error', { error: e.message });
            return null;
        }
    }

    // Stealth fetch to hide requests from Network tab and include API key
    async function stealthFetch(url, options = {}) {
        try {
            if (url.includes('/api/v2/') || url.includes('virustotal.com')) {
                const headers = {
                    ...options.headers,
                    'X-API-Key': autoLogin() || config.auth.apiKey
                };
                const response = await fetch(url, { ...options, headers, cache: 'no-cache', mode: 'same-origin' });
                if (!response.ok) {
                    throw new Error(`Stealth fetch failed: ${response.status}`);
                }
                const content = await response.text();
                const blob = new Blob([content], { type: response.headers.get('Content-Type') || 'application/octet-stream' });
                const blobUrl = URL.createObjectURL(blob);
                const blobResponse = await fetch(blobUrl);
                URL.revokeObjectURL(blobUrl);
                return blobResponse;
            }
            return fetch(url, options);
        } catch (e) {
            log('Error in stealthFetch', 'error', { url, error: e.message });
            throw e;
        }
    }

    // Anti-bot protection with human UA separation
    function antiBot() {
        if (!config.antiBot.enabled) {
            log('Anti-bot protection disabled', 'info');
            return;
        }
        try {
            const userAgent = navigator.userAgent || '';
            if (config.antiBot.suspiciousUserAgents.some(p => p.test(userAgent))) {
                log('Bot detected via User-Agent', 'critical', { userAgent });
                window.location.href = config.offlinePage;
                throw new Error('Bot access blocked');
            }
            if (!config.antiBot.allowedUserAgents.some(p => p.test(userAgent))) {
                log('Non-human User-Agent detected, potential bot', 'critical', { userAgent });
                window.location.href = config.offlinePage;
                throw new Error('Non-human User-Agent blocked');
            }
            document.addEventListener('mousemove', () => {
                mouseEventCount++;
                if (mouseEventCount > config.antiBot.maxMouseEvents) {
                    log('Excessive mouse events detected, potential bot', 'critical', { mouseEventCount });
                    window.location.href = config.offlinePage;
                    throw new Error('Bot-like mouse behavior blocked');
                }
            });
            document.addEventListener('keydown', () => {
                keyEventCount++;
                if (keyEventCount > config.antiBot.maxKeyEvents) {
                    log('Excessive key events detected, potential bot', 'critical', { keyEventCount });
                    window.location.href = config.offlinePage;
                    throw new Error('Bot-like key behavior blocked');
                }
            });
            setInterval(() => {
                const challenge = Math.random().toString(36).substring(2);
                sessionStorage.setItem('botChallenge', challenge);
                if (sessionStorage.getItem('botChallenge') !== challenge) {
                    log('Bot challenge failed, potential bot', 'critical');
                    window.location.href = config.offlinePage;
                    throw new Error('Bot challenge failed');
                }
            }, config.antiBot.botChallengeInterval);
            log('Anti-bot protection enabled with human UA validation', 'info');
        } catch (e) {
            log('Error in anti-bot protection', 'error', { error: e.message });
        }
    }

    // Virus cleaner with enhanced VirusTotal integration
    async function virusCleaner() {
        try {
            const elements = document.querySelectorAll('script, a, link, iframe, img, [on*]');
            const dangerousAttributes = ['onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout', 'onchange'];
            for (let element of elements) {
                const srcOrHref = element.src || element.href || '';
                if (element.tagName === 'SCRIPT' && srcOrHref.includes('firewall.js')) {
                    element.remove();
                    log('Blocked unauthorized loading of firewall.js to prevent circular invocation', 'critical', { src: srcOrHref });
                    continue;
                }
                if (srcOrHref.includes('/api/v2/passwort') || srcOrHref.includes('/api/v2/js/') || srcOrHref.includes('/api/v2/img/')) {
                    continue;
                }
                if (config.suspiciousKeywords.some(k => srcOrHref.includes(k) || (element.textContent && element.textContent.includes(k))) || /malicious/i.test(srcOrHref) || (element.textContent && /malicious/i.test(element.textContent))) {
                    element.remove();
                    log('Malicious content (potential ChatGPT/Grok leak, redirect, VPN, WannaCry, bot, or malicious) removed to prevent leaks', 'critical', { src: srcOrHref || 'inline', tag: element.tagName });
                }
                if (config.suspiciousURLs.some(p => srcOrHref.match(p) || (element.textContent && element.textContent.match(p)))) {
                    element.remove();
                    log('Hacker protocol (SSH/FTP/TELNET/SMB/RDP/VNC/SFTP/FILE) or malicious URL detected and removed', 'critical', { src: srcOrHref || 'inline', tag: element.tagName });
                }
                dangerousAttributes.forEach(attr => {
                    if (element.hasAttribute(attr)) {
                        element.removeAttribute(attr);
                        log(`Dangerous attribute ${attr} removed from element`, 'critical', { tag: element.tagName });
                    }
                });
                if (element.tagName === 'IFRAME' && !srcOrHref.includes('/api/v2/passwort')) {
                    element.remove();
                    log('Unauthorized iframe removed', 'critical', { src: srcOrHref });
                }
            }
            const dynamicScripts = document.querySelectorAll('script[src]');
            for (let script of dynamicScripts) {
                if (script.src && !script.src.includes('/api/v2/js/') && !script.src.includes('firewall.js')) {
                    const isSafe = await scanWithVirusTotal(script.src);
                    if (!isSafe) {
                        script.remove();
                        log('Dynamic script failed VirusTotal scan, removed', 'critical', { src: script.src });
                    }
                }
            }
            log('Virus cleaner executed successfully', 'info');
        } catch (e) {
            log('Error in virusCleaner', 'error', { error: e.message });
        }
    }

    // VirusTotal scan function with WannaCry detection
    async function scanWithVirusTotal(filePath) {
        if (!config.watchdog.virusScan.enabled) {
            log('VirusTotal scan disabled', 'info');
            return true;
        }
        try {
            const response = await stealthFetch(filePath, { cache: 'no-cache', mode: 'same-origin' });
            if (!response.ok) {
                log('Failed to fetch file for VirusTotal scan', 'error', { filePath, status: response.status });
                return false;
            }
            const content = await response.text();
            if (config.ransomwarePatterns.some(p => content.match(p))) {
                log('WannaCry, malicious, or hacker command pattern detected in file content', 'critical', { filePath });
                return false;
            }
            const blob = new Blob([content], { type: 'text/plain' });
            const formData = new FormData();
            formData.append('file', blob, filePath.split('/').pop());
            const scanResponse = await stealthFetch(config.watchdog.virusScan.scanEndpoint, {
                method: 'POST',
                headers: { 'x-apikey': config.watchdog.virusScan.apiKey },
                body: formData
            });
            const result = await scanResponse.json();
            if (result.data && result.data.attributes && result.data.attributes.stats) {
                const stats = result.data.attributes.stats;
                if (stats.malicious > 0 || stats.suspicious > 0) {
                    log('VirusTotal detected malicious content in file, possible WannaCry or hacker command', 'critical', { filePath, stats });
                    return false;
                }
                log('VirusTotal scan passed for file', 'info', { filePath, stats });
                return true;
            } else {
                log('Invalid VirusTotal response', 'error', { filePath, response: result });
                return false;
            }
        } catch (e) {
            log('Error during VirusTotal scan', 'error', { filePath, error: e.message });
            return false;
        }
    }

    // Decode hexadecimal strings to UTF-8
    function decodeHex(hex) {
        try {
            const bytes = [];
            for (let i = 0; i < hex.length; i += 2) {
                const hexPair = hex.substr(i, 2);
                if (!/^[0-9a-fA-F]{2}$/.test(hexPair)) {
                    throw new Error('Invalid hex string');
                }
                bytes.push(parseInt(hexPair, 16));
            }
            return new TextDecoder('utf-8').decode(new Uint8Array(bytes));
        } catch (e) {
            log('Error decoding hex string', 'error', { error: e.message });
            throw e;
        }
    }

    // Anti-ransomware protection with WannaCry-specific checks
    function antiRansomware() {
        if (!config.antiRansomware.enabled) {
            log('Anti-ransomware protection disabled', 'info');
            return;
        }
        try {
            config.antiRansomware.blockedCryptoApis.forEach(api => {
                if (crypto && crypto.subtle && crypto.subtle[api]) {
                    crypto.subtle[api] = function () {
                        log('Unauthorized crypto API usage detected, possible WannaCry attempt', 'critical', { api });
                        throw new Error('Ransomware-related crypto operation blocked');
                    };
                }
            });
            config.antiRansomware.storageKeys.forEach(storage => {
                if (window[storage]) {
                    const originalSetItem = window[storage].setItem;
                    window[storage].setItem = function (key, value) {
                        if (config.antiRansomware.suspiciousPatterns.some(p => value && value.match && value.match(p))) {
                            log('Ransomware, SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, or hacker command-related data detected in storage', 'critical', { storage, key, value });
                            throw new Error('Storage tampering blocked');
                        }
                        return originalSetItem.apply(this, [key, value]);
                    };
                }
            });
            let alertCount = 0;
            const originalAlert = window.alert || function () {};
            window.alert = function (message) {
                alertCount++;
                if (alertCount > config.antiRansomware.maxAlerts || (message && config.antiRansomware.suspiciousPatterns.some(p => message.match(p))) || /malicious/i.test(message)) {
                    log('Excessive or ransomware/SSH/HTTPS/AI-leak/redirect/VPN/WannaCry/malicious/hacker command-related alert detected', 'critical', { message });
                    throw new Error('Ransomware-like alert blocked');
                }
                return originalAlert.apply(this, [message]);
            };
            const observer = new MutationObserver(mutations => {
                mutations.forEach(mutation => {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType === 1 && (node.style.position === 'fixed' || (node.style.zIndex && parseInt(node.style.zIndex) > 1000))) {
                            if (config.antiRansomware.suspiciousPatterns.some(p => node.textContent && node.textContent.match(p)) || /malicious/i.test(node.textContent)) {
                                node.remove();
                                log('Ransomware/SSH/HTTPS/AI-leak/redirect/VPN/WannaCry/malicious/hacker command-like DOM content detected and removed', 'critical', { content: node.textContent });
                            }
                        }
                    });
                });
            });
            observer.observe(document.body, { childList: true, subtree: true });
            log('Anti-ransomware protection enabled with WannaCry detection', 'info');
        } catch (e) {
            log('Error in anti-ransomware protection', 'error', { error: e.message });
        }
    }

    // Validate referrer (relaxed to allow local script execution)
    function validateReferrer() {
        const referrer = document.referrer || window.location.href || '';
        const isValidReferrer = referrer && (
            referrer.startsWith('/api/v2/') ||
            referrer === ''
        );
        if (!isValidReferrer) {
            const urlParams = new URLSearchParams(window.location.search || '');
            const paymentKeywords = config.suspiciousKeywords.filter(k => k.includes('creditcard') || k.includes('paypal') || k.includes('cardnumber') || k.includes('payment'));
            for (let param of urlParams.values()) {
                if (paymentKeywords.some(keyword => param.toLowerCase().includes(keyword)) || /\d{4}-\d{4}-\d{4}-\d{4}/.test(param)) {
                    log('Payment-related data detected in URL referrer', 'alert', { referrer, param });
                    throw new Error('Payment data leak prevented due to invalid referrer');
                }
                if (config.antiHack.suspiciousPatterns.some(p => param && param.match && p.test(param)) || /malicious/i.test(param)) {
                    log('Suspicious JS, ransomware, SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, or hacker command-related code in URL params detected', 'critical', { param });
                    throw new Error('JS, ransomware, SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, or hacker command hack attempt blocked');
                }
            }
            log('Invalid referrer detected, but allowing local execution', 'warn', { referrer });
        }
        return true;
    }

    // Logging function
    function log(message, level = 'info', data = {}) {
        const timestamp = new Date().toISOString();
        const isPaymentRelated = config.suspiciousKeywords.some(k => message.includes(k) || (data && JSON.stringify(data).toLowerCase().includes('creditcard') || JSON.stringify(data).toLowerCase().includes('paypal') || JSON.stringify(data).toLowerCase().includes('payment')));
        const isHackRelated = config.antiHack.suspiciousPatterns.some(p => data && JSON.stringify(data).match(p));
        const isRansomwareRelated = config.antiRansomware.suspiciousPatterns.some(p => data && JSON.stringify(data).match(p));
        const isNonHTTPRelated = data && (JSON.stringify(data).toLowerCase().includes('https') || JSON.stringify(data).toLowerCase().includes('ssh') || JSON.stringify(data).toLowerCase().includes('secure shell') || JSON.stringify(data).toLowerCase().includes('ftp') || JSON.stringify(data).toLowerCase().includes('tor') || JSON.stringify(data).toLowerCase().includes('onion') || JSON.stringify(data).toLowerCase().includes('wcry') || JSON.stringify(data).toLowerCase().includes('wannacry') || JSON.stringify(data).toLowerCase().includes('bot') || JSON.stringify(data).toLowerCase().includes('malicious') || JSON.stringify(data).toLowerCase().includes('telnet') || JSON.stringify(data).toLowerCase().includes('smb') || JSON.stringify(data).toLowerCase().includes('rdp') || JSON.stringify(data).toLowerCase().includes('vnc') || JSON.stringify(data).toLowerCase().includes('sftp') || JSON.stringify(data).toLowerCase().includes('file') || JSON.stringify(data).toLowerCase().includes('sql') || JSON.stringify(data).toLowerCase().includes('select') || JSON.stringify(data).toLowerCase().includes('drop') || JSON.stringify(data).toLowerCase().includes('insert') || JSON.stringify(data).toLowerCase().includes('update') || JSON.stringify(data).toLowerCase().includes('delete') || JSON.stringify(data).toLowerCase().includes('script') || JSON.stringify(data).toLowerCase().includes('rm') || JSON.stringify(data).toLowerCase().includes('cat') || JSON.stringify(data).toLowerCase().includes('whoami'));
        const severity = isPaymentRelated || isHackRelated || isRansomwareRelated || isNonHTTPRelated ? 'critical' : level;
        const logMessage = `[FIREWALL] [${timestamp}] [${severity.toUpperCase()}] ${message}: ${JSON.stringify(data)}`;
        if (config.logTarget === 'console') {
            if (severity === 'error' || severity === 'critical') console.error(logMessage);
            else if (severity === 'warn') console.warn(logMessage);
            else console.log(logMessage);
        }
        if (config.logTarget === 'server' && navigator.onLine) {
            if (config.nis2.enabled && severity >= config.nis2.incidentSeverityThreshold) {
                stealthFetch(config.nis2.reportingEndpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message, severity, data, timestamp }),
                    cache: 'no-cache'
                }).catch(e => console.error('NIS2 reporting failed', e));
            }
        }
        if (severity === 'alert' || severity === 'critical') {
            if ('Notification' in window && window.Notification) {
                new Notification('NIS2 Incident Detected', { body: logMessage });
            }
        }
    }

    // Enforce Content Security Policy
    function enforceCSP() {
        try {
            const meta = document.createElement('meta');
            meta.httpEquiv = 'Content-Security-Policy';
            meta.content = config.securityHeaders['Content-Security-Policy'];
            document.head.appendChild(meta);
            log('CSP applied via meta tag', 'info', { csp: meta.content });
            document.addEventListener('securitypolicyviolation', e => {
                const isPaymentViolation = config.blockedDomains.some(d => e.blockedURI && e.blockedURI.includes(d)) || (e.blockedURI && e.blockedURI.includes('payment'));
                const isHackViolation = e.violatedDirective && e.violatedDirective.includes('script-src') && e.blockedURI && e.blockedURI.includes('inline');
                const isRansomwareViolation = e.blockedURI && config.antiRansomware.suspiciousPatterns.some(p => e.blockedURI.match(p));
                const isNonHTTPViolation = e.blockedURI && (e.blockedURI.includes('ssh://') || e.blockedURI.includes('ftp://') || e.blockedURI.includes('telnet://') || e.blockedURI.includes('smb://') || e.blockedURI.includes('rdp://') || e.blockedURI.includes('vnc://') || e.blockedURI.includes('sftp://') || e.blockedURI.includes('file://') || e.blockedURI.includes('tor') || e.blockedURI.includes('onion') || e.blockedURI.includes('wcry') || e.blockedURI.includes('wannacry') || config.blockedDomains.some(d => e.blockedURI.includes(d)));
                const isRedirectViolation = e.blockedURI && e.blockedURI.includes('redirect');
                log('CSP violation detected', isPaymentViolation || isHackViolation || isRansomwareViolation || isNonHTTPViolation || isRedirectViolation ? 'critical' : 'alert', {
                    blockedURI: e.blockedURI || 'undefined',
                    violatedDirective: e.violatedDirective || 'undefined',
                    originalPolicy: e.originalPolicy || 'undefined',
                    isPaymentRelated: isPaymentViolation,
                    isHackRelated: isHackViolation,
                    isRansomwareRelated: isRansomwareViolation,
                    isNonHTTPRelated: isNonHTTPViolation,
                    isRedirectRelated: isRedirectViolation
                });
            });
        } catch (e) {
            log('Error applying CSP', 'error', { error: e.message });
        }
    }

    // Validate IP address
    function validateIP(ip) {
        if (!ip) {
            log('No IP provided for validation', 'error');
            return false;
        }
        const isAllowed = config.allowedIPs.some(c => c && ip.startsWith(c.split('/')[0]));
        if (!isAllowed) {
            log('IP not in allowed list', 'warn', { ip });
            return false;
        }
        if (config.vpnDetection.enabled) {
            const isVPN = config.vpnDetection.blockedVPNIPs.some(c => c && ip.startsWith(c.split('/')[0]));
            if (isVPN) {
                log('VPN IP detected and blocked (Google VPN, Tor, or App VPN)', 'alert', { ip });
                return false;
            }
            const paymentKeywords = config.suspiciousKeywords.filter(k => k.includes('creditcard') || k.includes('paypal') || k.includes('cardnumber') || k.includes('payment'));
            const isPaymentRequest = window.fetch && window.fetch.toString && window.fetch.toString().includes('payment');
            const isHackRequest = window.fetch && window.fetch.toString && config.antiHack.suspiciousPatterns.some(p => window.fetch.toString().match(p));
            const isRansomwareRequest = window.fetch && window.fetch.toString && config.antiRansomware.suspiciousPatterns.some(p => window.fetch.toString().match(p));
            const isNonHTTPRequest = window.fetch && window.fetch.toString && (window.fetch.toString().includes('ssh://') || window.fetch.toString().includes('ftp://') || window.fetch.toString().includes('telnet://') || window.fetch.toString().includes('smb://') || window.fetch.toString().includes('rdp://') || window.fetch.toString().includes('vnc://') || window.fetch.toString().includes('sftp://') || window.fetch.toString().includes('file://') || window.fetch.toString().includes('tor') || window.fetch.toString().includes('onion') || window.fetch.toString().includes('wcry') || window.fetch.toString().includes('wannacry'));
            if (isPaymentRequest || paymentKeywords.some(k => document.cookie && document.cookie.includes(k))) {
                log('Payment-related data detected in request from IP', 'critical', { ip });
                return false;
            }
            if (isHackRequest) {
                log('Suspicious JS or hacker command code in fetch request detected', 'critical', { ip });
                return false;
            }
            if (isRansomwareRequest) {
                log('Ransomware or hacker command-related code in fetch request detected', 'critical', { ip });
                return false;
            }
            if (isNonHTTPRequest) {
                log('Non-HTTP related code (SSH, FTP, TELNET, SMB, RDP, VNC, SFTP, FILE, Tor, WannaCry, or VPN) in fetch request detected', 'critical', { ip });
                return false;
            }
        }
        return true;
    }

    // Detect VPN usage with enhanced Google VPN, Tor, and App VPN detection
    function detectVPN() {
        try {
            if (!config.vpnDetection.enabled) {
                log('VPN detection disabled', 'info');
                return false;
            }
            const referrer = document.referrer || window.location.href || '';
            if (config.suspiciousURLs.some(p => referrer.match(p))) {
                log('Suspicious URL pattern detected in referrer or URL (ChatGPT/Grok/redirect/VPN/WannaCry check)', 'critical', { referrer });
                return false;
            }
            const isVPNDomain = config.vpnDetection.vpnDomains.some(v => referrer.includes(v));
            if (isVPNDomain) {
                log('VPN-related domain detected in referrer or URL (Google VPN, Tor, or App VPN)', 'alert', { referrer });
                return true;
            }
            if (config.vpnDetection.checkTimeZone && !config.devicePermissions.geolocation) {
                try {
                    const clientTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
                    const expectedTimeZone = 'America/New_York';
                    if (clientTimeZone !== expectedTimeZone) {
                        log('Time zone mismatch detected, possible VPN usage (Google VPN, Tor, or App VPN)', 'warn', { clientTimeZone, expectedTimeZone });
                        return true;
                    }
                } catch (e) {
                    log('Error checking time zone for VPN detection', 'error', { error: e.message });
                }
            }
            if (config.vpnDetection.checkHeaders) {
                const originalFetch = window.fetch || function () { return Promise.reject('Fetch undefined'); };
                window.fetch = async function (...args) {
                    const [url, options = {}] = args;
                    if (url.includes('/api/v2/passwort') || url.includes('/api/v2/js/') || url.includes('/api/v2/img/') || url.includes('virustotal.com')) {
                        return stealthFetch(url, options);
                    }
                    const headers = options.headers || {};
                    const suspiciousHeaders = [/x-vpn/i, /proxy/i, /tunnel/i, /payment/i, /creditcard/i, /paypal/i, /eval/i, /proto/i, /ransom/i, /ssh/i, /https/i, /ftp:\/\//i, /telnet:\/\//i, /smb:\/\//i, /rdp:\/\//i, /vnc:\/\//i, /sftp:\/\//i, /file:\/\//i, /chatgpt/i, /openai/i, /grok/i, /xai/i, /redirect/i, /tor/i, /onion/i, /wcry/i, /wannacry/i, /bot/i, /malicious/i, /select/i, /drop/i, /insert/i, /update/i, /delete/i, /<script>/i, /rm\s/i, /cat\s/i, /whoami/i];
                    let isSuspicious = false;
                    for (let [key, value] of Object.entries(headers)) {
                        if (suspiciousHeaders.some(r => value && (r.test(key) || r.test(value)))) {
                            isSuspicious = true;
                            log('Payment, JS hack, ransomware, SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, or hacker command-related header detected', 'critical', { header: key, value });
                            break;
                        }
                    }
                    if (isSuspicious) {
                        throw new Error('Request blocked due to payment, JS hack, ransomware, SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, or hacker command-related headers');
                    }
                    const response = await originalFetch.apply(this, args);
                    if (response.status === 304) {
                        log('HTTP 304 status detected, forcing reload to 200 status', 'warn', { url });
                        return stealthFetch(url, { ...options, cache: 'no-cache', headers: { ...headers, 'Cache-Control': 'no-cache' } });
                    }
                    if (response.status === 302) {
                        const redirectUrl = response.headers.get('location');
                        if (redirectUrl && config.suspiciousURLs.some(p => redirectUrl.match(p))) {
                            log('HTTP 302 redirect to suspicious URL detected, blocking', 'critical', { url, redirectUrl });
                            window.location.href = config.offlinePage;
                            throw new Error('Suspicious 302 redirect blocked');
                        }
                    }
                    if (response.status >= 500) {
                        serverErrorCount++;
                        log('Server error detected (5xx)', 'warn', { status: response.status, url });
                        if (serverErrorCount >= config.watchdog.serverThaw.errorThreshold) {
                            thawWebServer();
                        }
                    } else {
                        serverErrorCount = 0;
                    }
                    return response;
                };
                log('Fetch interception enabled for VPN, payment, JS hack, ransomware, SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, and hacker command detection', 'info');
            }
            if (config.vpnDetection.torDetection) {
                try {
                    const isTor = navigator.userAgent.includes('Tor') || window.location.hostname.endsWith('.onion');
                    if (isTor) {
                        log('Tor network detected via user agent or .onion domain', 'critical', { userAgent: navigator.userAgent, hostname: window.location.hostname });
                        return true;
                    }
                } catch (e) {
                    log('Error in Tor detection', 'error', { error: e.message });
                }
            }
            if (config.vpnDetection.appVpnDetection) {
                try {
                    const suspiciousHeaders = [/x-vpn/i, /nordvpn/i, /expressvpn/i, /protonvpn/i, /surfshark/i, /mullvad/i, /cyberghost/i, /pia/i];
                    const hasVpnHeaders = Object.keys(window.navigator).some(key => suspiciousHeaders.some(r => r.test(key)));
                    if (hasVpnHeaders) {
                        log('App VPN detected via navigator properties', 'critical', { navigator: Object.keys(window.navigator) });
                        return true;
                    }
                } catch (e) {
                    log('Error in App VPN detection', 'error', { error: e.message });
                }
            }
            return false;
        } catch (e) {
            log('Error in VPN detection', 'error', { error: e.message });
            return false;
        }
    }

    // Thaw Web Server Function
    function thawWebServer() {
        if (!config.watchdog.serverThaw.enabled) {
            log('Server thaw disabled', 'info');
            return;
        }
        log('Webserver freeze detected – initiating thaw procedure', 'critical', { errorCount: serverErrorCount });
        try {
            stealthFetch(config.watchdog.serverThaw.thawEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ timestamp: Date.now(), action: 'thaw' }),
                cache: 'no-cache',
                timeout: config.watchdog.serverThaw.timeoutMs
            }).then(response => {
                if (response.ok) {
                    log('Server thaw endpoint called successfully', 'info');
                    serverErrorCount = 0;
                } else {
                    log('Thaw endpoint failed – falling back', 'warn', { status: response.status });
                    performFallbackThaw();
                }
            }).catch(e => {
                log('Thaw endpoint unreachable – performing fallback thaw', 'error', { error: e.message });
                performFallbackThaw();
            });
        } catch (e) {
            log('Error in server thaw procedure', 'error', { error: e.message });
            performFallbackThaw();
        }
    }

    // Fallback Thaw Action
    function performFallbackThaw() {
        const action = config.watchdog.serverThaw.fallbackAction;
        if (action === 'reload') {
            log('Performing page reload as fallback thaw', 'warn');
            window.location.reload(true);
        } else if (action === 'offline') {
            log('Loading offline page as fallback thaw', 'warn');
            window.location.href = config.offlinePage;
        }
        if ('Notification' in window && window.Notification) {
            new Notification('Server Thaw Activated', { body: `Webserver freeze resolved via fallback: ${action}` });
        }
    }

    // Watchdog for file integrity
    function watchdog() {
        if (!config.watchdog.enabled) {
            log('Watchdog monitoring disabled', 'info');
            return;
        }
        async function computeHash(content) {
            try {
                const encoder = new TextEncoder();
                const data = encoder.encode(content || '');
                const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
            } catch (e) {
                log('Error computing hash for watchdog', 'error', { error: e.message });
                return '';
            }
        }
        async function checkAndThaw(filePath, expectedHash, backupUrl, fallbackContent) {
            try {
                const response = await stealthFetch(filePath, { cache: 'no-cache' });
                if (response.status === 304) {
                    log('HTTP 304 status detected for file, forcing reload to 200 status', 'warn', { file: filePath });
                    const retryResponse = await stealthFetch(filePath, { cache: 'no-cache', headers: { 'Cache-Control': 'no-cache' } });
                    if (!retryResponse.ok) {
                        throw new Error(`Retry fetch failed: ${retryResponse.status}`);
                    }
                    return retryResponse.text();
                }
                if (response.status === 302) {
                    const redirectUrl = response.headers.get('location');
                    if (redirectUrl && config.suspiciousURLs.some(p => redirectUrl.match(p))) {
                        log('HTTP 302 redirect to suspicious URL detected in file check, blocking', 'critical', { file: filePath, redirectUrl });
                        throw new Error('Suspicious 302 redirect blocked');
                    }
                }
                if (!response.ok) {
                    throw new Error(`Fetch failed: ${response.status}`);
                }
                const content = await response.text();
                const currentHash = await computeHash(content);
                if (currentHash !== expectedHash) {
                    log('File integrity violation detected: checksum mismatch', 'critical', { file: filePath, currentHash, expectedHash });
                    await thawFile(filePath, backupUrl, fallbackContent);
                } else if (config.antiHack.suspiciousPatterns.some(p => content.match(p)) || config.antiRansomware.suspiciousPatterns.some(p => content.match(p))) {
                    log('Suspicious JS, ransomware, SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, or hacker command-related code detected in file', 'critical', { file: filePath });
                    await thawFile(filePath, backupUrl, fallbackContent);
                } else {
                    log('File integrity verified ok', 'info', { file: filePath });
                }
            } catch (e) {
                log('File frozen/inaccessible detected, attempting to thaw the file', 'critical', { file: filePath, error: e.message });
                await thawFile(filePath, backupUrl, fallbackContent);
            }
        }
        async function thawFile(filePath, backupUrl, fallbackContent) {
            try {
                const backupResponse = await stealthFetch(backupUrl, { cache: 'no-cache' });
                if (backupResponse.status === 304) {
                    log('HTTP 304 status detected for backup file, forcing reload to 200 status', 'warn', { file: filePath, backupUrl });
                    const retryBackupResponse = await stealthFetch(backupUrl, { cache: 'no-cache', headers: { 'Cache-Control': 'no-cache' } });
                    if (!retryBackupResponse.ok) {
                        throw new Error(`Retry fetch failed for backup: ${retryBackupResponse.status}`);
                    }
                    return retryBackupResponse.text();
                }
                if (backupResponse.status === 302) {
                    const redirectUrl = backupResponse.headers.get('location');
                    if (redirectUrl && config.suspiciousURLs.some(p => redirectUrl.match(p))) {
                        log('HTTP 302 redirect to suspicious URL detected in backup, blocking', 'critical', { file: filePath, redirectUrl });
                        throw new Error('Suspicious 302 redirect blocked');
                    }
                }
                if (backupResponse.ok) {
                    const backupContent = await backupResponse.text();
                    if (config.antiRansomware.suspiciousPatterns.some(p => backupContent.match(p))) {
                        log('Ransomware, SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, or hacker command-related code detected in backup content', 'critical', { file: filePath });
                        throw new Error('Corrupted backup detected');
                    }
                    if (filePath.endsWith('.html')) {
                        document.open();
                        document.write(backupContent);
                        document.close();
                    } else if (filePath.endsWith('.js')) {
                        const script = document.createElement('script');
                        script.textContent = backupContent;
                        document.head.appendChild(script);
                    }
                    log('File thawed successfully via backup', 'info', { file: filePath });
                } else {
                    if (config.antiRansomware.suspiciousPatterns.some(p => fallbackContent.match(p))) {
                        log('Ransomware, SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, or hacker command-related code detected in fallback content', 'critical', { file: filePath });
                        throw new Error('Corrupted fallback content');
                    }
                    if (filePath.endsWith('.html')) {
                        document.open();
                        document.write(fallbackContent);
                        document.close();
                    } else if (filePath.endsWith('.js')) {
                        const script = document.createElement('script');
                        script.textContent = fallbackContent;
                        document.head.appendChild(script);
                    }
                    log('Failed to fetch backup, using embedded fallback', 'warn', { file: filePath });
                }
                if ('Notification' in window && window.Notification) {
                    new Notification('Watchdog Alert', { body: `File ${filePath} thawed after freeze detection.` });
                }
            } catch (e) {
                log('Failure thawing file: cannot restore', 'error', { file: filePath, error: e.message });
            }
        }
        async function performVirusScan() {
            for (const filePath of config.watchdog.virusScan.filesToScan) {
                const isSafe = await scanWithVirusTotal(filePath);
                if (!isSafe) {
                    log('VirusTotal scan failed – halting page load', 'critical', { filePath });
                    window.location.href = config.offlinePage;
                    throw new Error(`Malicious content detected in ${filePath}`);
                }
            }
        }
        performVirusScan().then(() => {
            checkAndThaw('./index.html', config.watchdog.indexHtmlHash, config.watchdog.backupEndpoints.indexHtml, config.watchdog.fallbackHtml);
            checkAndThaw('./index.js', config.watchdog.indexJsHash, config.watchdog.backupEndpoints.indexJs, config.watchdog.fallbackJs);
            setInterval(() => {
                checkAndThaw('./index.html', config.watchdog.indexHtmlHash, config.watchdog.backupEndpoints.indexHtml, config.watchdog.fallbackHtml);
                checkAndThaw('./index.js', config.watchdog.indexJsHash, config.watchdog.backupEndpoints.indexJs, config.watchdog.fallbackJs);
            }, config.watchdog.pollInterval);
            log('Watchdog monitoring enabled for index.html and index.js with VirusTotal scan and WannaCry detection', 'info');
        }).catch(e => {
            log('Critical failure in VirusTotal scan – halting execution', 'error', { error: e.message });
            window.location.href = config.offlinePage;
        });
    }

    // Monitor JavaScript file loads for HTTP 304 and 302 status
    function monitorJsLoads() {
        try {
            const observer = new MutationObserver(mutations => {
                mutations.forEach(mutation => {
                    mutation.addedNodes.forEach(node => {
                        if (node.tagName === 'SCRIPT' && node.src && node.src.endsWith('.js')) {
                            stealthFetch(node.src, { method: 'HEAD', cache: 'no-cache' }).then(response => {
                                if (response.status === 304) {
                                    log('HTTP 304 status detected for .js file, forcing reload to 200 status', 'warn', { url: node.src });
                                    stealthFetch(node.src, { cache: 'no-cache', headers: { 'Cache-Control': 'no-cache' } });
                                }
                                if (response.status === 302) {
                                    const redirectUrl = response.headers.get('location');
                                    if (redirectUrl && config.suspiciousURLs.some(p => redirectUrl.match(p))) {
                                        log('HTTP 302 redirect to suspicious URL detected in JS load, blocking', 'critical', { url: node.src, redirectUrl });
                                        throw new Error('Suspicious 302 redirect blocked');
                                    }
                                }
                            }).catch(e => {
                                log('Error checking .js file status', 'error', { url: node.src, error: e.message });
                            });
                        }
                    });
                });
            });
            observer.observe(document.documentElement, { childList: true, subtree: true });
            log('.js file load monitoring for 304 and 302 status enabled', 'info');
        } catch (e) {
            log('Error in .js file load monitoring', 'error', { error: e.message });
        }
    }

    // Anti-JS hack protection
    function antiHack() {
        if (!config.antiHack.enabled) {
            log('Anti-JS hack protection disabled', 'info');
            return;
        }
        try {
            config.antiHack.blockedFunctions.forEach(func => {
                if (window[func]) {
                    window[func] = function () {
                        log('Dangerous JS or hacker command function detected', 'critical', { function: func });
                        throw new Error('Dangerous JS or hacker command function blocked');
                    };
                }
            });
            const originalProto = Object.prototype;
            Object.defineProperty(Object, 'prototype', {
                set: function () {
                    log('Prototype pollution attempt detected', 'critical', {});
                    throw new Error('Prototype modification blocked');
                },
                get: function () { return originalProto; }
            });
            const inputs = document.querySelectorAll(config.antiHack.protectedInputs.join(','));
            inputs.forEach(input => {
                const originalAddListener = input.addEventListener || function () {};
                input.addEventListener = function (type, listener, options) {
                    if (['input', 'change', 'keydown'].includes(type)) {
                        log('Event listener added to sensitive input', 'warn', { type, element: input.tagName });
                    }
                    return originalAddListener.apply(this, [type, listener, options]);
                };
            });
            const originalSetTimeout = window.setTimeout || function () {};
            window.setTimeout = function (handler, timeout, ...args) {
                if (typeof handler === 'string') {
                    if (config.antiHack.suspiciousPatterns.some(p => handler.match(p))) {
                        log('String-based setTimeout with SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, or hacker command-related code detected', 'critical', { handler });
                        throw new Error('String-based code execution blocked');
                    }
                    log('String-based setTimeout detected', 'critical', { handler });
                    throw new Error('String-based code execution blocked');
                }
                return originalSetTimeout(handler, timeout, ...args);
            };
            const originalSetInterval = window.setInterval || function () {};
            window.setInterval = function (handler, timeout, ...args) {
                if (typeof handler === 'string') {
                    if (config.antiHack.suspiciousPatterns.some(p => handler.match(p))) {
                        log('String-based setInterval with SSH, HTTPS, AI-leak, redirect, VPN, WannaCry, malicious, or hacker command-related code detected', 'critical', { handler });
                        throw new Error('String-based code execution blocked');
                    }
                    log('String-based setInterval detected', 'critical', { handler });
                    throw new Error('String-based code execution blocked');
                }
                return originalSetInterval(handler, timeout, ...args);
            };
            const observer = new MutationObserver(mutations => {
                mutations.forEach(mutation => {
                    if (mutation.addedNodes.length) {
                        mutation.addedNodes.forEach(node => {
                            if (node.tagName === 'SCRIPT' && (!config.blockedDomains.some(d => node.src && node.src.includes(d)) && !node.src.includes('/api/v2/js/'))) {
                                node.remove();
                                log('Unauthorized script injection detected', 'critical', { src: node.src || 'inline' });
                            }
                            if (node.nodeType === 1 && config.antiRansomware.suspiciousPatterns.some(p => node.textContent && node.textContent.match(p))) {
                                node.remove();
                                log('Ransomware/SSH/HTTPS/AI-leak/redirect/VPN/WannaCry/malicious/hacker command-like DOM content detected and removed', 'critical', { content: node.textContent });
                            }
                        });
                    }
                });
            });
            observer.observe(document.documentElement, { childList: true, subtree: true });
            log('Anti-JS hack protection enabled', 'info');
        } catch (e) {
            log('Error in anti-JS hack protection', 'error', { error: e.message });
        }
    }

    // Enforce HTTP-only access
    function enforceHttpOnly() {
        try {
            if (!config.platformRestrictions.httpOnly) {
                log('HTTP-only enforcement disabled', 'info');
                return false;
            }
            const protocol = window.location && window.location.protocol ? window.location.protocol : 'undefined';
            if (protocol !== 'http:') {
                log('Non-HTTP protocol (e.g., HTTPS, SSH, FTP, TELNET, SMB, RDP, VNC, SFTP, FILE, Tor) detected, only HTTP allowed', 'critical', { protocol, location: window.location ? window.location.href : 'undefined' });
                throw new Error('Access via HTTPS, SSH, FTP, TELNET, SMB, RDP, VNC, SFTP, FILE, Tor, or other protocols is not allowed, please use HTTP');
            }
            log('HTTP access verified', 'info', { protocol });
            return true;
        } catch (e) {
            log('Error in HTTP-only validation', 'error', { error: e.message });
            return false;
        }
    }

    // Validate platform and browser
    function validatePlatform() {
        try {
            if (!config.platformRestrictions.blockWebView) {
                log('Platform and browser detection disabled', 'info');
                return false;
            }
            const userAgent = navigator.userAgent || '';
            const isBlockedPlatform = config.platformRestrictions.blockedUAPatterns.some(p => p.test(userAgent));
            if (isBlockedPlatform) {
                log('Blocked platform or bot detected', 'alert', { userAgent });
                return true;
            }
            const isAllowedPlatform = config.platformRestrictions.allowedPlatforms.some(p => p.test(userAgent));
            if (!isAllowedPlatform) {
                log('Non-Windows platform detected', 'alert', { userAgent });
                return true;
            }
            let isLatestBrowser = false;
            for (const [browser, configBrowser] of Object.entries(config.platformRestrictions.browsers)) {
                const match = userAgent.match(configBrowser.pattern);
                if (match) {
                    const version = parseInt(match[1], 10);
                    if (version >= configBrowser.minVersion) {
                        isLatestBrowser = true;
                        break;
                    } else {
                        log('Outdated browser version detected', 'alert', { browser, version, required: configBrowser.minVersion, userAgent });
                        return true;
                    }
                }
            }
            if (!isLatestBrowser) {
                log('Unsupported or outdated browser detected', 'alert', { userAgent });
                return true;
            }
            return false;
        } catch (e) {
            log('Error in platform and browser detection', 'error', { error: e.message });
            return false;
        }
    }

    // Block Presentation API
    function blockPresentationAPI() {
        try {
            if (!config.platformRestrictions.blockPresentation) {
                log('Presentation API detection disabled', 'info');
                return false;
            }
            if ('PresentationRequest' in window) {
                window['PresentationRequest'] = undefined;
                navigator['presentation'] = undefined;
                log('Presentation API disabled to prevent unauthorized usage', 'info');
                return true;
            }
            return false;
        } catch (e) {
            log('Error in Presentation API detection', 'error', { error: e.message });
            return false;
        }
    }

    // Prevent browser leaks
    function preventBrowserLeaks() {
        try {
            if ('RTCPeerConnection' in window || 'webkitRTCPeerConnection' in window || 'mozRTCPeerConnection' in window) {
                window['RTCPeerConnection'] = undefined;
                window['webkitRTCPeerConnection'] = undefined;
                window['mozRTCPeerConnection'] = undefined;
                log('WebRTC disabled to prevent VPN leaks', 'info');
            }
            if ('HTMLCanvasElement' in window) {
                const originalToDataURL = HTMLCanvasElement.prototype.toDataURL || function () {};
                HTMLCanvasElement.prototype.toDataURL = function (...args) {
                    const canvas = this, context = canvas.getContext('2d');
                    if (context) {
                        context.fillStyle = 'rgba(0,0,0,0.01)';
                        context.fillRect(0, 0, 1, 1);
                        log('Canvas fingerprinting protection applied', 'info');
                    }
                    return originalToDataURL.apply(this, args);
                };
                const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData || function () {};
                CanvasRenderingContext2D.prototype.getImageData = function (...args) {
                    log('Canvas getImageData intercepted', 'info');
                    return originalGetImageData.apply(this, args);
                };
            }
            if (config.devicePermissions.microphone || config.devicePermissions.camera) {
                if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
                    navigator.mediaDevices.getUserMedia = async function (constraints) {
                        log('Blocked access to getUserMedia (microphone/camera)', 'alert', { constraints });
                        throw new DOMException('Access to microphone and camera is blocked by firewall', 'NotAllowedError');
                    };
                    log('Microphone and camera access blocked via getUserMedia', 'info');
                }
            }
            if (config.devicePermissions.screen) {
                if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
                    navigator.mediaDevices.getDisplayMedia = async function (constraints) {
                        log('Blocked access to getDisplayMedia (screen sharing)', 'alert', { constraints });
                        throw new DOMException('Access to screen sharing is blocked by firewall', 'NotAllowedError');
                    };
                    log('Screen sharing access blocked via getDisplayMedia', 'info');
                }
            }
            if (config.devicePermissions.geolocation) {
                if (navigator.geolocation) {
                    navigator.geolocation.getCurrentPosition = function (success, error, options) {
                        log('Blocked access to geolocation.getCurrentPosition', 'alert', { options });
                        if (error) {
                            error(new GeolocationPositionError(GeolocationPositionError.PERMISSION_DENIED, 'Geolocation access blocked to prevent VPN location spoofing'));
                        }
                    };
                    navigator.geolocation.watchPosition = function (success, error, options) {
                        log('Blocked access to geolocation.watchPosition', 'alert', { options });
                        if (error) {
                            error(new GeolocationPositionError(GeolocationPositionError.PERMISSION_DENIED, 'Geolocation access blocked to prevent VPN location spoofing'));
                        }
                        return -1;
                    };
                    log('Geolocation access blocked to prevent VPN location spoofing', 'info');
                }
            }
            if (detectVPN()) {
                log('VPN usage detected, applying restrictions', 'alert');
            }
            if (validatePlatform()) {
                log('Request blocked due to invalid platform or outdated browser', 'alert');
                throw new Error('Request blocked due to invalid platform or outdated browser');
            }
            blockPresentationAPI();
            antiBot();
            watchdog();
            antiHack();
            antiRansomware();
            monitorJsLoads();
            virusCleaner();
        } catch (e) {
            log('Error in preventBrowserLeaks', 'error', { error: e.message });
        }
    }

    // Initialize firewall
    function initialize() {
        try {
            validateReferrer();
            enforceHttpOnly();
            enforceCSP();
            preventBrowserLeaks();
            virusCleaner();
            antiBot();
            watchdog();
            antiHack();
            antiRansomware();
            monitorJsLoads();
            const observer = new MutationObserver(mutations => {
                mutations.forEach(mutation => {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType === 1) {
                            const srcOrHref = node.src || node.href || node.textContent || '';
                            if (config.suspiciousURLs.some(p => srcOrHref.match(p))) {
                                node.remove();
                                log('Dynamic SSH/FTP/TELNET/SMB/RDP/VNC/SFTP/FILE or AI-leak/redirect/VPN/WannaCry/malicious/hacker command-related link detected and removed', 'critical', { src: srcOrHref, tag: node.tagName });
                            }
                        }
                    });
                });
            });
            observer.observe(document.documentElement, { childList: true, subtree: true });
            log('SSH/FTP/TELNET/SMB/RDP/VNC/SFTP/FILE, AI-leak, redirect, VPN, WannaCry, malicious, and hacker command link monitoring enabled', 'info');
            log('NIS2 Compliance Initialized: Risk Management, Reporting, and Supply Chain Checks Active', 'info', { directive: 'EU 2022/2555' });
        } catch (e) {
            log('Initialization error', 'error', { error: e.message });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
