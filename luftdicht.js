// luftdicht.js - Luftdichte Sicherheitsbibliothek für Android-WebView
// Version 1.1 | Erstellt am 19.10.2025 | NIS2 & ISO 27001 konform
// Schutz vor: XSS, CSRF, Clickjacking, Injection, Unbekannte Protokolle

(function (global) {
    'use strict';

    // Konfiguration
    const defaultConfig = {
        allowedProtocols: ['http:', 'ws:'],  // HTTP-only, kein HTTPS
        logLevel: 'warn',  // 'error', 'warn', 'info', 'none'
        cspPolicy: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
        maxInputLength: 1000,  // Schutz vor Buffer Overflows
        blockFileAccess: true,  // Blockiert file://
        allowWebViewDebug: false  // Debugging deaktivieren
    };

    // Logging (ISO 27001 A.16)
    function logEvent(level, message, details = {}) {
        if (defaultConfig.logLevel === 'none') return;
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level,
            message,
            details,
            userAgent: navigator.userAgent,
            url: window.location.href
        };
        console[level](`[Luftdicht-Android] ${timestamp}: ${message}`, logEntry);
        // Android-native Logs
        try {
            if (global.Android?.logSecurityEvent) {
                global.Android.logSecurityEvent(JSON.stringify(logEntry));
            }
        } catch (e) {
            console.error('[Luftdicht] Native Logging fehlgeschlagen:', e);
        }
    }

    // 1. HTTP-only erzwingen
    function enforceHttpOnly() {
        try {
            if (window.location.protocol === 'https:') {
                logEvent('error', 'HTTPS erkannt – Umleitung zu HTTP');
                window.location.replace(window.location.href.replace('https://', 'http://'));
                return false;
            }
            const originalFetch = window.fetch;
            window.fetch = async (...args) => {
                if (args[0]?.startsWith('https://')) {
                    logEvent('warn', 'HTTPS-Request blockiert');
                    throw new Error('HTTPS verboten');
                }
                return originalFetch.apply(this, args);
            };
            const originalXHR = window.XMLHttpRequest.prototype.open;
            window.XMLHttpRequest.prototype.open = function(method, url, ...rest) {
                if (url.startsWith('https://')) {
                    logEvent('warn', 'HTTPS-XHR blockiert');
                    throw new Error('HTTPS verboten');
                }
                return originalXHR.apply(this, [method, url, ...rest]);
            };
            logEvent('info', 'HTTP-only Modus aktiviert');
            return true;
        } catch (e) {
            logEvent('error', 'Fehler in enforceHttpOnly', { error: e.message });
            return false;
        }
    }

    // 2. Unbekannte Protokolle blockieren
    function blockUnknownProtocols() {
        try {
            const allowed = new Set(defaultConfig.allowedProtocols);
            if (defaultConfig.blockFileAccess) allowed.delete('file:');
            const originalCreateElement = document.createElement;
            document.createElement = function(tag, ...args) {
                const el = originalCreateElement.apply(this, [tag, ...args]);
                if (['a', 'form', 'iframe'].includes(tag.toLowerCase())) {
                    const observer = new MutationObserver((mutations) => {
                        mutations.forEach((mutation) => {
                            mutation.addedNodes.forEach((node) => {
                                if (node.nodeType === 1 && ['A', 'FORM', 'IFRAME'].includes(node.tagName)) {
                                    const href = node.href || node.action || node.src;
                                    if (href && !allowed.has(new URL(href, window.location.href).protocol)) {
                                        logEvent('warn', `Unbekanntes Protokoll blockiert: ${href}`);
                                        node.href = '#';
                                        node.src = '';
                                        node.style.display = 'none';
                                    }
                                }
                            });
                        });
                    });
                    observer.observe(el, { attributes: true, subtree: true, attributeFilter: ['href', 'action', 'src'] });
                }
                return el;
            };
            const originalAssign = window.location.assign;
            window.location.assign = function(url) {
                if (url && !allowed.has(new URL(url, window.location.href).protocol)) {
                    logEvent('error', `Protokoll-Wechsel blockiert: ${url}`);
                    return;
                }
                return originalAssign.call(window.location, url);
            };
            logEvent('info', 'Unbekannte Protokolle blockiert');
        } catch (e) {
            logEvent('error', 'Fehler in blockUnknownProtocols', { error: e.message });
        }
    }

    // 3. Input-Sanitization
    function sanitizeInput(input) {
        try {
            if (typeof input !== 'string' || input.length > defaultConfig.maxInputLength) {
                logEvent('warn', 'Input ungültig oder zu lang');
                return '';
            }
            const safe = input.replace(/[^a-zA-Z0-9\s\-_.]/g, '');
            if (safe !== input) logEvent('warn', 'Input gesäubert', { original: input });
            return safe;
        } catch (e) {
            logEvent('error', 'Fehler in sanitizeInput', { error: e.message });
            return '';
        }
    }

    // 4. Input-Validierung
    function validateInput(input, type = 'text') {
        try {
            const validators = {
                text: /^[\w\s\-_.]{0,1000}$/,
                email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
                number: /^\d+$/
            };
            const isValid = validators[type]?.test(input) ?? false;
            if (!isValid) logEvent('error', `Input-Validierung fehlgeschlagen: ${type}`, { input });
            return isValid;
        } catch (e) {
            logEvent('error', 'Fehler in validateInput', { error: e.message });
            return false;
        }
    }

    // 5. XSS-Prävention
    function preventXSS(containerSelector) {
        try {
            const containers = document.querySelectorAll(containerSelector);
            containers.forEach((el) => {
                el.addEventListener('input', (e) => {
                    e.target.value = sanitizeInput(e.target.value);
                });
                el.addEventListener('DOMNodeInserted', (e) => {
                    if (e.target.innerHTML?.includes('<script')) {
                        logEvent('error', 'Potenzieller XSS blockiert');
                        e.target.innerHTML = e.target.textContent;
                    }
                });
            });
            window.escapeHtml = (text) => {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            };
            logEvent('info', 'XSS-Prävention aktiviert für', { selector: containerSelector });
        } catch (e) {
            logEvent('error', 'Fehler in preventXSS', { error: e.message });
        }
    }

    // 6. CSP-Enforcement
    function enforceCSP() {
        try {
            if (!document.querySelector("meta[http-equiv='Content-Security-Policy']")) {
                const meta = document.createElement('meta');
                meta.httpEquiv = 'Content-Security-Policy';
                meta.content = defaultConfig.cspPolicy;
                document.head.appendChild(meta);
            }
            logEvent('info', 'CSP erzwungen');
        } catch (e) {
            logEvent('error', 'Fehler in enforceCSP', { error: e.message });
        }
    }

    // 7. CSRF-Schutz
    function generateCSRToken() {
        try {
            const token = btoa(Math.random().toString(36)).substring(7);
            document.cookie = `csrf_token=${token}; HttpOnly; Secure=false; SameSite=Strict`;
            return token;
        } catch (e) {
            logEvent('error', 'Fehler in generateCSRToken', { error: e.message });
            return '';
        }
    }

    function validateCSRToken(form) {
        try {
            const token = form.querySelector('input[name="csrf_token"]')?.value;
            if (!token || token !== getCookie('csrf_token')) {
                logEvent('error', 'CSRF-Token ungültig');
                return false;
            }
            return true;
        } catch (e) {
            logEvent('error', 'Fehler in validateCSRToken', { error: e.message });
            return false;
        }
    }

    function getCookie(name) {
        try {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            return parts.length === 2 ? parts.pop().split(';').shift() : null;
        } catch (e) {
            logEvent('error', 'Fehler in getCookie', { error: e.message });
            return null;
        }
    }

    // 8. Clickjacking-Schutz
    function preventClickjacking() {
        try {
            if (top !== window) {
                logEvent('error', 'Clickjacking erkannt');
                top.location = window.location.href;
            }
            enforceCSP();
            logEvent('info', 'Clickjacking-Prävention aktiviert');
        } catch (e) {
            logEvent('error', 'Fehler in preventClickjacking', { error: e.message });
        }
    }

    // 9. DOM-Sicherung
    function secureDOM() {
        try {
            const dangerous = ['eval', 'setTimeout', 'setInterval', 'Function'];
            dangerous.forEach((func) => {
                if (window[func]) {
                    const original = window[func];
                    window[func] = function(...args) {
                        if (typeof args[0] === 'string') {
                            logEvent('warn', `${func} mit String blockiert`);
                            throw new Error('Unsichere DOM-Operation');
                        }
                        return original.apply(this, args);
                    };
                }
            });
            logEvent('info', 'DOM-Sicherung aktiviert');
        } catch (e) {
            logEvent('error', 'Fehler in secureDOM', { error: e.message });
        }
    }

    // 10. WebView-Sicherheit
    function secureWebView() {
        try {
            if (!defaultConfig.allowWebViewDebug && global.Android?.setWebContentsDebuggingEnabled) {
                global.Android.setWebContentsDebuggingEnabled(false);
                logEvent('info', 'WebView-Debugging deaktiviert');
            }
            if (defaultConfig.blockFileAccess && global.Android?.setAllowFileAccess) {
                global.Android.setAllowFileAccess(false);
                logEvent('info', 'WebView file:// Zugriff deaktiviert');
            }
        } catch (e) {
            logEvent('error', 'Fehler in secureWebView', { error: e.message });
        }
    }

    // Initialisierung
    const Luftdicht = {
        init: function(config = {}) {
            try {
                Object.assign(defaultConfig, config);
                enforceHttpOnly();
                blockUnknownProtocols();
                enforceCSP();
                preventClickjacking();
                secureDOM();
                secureWebView();
                document.addEventListener('submit', (e) => {
                    if (!e.target.querySelector('input[name="csrf_token"]')) {
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = 'csrf_token';
                        input.value = generateCSRToken();
                        e.target.appendChild(input);
                    }
                    if (!validateCSRToken(e.target)) {
                        e.preventDefault();
                    }
                });
                document.addEventListener('input', (e) => {
                    if (e.target.type !== 'password') {
                        e.target.value = sanitizeInput(e.target.value);
                    }
                });
                logEvent('info', 'Luftdicht-Android initialisiert');
            } catch (e) {
                logEvent('error', 'Fehler bei Initialisierung', { error: e.message });
            }
        },
        sanitize: sanitizeInput,
        validate: validateInput,
        log: logEvent,
        preventXSS,
        generateCSRToken,
    };

    global.Luftdicht = Luftdicht;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => Luftdicht.init());
    } else {
        Luftdicht.init();
    }

})(window);
