/**
 * 🔓 NIS2/ISO27001 SECURITY SYSTEM MIT AI LEAK DETECTION
 * Erweiterte Erkennung für DeepSeek, ChatGPT und andere AI-Tools
 * Beacon zu localhost:3000 erlaubt, Fetch komplett befreit
 */

(function() {
    'use strict';
    
    console.clear();
    
    // ==================== ERWEITERTE AI LEAK DETECTION ====================
    const AI_SECURITY_CONFIG = {
        // AI PLATTFORMEN DETECTION
        AI_PLATFORMS: {
            DEEPSEEK: {
                NAME: 'DeepSeek',
                DOMAINS: [
                    'deepseek.com',
                    'api.deepseek.com',
                    'chat.deepseek.com',
                    'platform.deepseek.ai'
                ],
                API_PATTERNS: [
                    /deepseek.*api/i,
                    /api.*deepseek/i,
                    /deepseek.*chat/i,
                    /deepseek.*v1/i
                ],
                USER_AGENTS: [
                    'deepseek',
                    'deepseek-ai',
                    'deepseek-chat'
                ],
                COOKIE_PATTERNS: [
                    /deepseek_session/i,
                    /deepseek_token/i,
                    /_ds_/i
                ],
                LOCAL_STORAGE_KEYS: [
                    'deepseek_',
                    'ds_',
                    'deepseek_chat_'
                ]
            },
            
            CHATGPT: {
                NAME: 'ChatGPT/OpenAI',
                DOMAINS: [
                    'openai.com',
                    'chat.openai.com',
                    'api.openai.com',
                    'platform.openai.com',
                    'chatgpt.com'
                ],
                API_PATTERNS: [
                    /openai.*api/i,
                    /api.*openai/i,
                    /chatgpt.*api/i,
                    /gpt.*api/i,
                    /v1.*chat\/completions/i
                ],
                USER_AGENTS: [
                    'chatgpt',
                    'openai',
                    'gpt-',
                    'chatgpt-web'
                ],
                COOKIE_PATTERNS: [
                    /_openai_session/i,
                    /_chatgpt_/i,
                    /__Secure-next-auth/i
                ],
                LOCAL_STORAGE_KEYS: [
                    'openai_',
                    'chatgpt_',
                    'nextauth_',
                    'oai_'
                ]
            },
            
            CLAUDE: {
                NAME: 'Claude/Anthropic',
                DOMAINS: [
                    'anthropic.com',
                    'claude.ai',
                    'console.anthropic.com'
                ],
                API_PATTERNS: [
                    /anthropic.*api/i,
                    /api.*anthropic/i,
                    /claude.*api/i,
                    /v1.*messages/i
                ],
                USER_AGENTS: [
                    'claude',
                    'anthropic',
                    'claude-web'
                ]
            },
            
            GEMINI: {
                NAME: 'Gemini/Google',
                DOMAINS: [
                    'gemini.google.com',
                    'ai.google.dev',
                    'generativelanguage.googleapis.com'
                ],
                API_PATTERNS: [
                    /gemini.*api/i,
                    /generativelanguage.*api/i
                ]
            },
            
            GENERAL_AI: {
                NAME: 'Allgemeine AI-Tools',
                DETECTION_PATTERNS: [
                    // API Key Patterns
                    /sk-[a-zA-Z0-9]{48}/i, // OpenAI Key
                    /sk-[a-zA-Z0-9_-]{20,}/i, // Allgemeine Secret Keys
                    /[a-zA-Z0-9]{32,}/i, // Allgemeine lange Tokens
                    
                    // Prompt Leakage
                    /system.*prompt/i,
                    /user.*prompt/i,
                    /assistant.*prompt/i,
                    
                    // AI Conversation Patterns
                    /role.*:\s*(system|user|assistant)/i,
                    /content.*:\s*".*"/i,
                    /messages.*\[.*\]/i,
                    
                    // Model Names
                    /model.*:\s*(gpt|claude|gemini|llama|mistral)/i,
                    /(gpt-4|gpt-3\.5|claude-3|claude-2|gemini-pro)/i,
                    
                    // AI Service Patterns
                    /temperature.*:\s*\d+\.?\d*/i,
                    /max_tokens.*:\s*\d+/i,
                    /top_p.*:\s*\d+\.?\d*/i
                ]
            }
        },
        
        // LEAK DETECTION LEVELS
        DETECTION_LEVELS: {
            LOW: {
                name: 'Niedrig',
                scanFrequency: 30000, // 30 Sekunden
                alertThreshold: 3,
                actions: ['LOG', 'WARN']
            },
            MEDIUM: {
                name: 'Mittel',
                scanFrequency: 15000, // 15 Sekunden
                alertThreshold: 2,
                actions: ['LOG', 'WARN', 'BLOCK_SENSITIVE']
            },
            HIGH: {
                name: 'Hoch',
                scanFrequency: 5000, // 5 Sekunden
                alertThreshold: 1,
                actions: ['LOG', 'WARN', 'BLOCK_ALL', 'REDACT']
            }
        },
        
        // CURRENT CONFIG
        CURRENT_LEVEL: 'HIGH',
        REAL_TIME_SCANNING: true,
        DATA_REDACTION: true,
        AUTO_BLOCKING: true
    };
    
    // ==================== AI LEAK DETECTION SYSTEM ====================
    class AILeakDetectionSystem {
        constructor() {
            this.detectedLeaks = [];
            this.aiActivities = [];
            this.securityAlerts = [];
            this.scanHistory = [];
            this.protectedData = new Set();
            
            this.initializeAIDetection();
            console.log('%c🤖 AI LEAK DETECTION INITIALISIERT (DeepSeek + ChatGPT)', 
                        'color: #FF6B6B; font-weight: bold;');
        }
        
        initializeAIDetection() {
            // 1. Initial Scan
            this.performInitialScan();
            
            // 2. Real-time Monitoring
            this.setupRealTimeMonitoring();
            
            // 3. Network Interception
            this.setupNetworkInterception();
            
            // 4. Clipboard Protection
            this.setupClipboardProtection();
            
            // 5. Form Protection
            this.setupFormProtection();
            
            // 6. Storage Monitoring
            this.setupStorageMonitoring();
        }
        
        performInitialScan() {
            console.group('%c🔍 INITIAL AI LEAK SCAN:', 'color: #3498db;');
            
            const scanResults = {
                deepseekFound: this.scanForDeepSeek(),
                chatgptFound: this.scanForChatGPT(),
                aiPatternsFound: this.scanForAIPatterns(),
                sensitiveDataFound: this.scanForSensitiveData(),
                cookies: this.scanCookies(),
                localStorage: this.scanLocalStorage(),
                sessionStorage: this.scanSessionStorage()
            };
            
            console.log('📊 Scan Results:', scanResults);
            
            if (scanResults.deepseekFound || scanResults.chatgptFound) {
                console.warn('⚠️ AI Plattformen erkannt!');
                this.createAlert('AI_PLATFORM_DETECTED', {
                    platforms: [
                        scanResults.deepseekFound ? 'DeepSeek' : null,
                        scanResults.chatgptFound ? 'ChatGPT' : null
                    ].filter(Boolean),
                    severity: 'HIGH'
                });
            }
            
            if (scanResults.aiPatternsFound.length > 0) {
                console.warn(`⚠️ ${scanResults.aiPatternsFound.length} AI Patterns erkannt`);
                this.createAlert('AI_PATTERNS_DETECTED', {
                    count: scanResults.aiPatternsFound.length,
                    patterns: scanResults.aiPatternsFound.slice(0, 3),
                    severity: 'MEDIUM'
                });
            }
            
            this.scanHistory.push({
                timestamp: new Date().toISOString(),
                type: 'INITIAL_SCAN',
                results: scanResults
            });
            
            console.groupEnd();
        }
        
        scanForDeepSeek() {
            const indicators = [];
            
            // Check User Agent
            if (navigator.userAgent.toLowerCase().includes('deepseek')) {
                indicators.push('User Agent contains DeepSeek');
            }
            
            // Check Cookies
            const cookies = document.cookie.toLowerCase();
            if (cookies.includes('deepseek')) {
                indicators.push('DeepSeek cookies found');
            }
            
            // Check Local Storage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key.toLowerCase().includes('deepseek')) {
                    indicators.push(`LocalStorage key: ${key}`);
                }
            }
            
            // Check Page Content
            const pageContent = document.body.innerText.toLowerCase();
            AI_SECURITY_CONFIG.AI_PLATFORMS.DEEPSEEK.API_PATTERNS.forEach(pattern => {
                if (pattern.test(pageContent)) {
                    indicators.push(`DeepSeek API pattern: ${pattern}`);
                }
            });
            
            return indicators.length > 0 ? indicators : false;
        }
        
        scanForChatGPT() {
            const indicators = [];
            
            // Check User Agent
            const userAgent = navigator.userAgent.toLowerCase();
            AI_SECURITY_CONFIG.AI_PLATFORMS.CHATGPT.USER_AGENTS.forEach(ua => {
                if (userAgent.includes(ua.toLowerCase())) {
                    indicators.push(`User Agent contains ${ua}`);
                }
            });
            
            // Check Cookies
            const cookies = document.cookie;
            AI_SECURITY_CONFIG.AI_PLATFORMS.CHATGPT.COOKIE_PATTERNS.forEach(pattern => {
                if (pattern.test(cookies)) {
                    indicators.push(`ChatGPT cookie pattern: ${pattern}`);
                }
            });
            
            // Check Local Storage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                AI_SECURITY_CONFIG.AI_PLATFORMS.CHATGPT.LOCAL_STORAGE_KEYS.forEach(lsKey => {
                    if (key.toLowerCase().includes(lsKey.toLowerCase()) || 
                        (value && value.toLowerCase().includes(lsKey.toLowerCase()))) {
                        indicators.push(`LocalStorage: ${key}`);
                    }
                });
            }
            
            // Check Page Content for API Keys
            const pageContent = document.body.innerText;
            const openAIKeyPattern = /sk-[a-zA-Z0-9]{48}/;
            if (openAIKeyPattern.test(pageContent)) {
                indicators.push('OpenAI API Key detected in page content');
            }
            
            // Check for ChatGPT specific patterns
            AI_SECURITY_CONFIG.AI_PLATFORMS.CHATGPT.API_PATTERNS.forEach(pattern => {
                if (pattern.test(pageContent)) {
                    indicators.push(`ChatGPT API pattern: ${pattern}`);
                }
            });
            
            return indicators.length > 0 ? indicators : false;
        }
        
        scanForAIPatterns() {
            const foundPatterns = [];
            const pageContent = document.body.innerText;
            
            AI_SECURITY_CONFIG.AI_PLATFORMS.GENERAL_AI.DETECTION_PATTERNS.forEach(pattern => {
                const matches = pageContent.match(pattern);
                if (matches) {
                    foundPatterns.push({
                        pattern: pattern.toString().substring(0, 50),
                        matches: matches.length,
                        sample: matches[0].substring(0, 100)
                    });
                }
            });
            
            return foundPatterns;
        }
        
        scanForSensitiveData() {
            const sensitiveData = [];
            const pageContent = document.body.innerText;
            
            // API Keys
            const apiKeyPatterns = [
                /sk-[a-zA-Z0-9_-]{20,}/gi,
                /[a-zA-Z0-9]{32,}/gi,
                /[a-zA-Z0-9_-]{20,}/gi
            ];
            
            apiKeyPatterns.forEach(pattern => {
                const matches = pageContent.match(pattern);
                if (matches) {
                    matches.forEach(match => {
                        if (match.length >= 20 && !this.isFalsePositive(match)) {
                            sensitiveData.push({
                                type: 'API_KEY',
                                value: this.redactData(match),
                                length: match.length
                            });
                        }
                    });
                }
            });
            
            // Email addresses
            const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
            const emails = pageContent.match(emailPattern);
            if (emails) {
                emails.forEach(email => {
                    sensitiveData.push({
                        type: 'EMAIL',
                        value: this.redactData(email),
                        domain: email.split('@')[1]
                    });
                });
            }
            
            // Personal data patterns
            const personalPatterns = [
                { pattern: /(\+49|0)[1-9][0-9]{3,14}/g, type: 'PHONE_DE' },
                { pattern: /\b\d{5}\b/g, type: 'ZIP_CODE' },
                { pattern: /\b[A-ZÄÖÜ][a-zäöüß]+\s[A-ZÄÖÜ][a-zäöüß]+\b/g, type: 'FULL_NAME' }
            ];
            
            personalPatterns.forEach(({ pattern, type }) => {
                const matches = pageContent.match(pattern);
                if (matches) {
                    matches.forEach(match => {
                        sensitiveData.push({
                            type: type,
                            value: this.redactData(match),
                            originalLength: match.length
                        });
                    });
                }
            });
            
            return sensitiveData;
        }
        
        scanCookies() {
            const aiCookies = [];
            const cookies = document.cookie.split(';');
            
            cookies.forEach(cookie => {
                const [name, value] = cookie.trim().split('=');
                
                // Check for AI related cookies
                const aiPatterns = [
                    /deepseek/i,
                    /openai/i,
                    /chatgpt/i,
                    /claude/i,
                    /anthropic/i,
                    /gemini/i,
                    /ai[_-]?token/i,
                    /api[_-]?key/i
                ];
                
                aiPatterns.forEach(pattern => {
                    if (pattern.test(name) || (value && pattern.test(value))) {
                        aiCookies.push({
                            name: this.redactData(name),
                            value: this.redactData(value?.substring(0, 20)),
                            pattern: pattern.toString()
                        });
                    }
                });
            });
            
            return aiCookies;
        }
        
        scanLocalStorage() {
            const aiItems = [];
            
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                
                const aiPatterns = [
                    /deepseek/i,
                    /openai/i,
                    /chatgpt/i,
                    /claude/i,
                    /ai[_-]?/i,
                    /gpt[_-]?/i,
                    /llm/i,
                    /model/i,
                    /prompt/i
                ];
                
                aiPatterns.forEach(pattern => {
                    if (pattern.test(key) || (value && pattern.test(value))) {
                        aiItems.push({
                            key: this.redactData(key),
                            valuePreview: this.redactData(value?.substring(0, 50)),
                            pattern: pattern.toString()
                        });
                    }
                });
            }
            
            return aiItems;
        }
        
        scanSessionStorage() {
            const aiItems = [];
            
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const value = sessionStorage.getItem(key);
                
                const aiPatterns = [
                    /ai[_-]?session/i,
                    /chat[_-]?history/i,
                    /prompt[_-]?cache/i,
                    /conversation[_-]?/i
                ];
                
                aiPatterns.forEach(pattern => {
                    if (pattern.test(key) || (value && pattern.test(value))) {
                        aiItems.push({
                            key: this.redactData(key),
                            valuePreview: this.redactData(value?.substring(0, 50))
                        });
                    }
                });
            }
            
            return aiItems;
        }
        
        setupRealTimeMonitoring() {
            if (!AI_SECURITY_CONFIG.REAL_TIME_SCANNING) return;
            
            // Periodische Scans
            const scanFrequency = AI_SECURITY_CONFIG.DETECTION_LEVELS[AI_SECURITY_CONFIG.CURRENT_LEVEL].scanFrequency;
            
            setInterval(() => {
                this.performRealTimeScan();
            }, scanFrequency);
            
            console.log(`⏱️ Real-time Monitoring aktiv (Scan alle ${scanFrequency/1000}s)`);
        }
        
        performRealTimeScan() {
            const scanId = Date.now();
            
            // Mutation Observer für DOM Änderungen
            this.scanDOMChanges();
            
            // Network Activity Scan
            this.scanNetworkActivity();
            
            // User Input Monitoring
            this.scanUserInputs();
            
            this.scanHistory.push({
                id: scanId,
                timestamp: new Date().toISOString(),
                type: 'REAL_TIME_SCAN',
                findings: this.getCurrentFindings()
            });
            
            // Cleanup old scans
            if (this.scanHistory.length > 100) {
                this.scanHistory = this.scanHistory.slice(-50);
            }
        }
        
        setupNetworkInterception() {
            // Intercept Fetch für AI API Aufrufe
            if (window.fetch) {
                const originalFetch = window.fetch;
                const self = this;
                
                window.fetch = async function(...args) {
                    const [resource, options] = args;
                    const url = resource instanceof Request ? resource.url : resource.toString();
                    
                    // Check for AI API calls
                    const isAIApi = self.detectAIApiCall(url, options);
                    
                    if (isAIApi.detected) {
                        self.createAlert('AI_API_CALL_DETECTED', {
                            url: self.redactData(url),
                            platform: isAIApi.platform,
                            method: options?.method || 'GET',
                            severity: 'HIGH',
                            timestamp: new Date().toISOString()
                        });
                        
                        // Log the attempt
                        self.aiActivities.push({
                            type: 'API_CALL',
                            platform: isAIApi.platform,
                            url: self.redactData(url),
                            timestamp: new Date().toISOString(),
                            blocked: false // Nur Monitoring, keine Blockierung
                        });
                        
                        console.warn(`⚠️ AI API Aufruf erkannt: ${isAIApi.platform} - ${url.substring(0, 100)}...`);
                    }
                    
                    // Original Fetch ausführen
                    return originalFetch.apply(this, arguments);
                };
            }
            
            console.log('📡 Network Interception für AI APIs aktiv');
        }
        
        detectAIApiCall(url, options) {
            const urlLower = url.toLowerCase();
            
            // DeepSeek Detection
            for (const domain of AI_SECURITY_CONFIG.AI_PLATFORMS.DEEPSEEK.DOMAINS) {
                if (urlLower.includes(domain)) {
                    return { detected: true, platform: 'DeepSeek' };
                }
            }
            
            // ChatGPT/OpenAI Detection
            for (const domain of AI_SECURITY_CONFIG.AI_PLATFORMS.CHATGPT.DOMAINS) {
                if (urlLower.includes(domain)) {
                    return { detected: true, platform: 'ChatGPT/OpenAI' };
                }
            }
            
            // Claude Detection
            for (const domain of AI_SECURITY_CONFIG.AI_PLATFORMS.CLAUDE.DOMAINS) {
                if (urlLower.includes(domain)) {
                    return { detected: true, platform: 'Claude' };
                }
            }
            
            // Check for AI API patterns in URL
            const aiPatterns = [
                ...AI_SECURITY_CONFIG.AI_PLATFORMS.DEEPSEEK.API_PATTERNS,
                ...AI_SECURITY_CONFIG.AI_PLATFORMS.CHATGPT.API_PATTERNS,
                ...AI_SECURITY_CONFIG.AI_PLATFORMS.CLAUDE.API_PATTERNS,
                ...AI_SECURITY_CONFIG.AI_PLATFORMS.GEMINI.API_PATTERNS
            ];
            
            for (const pattern of aiPatterns) {
                if (pattern.test(url)) {
                    return { detected: true, platform: 'AI_API' };
                }
            }
            
            // Check request body for AI content
            if (options && options.body) {
                const bodyStr = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
                
                // Check for AI conversation patterns
                if (bodyStr.includes('messages') && 
                    (bodyStr.includes('role') || bodyStr.includes('content'))) {
                    return { detected: true, platform: 'AI_CONVERSATION' };
                }
                
                // Check for model names
                const modelPattern = /model.*:\s*"(gpt|claude|gemini|llama|mistral)/i;
                if (modelPattern.test(bodyStr)) {
                    return { detected: true, platform: 'AI_MODEL' };
                }
            }
            
            return { detected: false, platform: null };
        }
        
        setupClipboardProtection() {
            // Clipboard Read Protection
            document.addEventListener('copy', (e) => {
                const selectedText = window.getSelection().toString();
                const hasSensitiveData = this.containsSensitiveData(selectedText);
                
                if (hasSensitiveData) {
                    console.warn('⚠️ Versuch sensitiver Daten zu kopieren erkannt');
                    this.createAlert('CLIPBOARD_COPY_ATTEMPT', {
                        dataPreview: this.redactData(selectedText.substring(0, 100)),
                        dataType: hasSensitiveData.type,
                        severity: 'MEDIUM'
                    });
                    
                    // Optional: Blockieren oder Daten redacten
                    if (AI_SECURITY_CONFIG.DATA_REDACTION) {
                        e.preventDefault();
                        const redactedText = this.redactSensitiveText(selectedText);
                        e.clipboardData.setData('text/plain', redactedText);
                        console.log('📋 Daten wurden automatisch redacted');
                    }
                }
            });
            
            // Clipboard Write Protection
            document.addEventListener('paste', (e) => {
                const pastedText = e.clipboardData.getData('text');
                const hasSensitiveData = this.containsSensitiveData(pastedText);
                
                if (hasSensitiveData) {
                    console.warn('⚠️ Versuch sensitiver Daten einzufügen erkannt');
                    this.createAlert('CLIPBOARD_PASTE_ATTEMPT', {
                        dataPreview: this.redactData(pastedText.substring(0, 100)),
                        dataType: hasSensitiveData.type,
                        severity: 'MEDIUM'
                    });
                    
                    if (AI_SECURITY_CONFIG.AUTO_BLOCKING) {
                        e.preventDefault();
                        console.log('📋 Einfügen blockiert - sensitive Daten erkannt');
                    }
                }
            });
            
            console.log('📋 Clipboard Protection aktiv');
        }
        
        setupFormProtection() {
            // Form Submission Monitoring
            document.addEventListener('submit', (e) => {
                const form = e.target;
                const formData = new FormData(form);
                
                // Check for sensitive data in form
                for (let [name, value] of formData.entries()) {
                    if (typeof value === 'string') {
                        const hasSensitiveData = this.containsSensitiveData(value);
                        
                        if (hasSensitiveData) {
                            console.warn(`⚠️ Sensitive Daten in Formularfeld: ${name}`);
                            this.createAlert('FORM_SENSITIVE_DATA', {
                                fieldName: name,
                                dataType: hasSensitiveData.type,
                                severity: 'HIGH',
                                formAction: form.action
                            });
                            
                            // Optional: Form submission blockieren
                            if (AI_SECURITY_CONFIG.AUTO_BLOCKING && hasSensitiveData.severity === 'HIGH') {
                                e.preventDefault();
                                alert('⚠️ Formular enthält sensitive Daten. Submission blockiert.');
                                return;
                            }
                        }
                    }
                }
            });
            
            // Input Field Monitoring
            document.addEventListener('input', (e) => {
                if (e.target.tagName === 'TEXTAREA' || e.target.tagName === 'INPUT') {
                    const value = e.target.value;
                    
                    // Check for AI API keys in input
                    const apiKeyPattern = /sk-[a-zA-Z0-9]{48}/;
                    if (apiKeyPattern.test(value)) {
                        console.warn('⚠️ AI API Key in Input-Feld erkannt');
                        this.createAlert('AI_API_KEY_INPUT', {
                            field: e.target.name || e.target.id,
                            severity: 'HIGH'
                        });
                        
                        if (AI_SECURITY_CONFIG.DATA_REDACTION) {
                            // Automatisch redacten
                            e.target.value = e.target.value.replace(apiKeyPattern, 'sk-***REDACTED***');
                        }
                    }
                }
            });
            
            console.log('📝 Form Protection aktiv');
        }
        
        setupStorageMonitoring() {
            // LocalStorage Monitoring
            const originalSetItem = localStorage.setItem;
            localStorage.setItem = function(key, value) {
                const self = window.AISystem || this;
                
                // Check for sensitive data
                if (self && self.containsSensitiveData) {
                    const hasSensitiveData = self.containsSensitiveData(value);
                    
                    if (hasSensitiveData) {
                        console.warn(`⚠️ Sensitive Daten in LocalStorage: ${key}`);
                        self.createAlert('LOCALSTORAGE_SENSITIVE_DATA', {
                            key: self.redactData(key),
                            dataType: hasSensitiveData.type,
                            severity: 'MEDIUM'
                        });
                        
                        // Optional: Blockieren
                        if (AI_SECURITY_CONFIG.AUTO_BLOCKING && hasSensitiveData.severity === 'HIGH') {
                            throw new Error('Sensitive Daten können nicht in LocalStorage gespeichert werden');
                        }
                    }
                }
                
                return originalSetItem.call(this, key, value);
            };
            
            // SessionStorage Monitoring
            const originalSessionSetItem = sessionStorage.setItem;
            sessionStorage.setItem = function(key, value) {
                const self = window.AISystem || this;
                
                if (self && self.containsSensitiveData) {
                    const hasSensitiveData = self.containsSensitiveData(value);
                    
                    if (hasSensitiveData) {
                        console.warn(`⚠️ Sensitive Daten in SessionStorage: ${key}`);
                        self.createAlert('SESSIONSTORAGE_SENSITIVE_DATA', {
                            key: self.redactData(key),
                            dataType: hasSensitiveData.type,
                            severity: 'MEDIUM'
                        });
                    }
                }
                
                return originalSessionSetItem.call(this, key, value);
            };
            
            console.log('💾 Storage Monitoring aktiv');
        }
        
        containsSensitiveData(text) {
            if (!text) return false;
            
            // AI API Keys
            const aiKeyPatterns = [
                /sk-[a-zA-Z0-9]{48}/, // OpenAI
                /sk-[a-zA-Z0-9_-]{20,}/, // Allgemeine Secret Keys
                /[a-zA-Z0-9]{32,}/ // Lange Tokens
            ];
            
            for (const pattern of aiKeyPatterns) {
                if (pattern.test(text)) {
                    return { type: 'AI_API_KEY', severity: 'HIGH' };
                }
            }
            
            // DeepSeek Patterns
            for (const pattern of AI_SECURITY_CONFIG.AI_PLATFORMS.DEEPSEEK.API_PATTERNS) {
                if (pattern.test(text)) {
                    return { type: 'DEEPSEEK_API', severity: 'MEDIUM' };
                }
            }
            
            // ChatGPT Patterns
            for (const pattern of AI_SECURITY_CONFIG.AI_PLATFORMS.CHATGPT.API_PATTERNS) {
                if (pattern.test(text)) {
                    return { type: 'CHATGPT_API', severity: 'MEDIUM' };
                }
            }
            
            // AI Conversation Patterns
            const aiConversationPatterns = [
                /role.*:\s*(system|user|assistant)/i,
                /content.*:\s*".*"/i,
                /messages.*\[.*\]/i
            ];
            
            let aiConversationCount = 0;
            for (const pattern of aiConversationPatterns) {
                const matches = text.match(pattern);
                if (matches) aiConversationCount += matches.length;
            }
            
            if (aiConversationCount >= 2) {
                return { type: 'AI_CONVERSATION', severity: 'MEDIUM' };
            }
            
            // Personal Data
            const personalPatterns = [
                { pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, type: 'EMAIL', severity: 'MEDIUM' },
                { pattern: /(\+49|0)[1-9][0-9]{3,14}/, type: 'PHONE_DE', severity: 'MEDIUM' },
                { pattern: /\b\d{5}\b/, type: 'ZIP_CODE', severity: 'LOW' }
            ];
            
            for (const { pattern, type, severity } of personalPatterns) {
                if (pattern.test(text)) {
                    return { type, severity };
                }
            }
            
            return false;
        }
        
        redactData(data) {
            if (!data || typeof data !== 'string') return data;
            
            if (AI_SECURITY_CONFIG.DATA_REDACTION) {
                // API Keys redacten
                data = data.replace(/sk-[a-zA-Z0-9]{48}/g, 'sk-***REDACTED***');
                data = data.replace(/sk-[a-zA-Z0-9_-]{20,}/g, 'sk-***REDACTED***');
                
                // Emails redacten
                data = data.replace(/([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})/g, 
                    '***@$2.$3');
                
                // Telefonnummern redacten
                data = data.replace(/(\+49|0)[1-9][0-9]{3,14}/g, '***REDACTED***');
            }
            
            return data;
        }
        
        redactSensitiveText(text) {
            if (!text) return text;
            
            // API Keys
            text = text.replace(/sk-[a-zA-Z0-9]{48}/g, 'sk-***REDACTED***');
            text = text.replace(/sk-[a-zA-Z0-9_-]{20,}/g, 'sk-***REDACTED***');
            
            // Emails
            text = text.replace(/([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})/g, 
                '***@$2.$3');
            
            // Phone numbers
            text = text.replace(/(\+49|0)[1-9][0-9]{3,14}/g, '***REDACTED***');
            
            return text;
        }
        
        isFalsePositive(text) {
            // Check for common false positives
            const falsePositives = [
                'data:text/html',
                'blob:',
                'http://',
                'https://',
                'localhost',
                '127.0.0.1',
                'example.com',
                'test.com',
                'placeholder'
            ];
            
            return falsePositives.some(fp => text.includes(fp));
        }
        
        createAlert(type, details) {
            const alert = {
                id: Date.now() + Math.random().toString(36).substr(2, 9),
                type: type,
                timestamp: new Date().toISOString(),
                details: details,
                severity: details.severity || 'MEDIUM',
                handled: false
            };
            
            this.securityAlerts.push(alert);
            
            // Limit alerts array
            if (this.securityAlerts.length > 100) {
                this.securityAlerts = this.securityAlerts.slice(-50);
            }
            
            return alert;
        }
        
        scanDOMChanges() {
            // Mutation Observer für neue Elemente
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    if (mutation.addedNodes.length > 0) {
                        mutation.addedNodes.forEach((node) => {
                            if (node.nodeType === 1) { // Element node
                                this.checkNodeForSensitiveData(node);
                            }
                        });
                    }
                });
            });
            
            observer.observe(document.body, {
                childList: true,
                subtree: true
            });
        }
        
        checkNodeForSensitiveData(node) {
            if (node.nodeType === 3) { // Text node
                const text = node.textContent;
                const hasSensitiveData = this.containsSensitiveData(text);
                
                if (hasSensitiveData) {
                    console.warn('⚠️ Sensitive Daten in neuem DOM-Element erkannt');
                    this.createAlert('DOM_SENSITIVE_DATA', {
                        nodeType: node.parentNode?.tagName || 'unknown',
                        dataType: hasSensitiveData.type,
                        severity: hasSensitiveData.severity
                    });
                    
                    // Optional: Daten redacten
                    if (AI_SECURITY_CONFIG.DATA_REDACTION && hasSensitiveData.severity === 'HIGH') {
                        node.textContent = this.redactSensitiveText(text);
                    }
                }
            } else if (node.nodeType === 1) {
                // Check attributes
                Array.from(node.attributes).forEach(attr => {
                    if (this.containsSensitiveData(attr.value)) {
                        console.warn(`⚠️ Sensitive Daten in Attribut: ${attr.name}`);
                    }
                });
                
                // Recursively check children
                node.childNodes.forEach(child => {
                    this.checkNodeForSensitiveData(child);
                });
            }
        }
        
        scanNetworkActivity() {
            // Überwache aktive Verbindungen
            const performanceEntries = performance.getEntriesByType('resource');
            
            performanceEntries.forEach(entry => {
                const url = entry.name;
                
                // Check for AI API calls
                const isAIApi = this.detectAIApiCall(url, {});
                
                if (isAIApi.detected && !this.aiActivities.some(a => a.url === url)) {
                    this.aiActivities.push({
                        type: 'NETWORK_RESOURCE',
                        platform: isAIApi.platform,
                        url: this.redactData(url),
                        timestamp: new Date().toISOString(),
                        duration: entry.duration
                    });
                }
            });
        }
        
        scanUserInputs() {
            // Überwache aktive Input-Felder
            const inputs = document.querySelectorAll('input[type="text"], input[type="password"], textarea');
            
            inputs.forEach(input => {
                if (input.value && this.containsSensitiveData(input.value)) {
                    const event = {
                        type: 'USER_INPUT_SENSITIVE',
                        element: input.tagName,
                        id: input.id || input.name || 'unknown',
                        timestamp: new Date().toISOString()
                    };
                    
                    // Check if this input was already logged
                    const existing = this.aiActivities.find(a => 
                        a.type === event.type && a.id === event.id);
                    
                    if (!existing) {
                        this.aiActivities.push(event);
                    }
                }
            });
        }
        
        getCurrentFindings() {
            return {
                leaks: this.detectedLeaks.length,
                alerts: this.securityAlerts.length,
                activities: this.aiActivities.length,
                scans: this.scanHistory.length,
                protectedItems: this.protectedData.size
            };
        }
        
        getDetectionSummary() {
            return {
                config: {
                    level: AI_SECURITY_CONFIG.CURRENT_LEVEL,
                    realTimeScanning: AI_SECURITY_CONFIG.REAL_TIME_SCANNING,
                    dataRedaction: AI_SECURITY_CONFIG.DATA_REDACTION,
                    autoBlocking: AI_SECURITY_CONFIG.AUTO_BLOCKING
                },
                findings: this.getCurrentFindings(),
                recentAlerts: this.securityAlerts.slice(-5).map(a => ({
                    type: a.type,
                    severity: a.severity,
                    timestamp: a.timestamp
                })),
                detectedPlatforms: this.getDetectedPlatforms()
            };
        }
        
        getDetectedPlatforms() {
            const platforms = new Set();
