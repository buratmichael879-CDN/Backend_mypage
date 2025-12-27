// server7-image-protection.js - COMPLETE VERSION
class Server7ImageProtector {
    constructor(options = {}) {
        // Schutz-Status
        this.protectedImages = new WeakMap();
        this.originalSources = new Map();
        this.encryptedSources = new Map();
        this.observer = null;
        
        // Konfiguration
        this.options = {
            protectPNG: true,
            protectSVG: true,
            protectJPG: true,
            protectGIF: true,
            protectWEBP: true,
            protectAll: true,
            enableWatermark: false, // Digitales Wasserzeichen
            preventDownload: true,
            preventRightClick: true,
            preventInspect: true,
            lazyLoad: true,
            blurUnloaded: true,
            addTimestamps: true,
            cacheBusting: true,
            encryption: false, // Experimentell
            maxRetries: 3,
            retryDelay: 1000,
            debug: false,
            ...options
        };
        
        // Bild-Erkennung
        this.imageExtensions = /\.(png|svg|jpg|jpeg|gif|webp|bmp|tiff|ico|avif|jfif)(\?.*)?$/i;
        this.dataUrlPattern = /^data:image\/(png|svg\+xml|jpeg|gif|webp|bmp|tiff);base64,/i;
        this.svgPattern = /\.svg(\?.*)?$/i;
        this.externalUrlPattern = /^https?:\/\//i;
        
        // Watermark Canvas
        this.watermarkCanvas = null;
        this.watermarkCache = new Map();
        
        // Performance Tracking
        this.performance = {
            startTime: Date.now(),
            imagesProtected: 0,
            errors: 0,
            blockedAttempts: 0
        };
        
        this.init();
    }
    
    // ==================== INITIALISIERUNG ====================
    
    init() {
        console.log('🛡️ Server7 Image Protection v2.0 initialisiert');
        
        // Warte auf DOM
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.startProtection());
        } else {
            this.startProtection();
        }
        
        // Global verfügbar machen
        window.server7ImageProtector = this;
    }
    
    startProtection() {
        console.log('🚀 Starte Bildschutz...');
        
        // 1. Vorhandene Bilder schützen
        this.protectExistingImages();
        
        // 2. Observer für neue Bilder
        this.setupMutationObserver();
        
        // 3. Event Listener
        this.setupEventListeners();
        
        // 4. Performance Monitoring
        this.setupPerformanceMonitor();
        
        // 5. Periodic Check
        this.setupPeriodicCheck();
        
        console.log('✅ Bildschutz aktiv - Alle Bilder werden geschützt');
    }
    
    // ==================== BILD-ERKENNUNG ====================
    
    isImageElement(element) {
        const tag = element.tagName.toLowerCase();
        return tag === 'img' || 
               tag === 'image' || 
               tag === 'picture' ||
               element.style.backgroundImage ||
               element.hasAttribute('data-img') ||
               element.classList.contains('image-container');
    }
    
    getImageSource(element) {
        if (element.tagName.toLowerCase() === 'img') {
            return element.src || 
                   element.dataset.src ||
                   element.getAttribute('data-original') ||
                   element.currentSrc;
        }
        
        if (element.tagName.toLowerCase() === 'image') {
            return element.href?.baseVal || 
                   element.getAttribute('xlink:href') ||
                   element.getAttribute('href');
        }
        
        if (element.style.backgroundImage) {
            const match = element.style.backgroundImage.match(/url\(["']?([^"']+)["']?\)/i);
            return match ? match[1] : null;
        }
        
        // Für CSS Klassen und Data-Attribute
        if (element.dataset.bg) return element.dataset.bg;
        if (element.dataset.image) return element.dataset.image;
        if (element.dataset.srcset) return element.dataset.srcset.split(',')[0].split(' ')[0];
        
        return null;
    }
    
    shouldProtectImage(src) {
        if (!src || typeof src !== 'string') return false;
        
        // Data URLs immer schützen
        if (this.dataUrlPattern.test(src)) {
            return true;
        }
        
        // Externe URLs prüfen
        if (this.externalUrlPattern.test(src)) {
            const url = new URL(src);
            const path = url.pathname.toLowerCase();
            
            // Prüfe nach Bild-Endungen
            if (this.imageExtensions.test(path)) {
                const ext = path.match(this.imageExtensions)[1];
                
                // Prüfe Optionen
                if (ext === 'png' && this.options.protectPNG) return true;
                if (ext === 'svg' && this.options.protectSVG) return true;
                if ((ext === 'jpg' || ext === 'jpeg') && this.options.protectJPG) return true;
                if (ext === 'gif' && this.options.protectGIF) return true;
                if (ext === 'webp' && this.options.protectWEBP) return true;
                if (this.options.protectAll) return true;
            }
        }
        
        // Relative Pfade
        if (this.imageExtensions.test(src.split('?')[0])) {
            return true;
        }
        
        return false;
    }
    
    // ==================== HAUPT-SCHUTZFUNKTIONEN ====================
    
    protectExistingImages() {
        // Finde alle Bilder
        const selectors = [
            'img',
            'image',
            'picture',
            '[style*="background-image"]',
            '[data-bg]',
            '[data-image]',
            '[data-src]',
            '.lazy',
            '.lazy-load',
            '.image',
            '.photo',
            '.img',
            '.bg-image'
        ];
        
        const images = document.querySelectorAll(selectors.join(', '));
        console.log(`📸 ${images.length} Bilder gefunden`);
        
        images.forEach((img, index) => {
            this.protectSingleImage(img, index);
        });
    }
    
    protectSingleImage(element, delayIndex = 0) {
        try {
            // Prüfe ob bereits geschützt
            if (this.protectedImages.has(element)) {
                return;
            }
            
            // Prüfe ob es ein Bild ist
            if (!this.isImageElement(element)) {
                return;
            }
            
            // Hole Quelle
            const originalSrc = this.getImageSource(element);
            if (!originalSrc) {
                return;
            }
            
            // Prüfe ob Schutz benötigt wird
            if (!this.shouldProtectImage(originalSrc)) {
                if (this.options.debug) console.log(`ℹ️ Bild nicht geschützt: ${originalSrc.substring(0, 50)}`);
                return;
            }
            
            // Verzögerung für Performance
            setTimeout(() => {
                this.applyProtection(element, originalSrc);
            }, delayIndex * 30);
            
        } catch (error) {
            this.performance.errors++;
            if (this.options.debug) console.error('Fehler beim Bildschutz:', error);
        }
    }
    
    applyProtection(element, originalSrc) {
        try {
            // Markiere als geschützt
            this.protectedImages.set(element, {
                timestamp: Date.now(),
                originalSrc: originalSrc,
                attempts: 0
            });
            
            this.originalSources.set(element, originalSrc);
            
            // Wende Schutzmethoden an
            this.applyProtectionMethods(element, originalSrc);
            
            // Erfolg tracken
            this.performance.imagesProtected++;
            
            if (this.options.debug) {
                console.log(`✅ Bild geschützt: ${element.tagName} - ${originalSrc.substring(0, 60)}...`);
            }
            
        } catch (error) {
            console.warn('Bildschutz fehlgeschlagen:', error);
            this.performance.errors++;
        }
    }
    
    applyProtectionMethods(element, originalSrc) {
        // 1. Source Manipulation
        this.manipulateImageSource(element, originalSrc);
        
        // 2. Event Protection
        this.addEventProtection(element);
        
        // 3. Visual Protection
        this.addVisualProtection(element);
        
        // 4. Watermark (optional)
        if (this.options.enableWatermark) {
            this.addWatermark(element);
        }
        
        // 5. Lazy Loading (optional)
        if (this.options.lazyLoad) {
            this.setupLazyLoading(element);
        }
    }
    
    // ==================== SCHUTZ-METHODEN ====================
    
    manipulateImageSource(element, originalSrc) {
        if (element.tagName.toLowerCase() === 'img') {
            // Cache Busting
            let protectedSrc = originalSrc;
            
            if (this.options.cacheBusting) {
                protectedSrc = this.addCacheBusting(originalSrc);
            }
            
            if (this.options.addTimestamps) {
                protectedSrc = this.addTimestamp(protectedSrc);
            }
            
            // Temporäre Attribute setzen
            element.setAttribute('data-original-src', originalSrc);
            element.setAttribute('data-protected', 'true');
            element.setAttribute('data-protected-time', Date.now());
            
            // Encrypted Proxy (experimentell)
            if (this.options.encryption) {
                const encryptedSrc = this.encryptImageUrl(originalSrc);
                this.encryptedSources.set(element, encryptedSrc);
                element.setAttribute('data-encrypted', 'true');
            }
            
            // Setze geschützte Quelle
            setTimeout(() => {
                if (element.src !== protectedSrc) {
                    element.src = protectedSrc;
                }
            }, 10);
            
        } else if (element.style.backgroundImage) {
            // Für Background Images
            const protectedSrc = this.options.cacheBusting ? 
                this.addCacheBusting(originalSrc) : originalSrc;
            
            element.style.setProperty('--original-bg', `url("${originalSrc}")`);
            element.style.backgroundImage = `url("${protectedSrc}")`;
            element.setAttribute('data-bg-protected', 'true');
        }
    }
    
    addCacheBusting(url) {
        try {
            if (url.includes('?')) {
                return `${url}&_t=${Date.now()}`;
            } else {
                return `${url}?_t=${Date.now()}`;
            }
        } catch {
            return url;
        }
    }
    
    addTimestamp(url) {
        const timestamp = Math.floor(Date.now() / 60000); // Minute-Genauigkeit
        if (url.includes('?')) {
            return `${url}&_protect=${timestamp}`;
        } else {
            return `${url}?_protect=${timestamp}`;
        }
    }
    
    encryptImageUrl(url) {
        // Einfache URL "Verschlüsselung" (Base64)
        try {
            return `data:image/svg+xml;base64,${btoa(`<svg xmlns="http://www.w3.org/2000/svg">
                <image href="${url}" width="100%" height="100%"/>
                <text x="10" y="20" font-size="12" fill="red">🔒 PROTECTED</text>
            </svg>`)}`;
        } catch {
            return url;
        }
    }
    
    addEventProtection(element) {
        // Rechtsklick verhindern
        if (this.options.preventRightClick) {
            element.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                this.performance.blockedAttempts++;
                return false;
            }, true);
            
            element.addEventListener('dragstart', (e) => {
                e.preventDefault();
                return false;
            }, true);
        }
        
        // Copy Protection
        element.addEventListener('copy', (e) => {
            e.clipboardData.setData('text/plain', '🔒 Geschütztes Bild');
            e.preventDefault();
        }, true);
        
        // Inspect Protection
        if (this.options.preventInspect) {
            element.addEventListener('DOMNodeInserted', (e) => {
                // Verhindere Bild-Inspektion
                if (e.target === element && document.hidden) {
                    element.style.opacity = '0.01';
                    setTimeout(() => element.style.opacity = '', 100);
                }
            }, true);
        }
        
        // DevTools Detection
        element.addEventListener('mousedown', (e) => {
            if (e.ctrlKey && e.shiftKey) {
                // Ctrl+Shift+I oder Ctrl+Shift+C Kombination
                e.preventDefault();
                element.style.outline = '2px solid red';
                setTimeout(() => element.style.outline = '', 2000);
            }
        }, true);
    }
    
    addVisualProtection(element) {
        // CSS Protection hinzufügen
        if (!element.hasAttribute('data-server7-style')) {
            const styleId = 'server7-protection-' + Date.now();
            element.setAttribute('data-server7-style', styleId);
            
            // CSS hinzufügen
            const style = document.createElement('style');
            style.id = styleId;
            style.textContent = `
                [data-server7-style="${styleId}"] {
                    image-rendering: optimizeQuality;
                    -webkit-user-select: none;
                    -moz-user-select: none;
                    -ms-user-select: none;
                    user-select: none;
                    -webkit-user-drag: none;
                    -webkit-touch-callout: none;
                }
                
                [data-server7-style="${styleId}"]::after {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: linear-gradient(45deg, transparent 97%, rgba(255,0,0,0.05) 100%);
                    pointer-events: none;
                    z-index: 1;
                }
            `;
            
            document.head.appendChild(style);
        }
        
        // Blur Effekt für Lazy Loading
        if (this.options.blurUnloaded && element.tagName === 'IMG') {
            if (!element.complete) {
                element.style.filter = 'blur(10px)';
                element.style.transition = 'filter 0.5s ease';
                
                element.addEventListener('load', () => {
                    element.style.filter = 'blur(0px)';
                    setTimeout(() => element.style.filter = '', 500);
                });
            }
        }
    }
    
    addWatermark(element) {
        // Digitales Wasserzeichen (unsichtbar)
        if (!this.watermarkCanvas) {
            this.watermarkCanvas = document.createElement('canvas');
            this.watermarkCanvas.style.display = 'none';
            document.body.appendChild(this.watermarkCanvas);
        }
        
        // Wasserzeichen nur für große Bilder
        if (element.naturalWidth > 100 && element.naturalHeight > 100) {
            element.addEventListener('load', () => {
                this.applyDigitalWatermark(element);
            });
        }
    }
    
    applyDigitalWatermark(imgElement) {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            canvas.width = imgElement.naturalWidth;
            canvas.height = imgElement.naturalHeight;
            
            // Zeichne Originalbild
            ctx.drawImage(imgElement, 0, 0);
            
            // Füge unsichtbares Wasserzeichen hinzu
            ctx.font = '12px Arial';
            ctx.fillStyle = 'rgba(255, 255, 255, 0.01)';
            ctx.fillText(`SERVER7:${Date.now()}:${window.location.hostname}`, 10, 20);
            
            // Ersetze Bild mit Wasserzeichen-Version
            const watermarkedSrc = canvas.toDataURL('image/png', 0.99);
            
            // In Cache speichern
            this.watermarkCache.set(imgElement, watermarkedSrc);
            
            // Wenn Bild schon geladen, nicht ersetzen (nur für neue)
            if (!imgElement.complete) {
                imgElement.src = watermarkedSrc;
            }
            
        } catch (error) {
            if (this.options.debug) console.warn('Wasserzeichen fehlgeschlagen:', error);
        }
    }
    
    setupLazyLoading(element) {
        if (element.tagName === 'IMG') {
            // Wenn Bild nicht im Viewport, verzögere Laden
            if (!this.isInViewport(element)) {
                element.loading = 'lazy';
                
                // Custom Lazy Loading
                const observer = new IntersectionObserver((entries) => {
                    entries.forEach(entry => {
                        if (entry.isIntersecting) {
                            const img = entry.target;
                            if (img.dataset.src && !img.src) {
                                img.src = img.dataset.src;
                                img.removeAttribute('data-src');
                            }
                            observer.unobserve(img);
                        }
                    });
                }, {
                    rootMargin: '50px',
                    threshold: 0.01
                });
                
                observer.observe(element);
            }
        }
    }
    
    isInViewport(element) {
        const rect = element.getBoundingClientRect();
        return (
            rect.top >= 0 &&
            rect.left >= 0 &&
            rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
            rect.right <= (window.innerWidth || document.documentElement.clientWidth)
        );
    }
    
    // ==================== OBSERVER & EVENTS ====================
    
    setupMutationObserver() {
        this.observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === 1) { // Element node
                            // Prüfe das Node selbst
                            if (this.isImageElement(node)) {
                                this.protectSingleImage(node);
                            }
                            
                            // Prüfe Kinder
                            const images = node.querySelectorAll ? 
                                node.querySelectorAll('img, image, [style*="background-image"]') : [];
                            
                            images.forEach(img => this.protectSingleImage(img));
                        }
                    });
                }
                
                // Attribute changes (z.B. src Änderung)
                if (mutation.type === 'attributes' && 
                    (mutation.attributeName === 'src' || 
                     mutation.attributeName === 'style')) {
                    
                    const target = mutation.target;
                    if (this.isImageElement(target)) {
                        const newSrc = this.getImageSource(target);
                        if (newSrc && this.shouldProtectImage(newSrc)) {
                            this.protectSingleImage(target);
                        }
                    }
                }
            });
        });
        
        // Observer konfigurieren
        this.observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['src', 'href', 'xlink:href', 'style', 'data-src', 'data-bg']
        });
    }
    
    setupEventListeners() {
        // Window Events
        window.addEventListener('load', () => {
            // Finaler Scan nach allem Laden
            setTimeout(() => this.protectExistingImages(), 1000);
        });
        
        window.addEventListener('beforeunload', () => {
            // Cleanup
            if (this.observer) {
                this.observer.disconnect();
            }
        });
        
        // Network Events
        window.addEventListener('offline', () => {
            console.log('🌐 Offline - Pausiere Bildschutz');
        });
        
        window.addEventListener('online', () => {
            console.log('🌐 Online - Aktiviere Bildschutz');
            setTimeout(() => this.protectExistingImages(), 500);
        });
        
        // Error Handling für Bilder
        document.addEventListener('error', (e) => {
            if (e.target.tagName === 'IMG' && this.protectedImages.has(e.target)) {
                const originalSrc = this.originalSources.get(e.target);
                if (originalSrc && e.target.src !== originalSrc) {
                    // Fallback auf Original
                    setTimeout(() => {
                        e.target.src = originalSrc;
                    }, 1000);
                }
            }
        }, true);
    }
    
    // ==================== MONITORING & UTILITIES ====================
    
    setupPerformanceMonitor() {
        setInterval(() => {
            const uptime = Date.now() - this.performance.startTime;
            const minutes = Math.floor(uptime / 60000);
            
            console.log(`📊 Image Protection Status:
                Laufzeit: ${minutes} Minuten
                Geschützte Bilder: ${this.performance.imagesProtected}
                Blockierte Versuche: ${this.performance.blockedAttempts}
                Fehler: ${this.performance.errors}`);
            
        }, 60000); // Alle Minute
    }
    
    setupPeriodicCheck() {
        // Alle 30 Sekunden prüfen
        setInterval(() => {
            this.checkProtectionStatus();
        }, 30000);
    }
    
    checkProtectionStatus() {
        // Prüfe ob alle Bilder noch geschützt sind
        const allImages = document.querySelectorAll('img, [style*="background-image"]');
        let unprotected = 0;
        
        allImages.forEach(img => {
            const src = this.getImageSource(img);
            if (src && this.shouldProtectImage(src) && !this.protectedImages.has(img)) {
                unprotected++;
                this.protectSingleImage(img);
            }
        });
        
        if (unprotected > 0 && this.options.debug) {
            console.log(`⚠️ ${unprotected} Bilder neu geschützt`);
        }
    }
    
    // ==================== PUBLIC API ====================
    
    getStats() {
        return {
            ...this.performance,
            uptime: Date.now() - this.performance.startTime,
            options: { ...this.options },
            protectedCount: this.performance.imagesProtected,
            cacheSize: this.watermarkCache.size
        };
    }
    
    protectImageUrl(url) {
        if (!this.shouldProtectImage(url)) return url;
        
        let protectedUrl = url;
        
        if (this.options.cacheBusting) {
            protectedUrl = this.addCacheBusting(protectedUrl);
        }
        
        if (this.options.addTimestamps) {
            protectedUrl = this.addTimestamp(protectedUrl);
        }
        
        return protectedUrl;
    }
    
    disableProtection() {
        if (this.observer) {
            this.observer.disconnect();
        }
        
        // Entferne Event Listener
        document.removeEventListener('contextmenu', this.handleContextMenu);
        
        console.log('🔓 Bildschutz deaktiviert');
        return { success: true, message: 'Protection disabled' };
    }
    
    enableProtection() {
        this.startProtection();
        return { success: true, message: 'Protection enabled' };
    }
    
    forceProtection() {
        this.protectExistingImages();
        return { success: true, protected: this.performance.imagesProtected };
    }
    
    // ==================== HELPER FUNCTIONS ====================
    
    createSecureImageElement(src, options = {}) {
        const img = document.createElement('img');
        
        // Setze geschützte URL
        img.src = this.protectImageUrl(src);
        
        // Füge Schutzattribute hinzu
        img.setAttribute('data-original-src', src);
        img.setAttribute('data-protected', 'true');
        img.setAttribute('data-server7', 'true');
        
        // Wende Optionen an
        if (options.lazy) {
            img.loading = 'lazy';
        }
        
        if (options.className) {
            img.className = options.className;
        }
        
        if (options.alt) {
            img.alt = options.alt;
        }
        
        // Sofort schützen
        this.protectSingleImage(img);
        
        return img;
    }
}

// ==================== AUTO-START ====================

(function() {
    // Prüfe ob bereits läuft
    if (window.server7ImageProtector) {
        console.log('ℹ️ Server7 Image Protection läuft bereits');
        return;
    }
    
    // Starte Protection
    const imageProtector = new Server7ImageProtector({
        debug: false, // true für Entwickler-Modus
        preventRightClick: true,
        preventDownload: true,
        lazyLoad: true,
        blurUnloaded: true
    });
    
    // Expose API
    window.Server7ImageProtector = Server7ImageProtector;
    window.server7ImageProtector = imageProtector;
    
    console.log('🎉 Server7 Image Protection erfolgreich gestartet');
})();

// ==================== EXPORT FÜR MODULE ====================

if (typeof module !== 'undefined' && module.exports) {
    module.exports = Server7ImageProtector;
}
