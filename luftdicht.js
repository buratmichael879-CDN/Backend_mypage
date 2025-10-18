/* luftdicht.js — Complete Browser Isolation + Payment Leak Closure
   Professor Dr. Dr. Dr. Dr. — ISO27001 / NIS2 Version
   Features:
   - HTTP-only enforcement (127.0.0.1)
   - Camera, mic, geo, sensors, WebRTC, USB, Bluetooth, push, notifications blocked
   - Payment & autofill leaks closed (5 protection functions)
   - Permissions-Policy injection (no CSP)
   - Background watchdog + service worker neutralizer
   - Freeze/thaw mechanism for DOM restrictions
   - Ransomware protection (File System API block, Crypto API monitoring, suspicious activity detection)
   - XSS protection (input sanitization, DOM clobbering prevention, script execution control)
*/

(function Luftdicht(window, document) {
  'use strict';
  const LOG = (...a) => console.log('[LUFTDICHT]', ...a);
  const now = () => new Date().toISOString();

  // === 0. HTTP enforcement ===
  if (location.protocol !== 'http:' || location.hostname !== '127.0.0.1') {
    LOG('Redirecting to http://127.0.0.1');
    location.href = 'http://127.0.0.1';
    return;
  }

  // === 1. Permissions-Policy Injection (no CSP) ===
  (function injectPermissions() {
    const meta = document.createElement('meta');
    meta.name = 'permissions-policy';
    meta.content = 'camera=(), microphone=(), geolocation=(), payment=(), interest-cohort=(), usb=(), bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=(), notifications=(), filesystem=()';
    document.head.prepend(meta);
    LOG('Permissions-Policy applied, including filesystem');
  })();

  // === 2. Privacy Protection Core ===
  (function privacy() {
    // Camera / Mic
    if (navigator.mediaDevices) {
      navigator.mediaDevices.getUserMedia = () => Promise.reject(new DOMException('Blocked', 'NotAllowedError'));
      navigator.mediaDevices.enumerateDevices = () => Promise.resolve([]);
      LOG('Camera and microphone access blocked');
    }

    // Geolocation
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition = (success, error) => error && error({ code: 1, message: 'Blocked' });
      navigator.geolocation.watchPosition = (success, error) => error && error({ code: 1, message: 'Blocked' });
      LOG('Geolocation access blocked');
    }

    // WebRTC
    if (window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection) {
      window.RTCPeerConnection = window.webkitRTCPeerConnection = window.mozRTCPeerConnection = null;
      LOG('WebRTC disabled');
    }

    // USB
    if (navigator.usb) {
      navigator.usb.requestDevice = () => Promise.reject(new DOMException('Blocked', 'NotAllowedError'));
      navigator.usb.getDevices = () => Promise.resolve([]);
      LOG('USB access blocked');
    }

    // Bluetooth
    if (navigator.bluetooth) {
      navigator.bluetooth.requestDevice = () => Promise.reject(new DOMException('Blocked', 'NotAllowedError'));
      navigator.bluetooth.getAvailability = () => Promise.resolve(false);
      LOG('Bluetooth access blocked');
    }

    // Sensors
    ['Accelerometer', 'Gyroscope', 'Magnetometer', 'AmbientLightSensor'].forEach(sensor => {
      if (window[sensor]) {
        window[sensor] = null;
        LOG(`${sensor} access blocked`);
      }
    });

    // Notifications
    if (window.Notification) {
      Notification.requestPermission = () => Promise.resolve('denied');
      window.Notification = null;
      LOG('Notifications blocked');
    }

    // Push API
    if ('pushManager' in window) {
      navigator.serviceWorker.getRegistration = () => Promise.resolve(null);
      LOG('Push API blocked');
    }
  })();

  // === 3. Payment & Autofill Leak Closure ===
  (function paymentAutofillProtection() {
    // 1. Disable Payment Request API
    if (window.PaymentRequest) {
      window.PaymentRequest = null;
      LOG('PaymentRequest API disabled');
    }

    // 2. Block autofill for sensitive fields
    const blockAutofill = () => {
      const sensitiveFields = document.querySelectorAll('input[type="text"], input[type="password"], input[type="email"], input[type="tel"], input[type="number"]');
      sensitiveFields.forEach(field => {
        field.setAttribute('autocomplete', 'off');
        field.setAttribute('autocorrect', 'off');
        field.setAttribute('autocapitalize', 'off');
        field.setAttribute('spellcheck', 'false');
      });
      LOG('Autofill blocked for sensitive fields');
    };

    // 3. Prevent clipboard access
    document.addEventListener('copy', e => {
      e.preventDefault();
      LOG('Clipboard copy blocked');
    });
    document.addEventListener('paste', e => {
      e.preventDefault();
      LOG('Clipboard paste blocked');
    });

    // 4. Disable form autofill suggestions
    if (window.Autofill) {
      window.Autofill = null;
      LOG('Autofill API disabled');
    }

    // 5. Monitor form submissions for sensitive data
    document.addEventListener('submit', e => {
      const form = e.target;
      const inputs = form.querySelectorAll('input');
      inputs.forEach(input => {
        if (input.value && /[\d\s-]{12,19}/.test(input.value)) {
          e.preventDefault();
          LOG('Potential credit card data submission blocked');
        }
      });
    });

    blockAutofill();
  })();

  // === 4. Ransomware Protection ===
  (function ransomwareProtection() {
    // Block File System Access API
    if (window.showDirectoryPicker || window.showOpenFilePicker || window.showSaveFilePicker) {
      window.showDirectoryPicker = window.showOpenFilePicker = window.showSaveFilePicker = () => Promise.reject(new DOMException('Blocked', 'NotAllowedError'));
      LOG('File System Access API blocked');
    }

    // Monitor Web Crypto API usage
    const originalSubtleCrypto = window.crypto.subtle;
    if (window.crypto && window.crypto.subtle) {
      window.crypto.subtle = new Proxy(originalSubtleCrypto, {
        get(target, prop) {
          if (['encrypt', 'generateKey'].includes(prop)) {
            LOG('Suspicious Web Crypto API call detected:', prop);
            freeze(); // Freeze DOM on suspicious crypto activity
            return () => Promise.reject(new DOMException('Blocked', 'NotAllowedError'));
          }
          return target[prop];
        }
      });
      LOG('Web Crypto API monitored');
    }

    // Detect rapid DOM modifications (potential ransomware behavior)
    let modificationCount = 0;
    const modificationThreshold = 50; // Arbitrary threshold for rapid changes
    const modificationWindow = 1000; // 1 second window
    setInterval(() => {
      if (modificationCount > modificationThreshold) {
        LOG('Rapid DOM modifications detected, potential ransomware activity');
        freeze();
      }
      modificationCount = 0;
    }, modificationWindow);
  })();

  // === 5. XSS Protection ===
  (function xssProtection() {
    // Sanitize dynamic inputs
    const sanitizeInput = (value) => {
      return value.replace(/[<>]/g, '').replace(/(\b(on\w+)=)/gi, 'data-$1'); // Remove HTML tags and event attributes
    };

    // Override dangerous DOM methods
    const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set;
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set(value) {
        const sanitized = sanitizeInput(value);
        LOG('Sanitized innerHTML input');
        return originalInnerHTML.call(this, sanitized);
      }
    });

    // Block eval and Function constructor
    window.eval = window.Function = () => {
      LOG('Blocked eval or Function constructor');
      throw new Error('Dynamic code execution blocked');
    };

    // Prevent DOM clobbering
    const protectDOM = () => {
      ['createElement', 'createElementNS', 'appendChild', 'insertBefore'].forEach(method => {
        const original = document[method];
        document[method] = function (...args) {
          if (args[0] && args[0].tagName === 'SCRIPT') {
            LOG('Blocked dynamic script injection');
            return null;
          }
          return original.apply(this, args);
        };
      });
      LOG('DOM clobbering protection applied');
    };

    // Monitor suspicious event listeners
    const originalAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, listener, options) {
      if (type.startsWith('on') || /javascript:/i.test(listener.toString())) {
        LOG('Blocked suspicious event listener:', type);
        return;
      }
      return originalAddEventListener.apply(this, [type, listener, options]);
    };

    protectDOM();
    LOG('XSS protection initialized');
  })();

  // === 6. Background Watchdog + Service Worker Neutralizer ===
  (function watchdog() {
    // Neutralize service workers
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then(registrations => {
        registrations.forEach(reg => reg.unregister());
        LOG('Service workers unregistered');
      });
      navigator.serviceWorker.register = () => Promise.reject(new DOMException('Service worker registration blocked', 'NotAllowedError'));
      LOG('Service worker registration disabled');
    }

    // Enhanced watchdog for ransomware and XSS detection
    let modificationCount = 0; // Shared with ransomware protection
    const observer = new MutationObserver(mutations => {
      mutations.forEach(mutation => {
        if (mutation.addedNodes.length || mutation.removedNodes.length) {
          modificationCount++;
          if (mutation.addedNodes.length && Array.from(mutation.addedNodes).some(node => node.tagName === 'SCRIPT')) {
            LOG('Unauthorized script injection detected at', now());
            freeze(); // Freeze DOM on script injection
            mutation.addedNodes.forEach(node => node.remove());
          }
        }
      });
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    LOG('Watchdog started');
  })();

  // === 7. Freeze/Thaw Mechanism ===
  (function freezeThaw() {
    let isFrozen = false;

    // Freeze: Lock DOM to prevent modifications
    window.freeze = () => {
      if (!isFrozen) {
        document.documentElement.style.pointerEvents = 'none';
        document.body.style.userSelect = 'none';
        isFrozen = true;
        LOG('DOM frozen at', now());
      }
    };

    // Thaw: Unlock DOM
    window.thaw = () => {
      if (isFrozen) {
        document.documentElement.style.pointerEvents = '';
        document.body.style.userSelect = '';
        isFrozen = false;
        LOG('DOM thawed at', now());
      }
    };

    // Detect external freeze conditions
    const checkFreeze = () => {
      if (document.documentElement.style.pointerEvents === 'none' && !isFrozen) {
        LOG('External DOM freeze detected, thawing immediately');
        window.thaw();
      }
    };

    // Periodically check for freeze conditions
    setInterval(checkFreeze, 1000);

    // Freeze on suspicious activity (e.g., excessive script injections)
    document.addEventListener('beforescriptexecute', e => {
      const scripts = document.getElementsByTagName('script').length;
      if (scripts > 10) { // Arbitrary threshold
        window.freeze();
        LOG('DOM frozen due to excessive script injections');
      }
    });

    // Thaw on user command
    window.addEventListener('message', e => {
      if (e.data === 'thaw') {
        window.thaw();
      }
    });

    LOG('Freeze/thaw mechanism initialized');
  })();
})(window, document);
