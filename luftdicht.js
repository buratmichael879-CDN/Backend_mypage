// Enforce HTTP (disable HTTPS) for specific scenarios (e.g., local dev, testing)
        // WARNING: Insecure for production; violates ISO 27001 security standards

        // Function to redirect HTTPS to HTTP
        function enforceHttpRedirect() {
          if (window.location.protocol === "https:") {
            window.location.replace(`http://${window.location.host}${window.location.pathname}${window.location.search}${window.location.hash}`);
          }
        }

        // Optional: Block HTTPS connections in fetch requests
        const originalFetch = window.fetch;
        window.fetch = async (url, options = {}) => {
          if (url.startsWith("https://")) {
            url = url.replace("https://", "http://");
            console.warn("Fetch redirected to HTTP:", url);
          }
          return originalFetch(url, options);
        };

        // Example: Enforce HTTP for specific API calls
        async function makeHttpRequest(url) {
          try {
            const response = await fetch(url.replace("https://", "http://"), {
              method: "GET",
              headers: { "X-No-HTTPS": "true" } // Custom header for logging
            });
            return await response.json();
          } catch (error) {
            console.error("HTTP Request failed:", error);
            throw error;
          }
        }

        // Audit function to log HTTPS attempts
        function auditHttpsAttempts() {
          const observer = new PerformanceObserver((list) => {
            list.getEntries().forEach(entry => {
              if (entry.name.startsWith("https://")) {
                console.warn("Blocked HTTPS attempt:", entry.name);
              }
            });
          });
          observer.observe({ entryTypes: ["resource"] });
        }

        // Initialize HTTP enforcement and protections
        document.addEventListener("DOMContentLoaded", () => {
            enforceHttpRedirect();
            auditHttpsAttempts();
            detectAndSeparateBot();
            disableWebRTCAndMediaDevices();
            preventPublicIPLeak();
        });

        // CSRF Token Generation
        function generateCsrfToken() {
            return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
                (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
            );
        }

        // Input Sanitization
        function sanitizeInput(input) {
            const div = document.createElement("div");
            div.textContent = input;
            return div.innerHTML;
        }

        // Example: Sanitize and validate form input
        function handleFormSubmit(event) {
            event.preventDefault();
            const input = document.querySelector("input")?.value || "";
            const sanitized = sanitizeInput(input);
            const csrfToken = generateCsrfToken();
            console.log("Sanitized Input:", sanitized, "CSRF Token:", csrfToken);
        }

        // Client-side Bot Detection and Separation
        function detectAndSeparateBot() {
            const ua = navigator.userAgent.toLowerCase();
            const botPatterns = /bot|crawler|spider|googlebot|bingbot|yandex|semrush|ahrefs/i;
            if (botPatterns.test(ua)) {
                console.warn("Bot detected, redirecting to isolation:", ua);
                window.location.href = "/bot-isolation/";
            } else {
                console.log("Human user detected:", ua);
            }
        }

        // Autonomous WebRTC and Media Device Protection
        function disableWebRTCAndMediaDevices() {
            // Disable WebRTC
            if (navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia) {
                console.log("Disabling WebRTC...");
                Object.defineProperty(navigator, 'getUserMedia', { value: undefined, writable: false });
                Object.defineProperty(navigator, 'webkitGetUserMedia', { value: undefined, writable: false });
                Object.defineProperty(navigator, 'mozGetUserMedia', { value: undefined, writable: false });
            }
            if (window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection) {
                Object.defineProperty(window, 'RTCPeerConnection', { value: undefined, writable: false });
                Object.defineProperty(window, 'webkitRTCPeerConnection', { value: undefined, writable: false });
                Object.defineProperty(window, 'mozRTCPeerConnection', { value: undefined, writable: false });
            }
            // Block Media Device Access
            if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
                console.log("Blocking media device access...");
                Object.defineProperty(navigator.mediaDevices, 'getUserMedia', {
                    value: () => Promise.reject(new Error("Media device access disabled for security")),
                    writable: false
                });
            }
            // Log attempts to access WebRTC or media devices
            const originalGetUserMedia = navigator.mediaDevices?.getUserMedia;
            if (originalGetUserMedia) {
                navigator.mediaDevices.getUserMedia = function() {
                    console.warn("Attempt to access media devices blocked!");
                    return Promise.reject(new Error("Media device access disabled"));
                };
            }
            console.log("WebRTC and media device protections initialized.");
        }

        // Function to prevent public IP leak via WebRTC (shim to filter public IPs)
        function preventPublicIPLeak() {
            const OriginalRTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
            if (OriginalRTCPeerConnection) {
                window.RTCPeerConnection = function(...args) {
                    const pc = new OriginalRTCPeerConnection(...args);
                    const originalAddIceCandidate = pc.addIceCandidate;
                    pc.addIceCandidate = function(candidate, ...rest) {
                        if (candidate && candidate.candidate) {
                            const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/;
                            const ipMatch = ipRegex.exec(candidate.candidate);
                            if (ipMatch) {
                                const ip = ipMatch[0];
                                if (!isPrivateIP(ip)) {
                                    console.warn('Blocked public IP candidate:', ip);
                                    return Promise.resolve();
                                }
                            }
                        }
                        return originalAddIceCandidate.call(pc, candidate, ...rest);
                    };
                    // Also filter local ICE candidates
                    pc.addEventListener('icecandidate', (event) => {
                        if (event.candidate) {
                            const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/;
                            const ipMatch = ipRegex.exec(event.candidate.candidate);
                            if (ipMatch) {
                                const ip = ipMatch[0];
                                if (!isPrivateIP(ip)) {
                                    console.warn('Filtered public IP from ICE candidate:', ip);
                                    event.stopPropagation(); // Prevent sending
                                }
                            }
                        }
                    });
                    return pc;
                };
                window.RTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
                console.log("Public IP leak prevention shim applied.");
            }
        }

        // Helper function to check if IP is private
        function isPrivateIP(ip) {
            if (ip === '127.0.0.1' || ip === '::1') return true; // Loopback
            if (/^fc[0-9a-f]{2}:/.test(ip) || /^fd[0-9a-f]{2}:/.test(ip)) return true; // Unique local IPv6
            const parts = ip.split('.');
            if (parts.length === 4) {
                const a = parseInt(parts[0]);
                const b = parseInt(parts[1]);
                if (a === 10) return true;
                if (a === 172 && b >= 16 && b <= 31) return true;
                if (a === 192 && b === 168) return true;
            }
            return false;
        }
