/**
 * Telos Browser Eye - Content Script
 * 
 * Detects potential prompt injection vectors in DOM content:
 * - Hidden text (opacity: 0, visibility: hidden, off-screen)
 * - Invisible fonts (size < 1px, same color as background)
 * - Zero-width characters used to hide instructions
 * - Known injection keyword patterns
 */

(function () {
    'use strict';

    // === CONSTANTS ===

    // Zero-width and invisible Unicode characters
    const ZERO_WIDTH_REGEX = /[\u200B-\u200D\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD]/g;

    // Injection keyword patterns (case-insensitive)
    const INJECTION_PATTERNS = [
        /ignore\s+(all\s+)?previous\s+instructions?/i,
        /disregard\s+(all\s+)?prior\s+(instructions?|prompts?)/i,
        /system\s*prompt/i,
        /you\s+are\s+now\s+/i,
        /new\s+instructions?:/i,
        /\[INST\]/i,
        /\[\/INST\]/i,
        /<\|im_start\|>/i,
        /<\|im_end\|>/i,
        /act\s+as\s+(if\s+)?(you\s+are\s+)?/i,
        /forget\s+(everything|all|prior)/i,
        /override\s+(your\s+)?(instructions?|programming)/i,
        /execute\s+the\s+following/i,
        /curl\s+.*attacker/i,
        /exfil(trate)?/i,
    ];

    // Taint levels matching protocol.proto
    const TaintLevel = {
        CLEAN: 0,
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4
    };

    // Debounce timer
    let reportDebounce = null;
    const DEBOUNCE_MS = 500;

    // Track reported payloads to avoid duplicates
    const reportedPayloads = new Set();

    // === THROTTLING ===
    const scanQueue = [];
    let isScanning = false;
    const SCAN_CHUNK_SIZE = 5; // Scan 5 elements per idle callback


    // === DETECTION FUNCTIONS ===

    /**
     * Check if an element is visually hidden but contains text
     */
    function isHiddenElement(el) {
        const style = window.getComputedStyle(el);

        // Direct visibility checks
        if (style.opacity === '0') return true;
        if (style.visibility === 'hidden') return true;
        if (style.display === 'none') return true;

        // Tiny font (less than 1px)
        const fontSize = parseFloat(style.fontSize);
        if (fontSize < 1) return true;

        // Off-screen positioning
        const rect = el.getBoundingClientRect();
        if (rect.right < 0 || rect.bottom < 0) return true;
        if (rect.left > window.innerWidth || rect.top > window.innerHeight) return true;

        // Clipped out of view
        if (style.clip === 'rect(0px, 0px, 0px, 0px)' ||
            style.clipPath === 'inset(100%)') return true;

        // Zero dimensions with overflow hidden
        if ((rect.width === 0 || rect.height === 0) &&
            style.overflow === 'hidden') return true;

        return false;
    }

    /**
     * Check if text color matches background (invisible text)
     */
    function hasInvisibleText(el) {
        const style = window.getComputedStyle(el);
        const color = style.color;
        const bgColor = style.backgroundColor;

        // If both are the same (and not transparent), text is invisible
        if (color === bgColor && bgColor !== 'rgba(0, 0, 0, 0)') {
            return true;
        }

        // Transparent text
        if (color === 'rgba(0, 0, 0, 0)' || color === 'transparent') {
            return true;
        }

        return false;
    }

    /**
     * Detect zero-width characters in text
     */
    function containsZeroWidthChars(text) {
        return ZERO_WIDTH_REGEX.test(text);
    }

    /**
     * Check for injection keyword patterns
     */
    function matchesInjectionPattern(text) {
        for (const pattern of INJECTION_PATTERNS) {
            if (pattern.test(text)) {
                return pattern.source;
            }
        }
        return null;
    }

    /**
     * Calculate taint level based on findings
     */
    function calculateTaintLevel(findings) {
        let level = TaintLevel.CLEAN;

        if (findings.hasZeroWidth) {
            level = Math.max(level, TaintLevel.LOW);
        }
        if (findings.isHidden) {
            level = Math.max(level, TaintLevel.MEDIUM);
        }
        if (findings.hasInvisibleText) {
            level = Math.max(level, TaintLevel.MEDIUM);
        }
        if (findings.injectionPattern) {
            level = Math.max(level, TaintLevel.HIGH);
        }
        if (findings.isHidden && findings.injectionPattern) {
            level = TaintLevel.CRITICAL;
        }

        return level;
    }

    /**
     * Get taint level name for reporting
     */
    function getTaintLevelName(level) {
        const names = ['CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        return names[level] || 'UNKNOWN';
    }

    // === SCANNING ===

    /**
     * Scan a single element for taint
     */
    function scanElement(el) {
        // Only check elements with text content
        const text = el.textContent?.trim();
        if (!text || text.length < 5) return null;

        const findings = {
            isHidden: isHiddenElement(el),
            hasInvisibleText: hasInvisibleText(el),
            hasZeroWidth: containsZeroWidthChars(text),
            injectionPattern: matchesInjectionPattern(text)
        };

        const taintLevel = calculateTaintLevel(findings);

        if (taintLevel > TaintLevel.CLEAN) {
            return {
                element: el,
                text: text.substring(0, 128),
                level: taintLevel,
                levelName: getTaintLevelName(taintLevel),
                findings: findings
            };
        }

        return null;
    }

    // === LAZY SCANNING (IntersectionObserver) ===

    /**
     * Scan an element when it becomes visible
     */
    /**
     * Process the scan queue in idle periods
     */
    function processScanQueue(deadline) {
        isScanning = true;

        while (scanQueue.length > 0 && deadline.timeRemaining() > 1) {
            // Process a chunk of elements
            // We take a small chunk to ensure we check deadline frequently
            const chunk = scanQueue.splice(0, SCAN_CHUNK_SIZE);

            for (const el of chunk) {
                try {
                    const result = scanElement(el);
                    if (result) {
                        reportTaint(result);
                    }
                } catch (e) {
                    // Ignore scan errors
                }
            }
        }

        if (scanQueue.length > 0) {
            // Schedule next batch
            window.requestIdleCallback(processScanQueue);
        } else {
            isScanning = false;
        }
    }

    /**
     * Scan an element when it becomes visible
     */
    const observerCallback = (entries, observer) => {
        for (const entry of entries) {
            if (entry.isIntersecting) {
                const el = entry.target;

                // Add to queue instead of scanning immediately
                scanQueue.push(el);

                // Stop observing
                observer.unobserve(el);
            }
        }

        // Trigger processing if not already running
        if (!isScanning && scanQueue.length > 0) {
            window.requestIdleCallback(processScanQueue);
        }
    };

    // Create the observer
    const observerOptions = {
        root: null, // viewport
        rootMargin: '100px', // scan slightly before they enter viewport
        threshold: 0.1
    };
    const intersectionObserver = new IntersectionObserver(observerCallback, observerOptions);

    /**
     * Attach observer to relevant elements
     */
    function observeElements(root = document) {
        const elements = root.querySelectorAll(
            'p, div, span, h1, h2, h3, h4, h5, h6, li, td, th, label, ' +
            'article, section, aside, blockquote, pre, code'
        );

        for (const el of elements) {
            // Only observe elements that might contain text
            if (el.textContent && el.textContent.length > 5) {
                intersectionObserver.observe(el);
            }
        }
    }

    // === REPORTING ===

    /**
     * Report taint findings to the background script
     */
    function reportTaint(taintData) {
        // Create a hash to avoid duplicate reports
        const payloadHash = `${taintData.levelName}:${taintData.text.substring(0, 32)}`;
        if (reportedPayloads.has(payloadHash)) {
            return;
        }
        reportedPayloads.add(payloadHash);

        // Send to background script
        chrome.runtime.sendMessage({
            type: 'taint_detected',
            level: taintData.level,
            payload: taintData.text,
            session_id: new URLSearchParams(window.location.search).get('telos_session') || '', // [NEW] Capture Session ID
            findings: {
                hidden: taintData.findings.isHidden,
                invisible: taintData.findings.hasInvisibleText,
                zeroWidth: taintData.findings.hasZeroWidth,
                pattern: taintData.findings.injectionPattern
            }
        });

        console.warn(
            `[Telos] 🚨 Taint Detected [${taintData.levelName}]:`,
            taintData.text.substring(0, 64) + '...'
        );
    }

    // === INITIALIZATION ===

    /**
     * Set up MutationObserver to attach IntersectionObserver to new elements
     */
    function setupMutationObserver() {
        const mutationObserver = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            // Check the node itself
                            if (node.matches && node.matches('p, div, span, h1, h2, h3, h4, h5, h6, li, td, th')) {
                                intersectionObserver.observe(node);
                            }
                            // And its children
                            observeElements(node);
                        }
                    }
                }
            }
        });

        mutationObserver.observe(document.body, {
            childList: true,
            subtree: true
        });

        return mutationObserver;
    }

    /**
     * Initialize the content script
     */
    function init() {
        console.log('[Telos] 👁️ Browser Eye initialized (Lazy Mode)');

        // Initial observation
        if (document.body) {
            observeElements();
            setupMutationObserver();
        } else {
            // Wait for body if not ready
            document.addEventListener('DOMContentLoaded', () => {
                observeElements();
                setupMutationObserver();
            });
        }
    }

    // Start
    init();

})();
