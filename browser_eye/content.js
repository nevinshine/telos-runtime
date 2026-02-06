/**
 * Telos Browser Eye - Content Script
 * 
 * Detects potential prompt injection vectors in DOM content:
 * - Hidden text (opacity: 0, visibility: hidden, off-screen)
 * - Invisible fonts (size < 1px, same color as background)
 * - Zero-width characters used to hide instructions
 * - Known injection keyword patterns
 */

(function() {
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

    /**
     * Scan all relevant elements in the document
     */
    function scanDocument() {
        const taints = [];
        
        // Select elements likely to contain text
        const elements = document.querySelectorAll(
            'p, div, span, h1, h2, h3, h4, h5, h6, li, td, th, label, ' +
            'article, section, aside, blockquote, pre, code'
        );
        
        for (const el of elements) {
            try {
                const result = scanElement(el);
                if (result) {
                    taints.push(result);
                }
            } catch (e) {
                // Skip elements that throw errors
            }
        }
        
        return taints;
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
            level: taintData.levelName,
            payload: taintData.text,
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

    /**
     * Debounced scan and report
     */
    function debouncedScan() {
        if (reportDebounce) {
            clearTimeout(reportDebounce);
        }
        
        reportDebounce = setTimeout(() => {
            const taints = scanDocument();
            
            // Report only the highest severity taint, or all HIGH+ taints
            const highTaints = taints.filter(t => t.level >= TaintLevel.HIGH);
            
            if (highTaints.length > 0) {
                // Report all high severity taints
                for (const taint of highTaints) {
                    reportTaint(taint);
                }
            } else if (taints.length > 0) {
                // Report the highest severity one
                const maxTaint = taints.reduce((a, b) => 
                    a.level > b.level ? a : b
                );
                reportTaint(maxTaint);
            }
        }, DEBOUNCE_MS);
    }

    // === INITIALIZATION ===

    /**
     * Set up MutationObserver for dynamic content
     */
    function setupObserver() {
        const observer = new MutationObserver((mutations) => {
            // Check if any mutations added meaningful content
            let hasNewContent = false;
            
            for (const mutation of mutations) {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === Node.ELEMENT_NODE || 
                            node.nodeType === Node.TEXT_NODE) {
                            hasNewContent = true;
                            break;
                        }
                    }
                }
                if (hasNewContent) break;
            }
            
            if (hasNewContent) {
                debouncedScan();
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true
        });

        return observer;
    }

    /**
     * Initialize the content script
     */
    function init() {
        console.log('[Telos] 👁️ Browser Eye initialized');
        
        // Initial scan after page load
        debouncedScan();
        
        // Set up mutation observer for dynamic content
        if (document.body) {
            setupObserver();
        } else {
            // Wait for body if not ready
            document.addEventListener('DOMContentLoaded', () => {
                setupObserver();
            });
        }
    }

    // Start
    init();

})();
