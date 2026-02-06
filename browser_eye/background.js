/**
 * Telos Browser Eye - Background Service Worker
 * 
 * Handles:
 * - Native Messaging connection to host daemon
 * - Forwarding taint reports from content scripts
 * - Connection lifecycle management
 */

// Native Messaging Host name (must match the .json manifest)
const NATIVE_HOST_NAME = 'com.telos.native';

// Connection state
let nativePort = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY_MS = 2000;

/**
 * Establish connection to the Native Host
 */
function connectToNativeHost() {
    try {
        nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);
        console.log('[Telos] 🔗 Connected to Native Host');
        reconnectAttempts = 0;

        // Handle incoming messages from Native Host
        nativePort.onMessage.addListener((msg) => {
            console.log('[Telos] ← Native Host:', msg);

            // Handle acknowledgments or commands from Cortex
            if (msg.type === 'ack') {
                console.log('[Telos] ✓ Taint report acknowledged');
            } else if (msg.type === 'policy_update') {
                // Future: Could inject policy into content scripts
                console.log('[Telos] Policy update received:', msg.policy);
            }
        });

        // Handle disconnection
        nativePort.onDisconnect.addListener(() => {
            const error = chrome.runtime.lastError?.message || 'Unknown error';
            console.warn(`[Telos] ⚠️ Native Host disconnected: ${error}`);
            nativePort = null;

            // Attempt reconnection
            if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
                reconnectAttempts++;
                console.log(`[Telos] Reconnection attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS} in ${RECONNECT_DELAY_MS}ms...`);
                setTimeout(connectToNativeHost, RECONNECT_DELAY_MS);
            } else {
                console.error('[Telos] ❌ Max reconnection attempts reached. Native Host unavailable.');
            }
        });

    } catch (err) {
        console.error('[Telos] Failed to connect to Native Host:', err);
    }
}

/**
 * Send a message to the Native Host
 */
function sendToNativeHost(message) {
    if (nativePort) {
        try {
            nativePort.postMessage(message);
            console.log('[Telos] → Native Host:', message);
            return true;
        } catch (err) {
            console.error('[Telos] Failed to send message:', err);
            return false;
        }
    } else {
        console.warn('[Telos] Cannot send - Native Host not connected');
        // Queue message and reconnect
        connectToNativeHost();
        return false;
    }
}

/**
 * Handle messages from content scripts
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'taint_detected') {
        console.log(`[Telos] 🚨 Taint from tab ${sender.tab?.id}: ${request.level}`);

        // Construct the report for Native Host
        const report = {
            source_id: sender.tab?.id?.toString() || 'unknown',
            url: sender.tab?.url || sender.url || 'unknown',
            level: request.level,
            payload: request.payload || '',
            findings: request.findings || {},
            timestamp: Date.now()
        };

        // Forward to Native Host
        const sent = sendToNativeHost(report);

        // Respond to content script
        sendResponse({
            received: true,
            forwarded: sent
        });
    }

    // Return true to indicate async response
    return true;
});

/**
 * Handle extension installation/update
 */
chrome.runtime.onInstalled.addListener((details) => {
    console.log('[Telos] 👁️ Browser Eye installed/updated:', details.reason);
    connectToNativeHost();
});

/**
 * Handle browser startup
 */
chrome.runtime.onStartup.addListener(() => {
    console.log('[Telos] 👁️ Browser Eye starting...');
    connectToNativeHost();
});

// Initial connection attempt
connectToNativeHost();
