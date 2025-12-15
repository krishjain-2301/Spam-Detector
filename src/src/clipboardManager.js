// Import required modules
import { clipboard, ipcMain, Notification } from 'electron';

// Clipboard monitoring state
let isMonitoring = false;
let clipboardInterval = null;
let lastClipboardContent = '';

// Start clipboard monitoring
function startClipboardMonitoring() {
    if (clipboardInterval) {
        stopClipboardMonitoring();
    }

    console.log('[Clipboard] Starting monitoring...');
    
    // Get initial clipboard content
    try {
        lastClipboardContent = clipboard.readText() || '';
    } catch (error) {
        console.error('[Clipboard] Error reading initial clipboard:', error);
        lastClipboardContent = '';
    }

    // Check clipboard every 100ms
    clipboardInterval = setInterval(() => {
        try {
            const content = clipboard.readText() || '';
            if (content !== lastClipboardContent) {
                console.log('[Clipboard] Content changed');
                lastClipboardContent = content;
                
                if (content.trim()) {
                    // Content changed and not empty, trigger scan
                    scanClipboardContent(content);
                }
            }
        } catch (error) {
            console.error('[Clipboard] Monitoring error:', error);
        }
    }, 100);
}

// Stop clipboard monitoring
function stopClipboardMonitoring() {
    if (clipboardInterval) {
        clearInterval(clipboardInterval);
        clipboardInterval = null;
    }
    lastClipboardContent = '';
    console.log('[Clipboard] Monitoring stopped');
}

// Scan clipboard content
async function scanClipboardContent(content) {
    try {
        // Import the detectSpamWithAI function from your main module
        const { detectSpamWithAI } = await import('./main.js');
        
        const result = await detectSpamWithAI(content);
        const score = result.score || result.confidence || 0;
        const isSpam = result.isSpam;

        // Show notification
        const notification = new Notification({
            title: isSpam ? '⚠️ Warning: Suspicious Content' : '✅ Content Looks Safe',
            body: `Scan complete • Score: ${score}`,
            urgency: isSpam ? 'critical' : 'normal'
        });
        notification.show();

        return { ok: true, result };
    } catch (error) {
        console.error('[Clipboard] Scan error:', error);
        return { ok: false, error: error.message };
    }
}

// Setup IPC handlers
function setupClipboardIPC() {
    // Get clipboard content
    ipcMain.handle('get-clipboard-content', () => {
        try {
            return clipboard.readText() || '';
        } catch (error) {
            console.error('[Clipboard] Error reading clipboard:', error);
            return '';
        }
    });

    // Toggle monitoring
    ipcMain.handle('toggle-monitoring', () => {
        isMonitoring = !isMonitoring;
        if (isMonitoring) {
            startClipboardMonitoring();
        } else {
            stopClipboardMonitoring();
        }
        return isMonitoring;
    });

    // Get monitoring status
    ipcMain.handle('get-monitoring-status', () => isMonitoring);

    // Scan clipboard now
    ipcMain.handle('scan-clipboard-now', async () => {
        const content = clipboard.readText() || '';
        if (!content.trim()) {
            return { ok: false, error: 'Clipboard is empty' };
        }
        return await scanClipboardContent(content);
    });
}

export {
    setupClipboardIPC,
    startClipboardMonitoring,
    stopClipboardMonitoring,
    isMonitoring
};