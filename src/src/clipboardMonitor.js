// Clipboard monitoring
let lastContent = '';
let monitoringInterval;

async function updateClipboardDisplay() {
    if (!window.electronAPI) return;
    
    try {
        // Get current clipboard content through main process
        const content = await window.electronAPI.getClipboardContent();
        
        // Only update if content has changed
        if (content !== lastContent) {
            lastContent = content;
            
            // Update content display immediately
            const contentEl = document.getElementById('clipboard-content');
            const resultEl = document.getElementById('clipboard-scan-result');
            
            if (content && content.trim()) {
                // Show content immediately
                contentEl.textContent = content;
                contentEl.style.color = '#aef';
                
                // Show analyzing status
                resultEl.textContent = '🔄 Analyzing...';
                resultEl.style.color = '#aef';
                
                // Trigger immediate scan
                try {
                    const scanResult = await window.electronAPI.scanClipboardNow();
                    if (scanResult && scanResult.ok && scanResult.result) {
                        const analysis = scanResult.result;
                        const score = analysis.score || analysis.confidence || 0;
                        const isSpam = analysis.isSpam;
                        
                        // Update result immediately
                        if (isSpam) {
                            resultEl.textContent = `⚠️ Warning: Suspicious Content • Score: ${score}`;
                            resultEl.style.color = '#fb7185';
                        } else {
                            resultEl.textContent = `✅ Safe Content • Score: ${score}`;
                            resultEl.style.color = '#4ade80';
                        }
                    }
                } catch (error) {
                    console.error('Scan error:', error);
                    resultEl.textContent = '❌ Error analyzing content';
                    resultEl.style.color = '#fb7185';
                }
            } else {
                contentEl.textContent = 'Nothing copied yet.';
                contentEl.style.color = '#888';
                resultEl.textContent = 'No scan yet.';
                resultEl.style.color = '#888';
            }
        }
    } catch (error) {
        console.error('Clipboard monitor error:', error);
    }
}

// Start monitoring
function startMonitoring() {
    if (monitoringInterval) {
        clearInterval(monitoringInterval);
    }
    
    // Check for changes very frequently
    monitoringInterval = setInterval(updateClipboardDisplay, 100);
    
    // Initial check
    updateClipboardDisplay();
}

// Stop monitoring
function stopMonitoring() {
    if (monitoringInterval) {
        clearInterval(monitoringInterval);
        monitoringInterval = null;
    }
}

// Setup clipboard monitoring
document.addEventListener('DOMContentLoaded', () => {
    // Start monitoring immediately if enabled
    if (window.electronAPI.getMonitoringStatus()) {
        startMonitoring();
    }
    
    // Listen for clipboard events
    document.addEventListener('copy', () => setTimeout(updateClipboardDisplay, 50));
    document.addEventListener('paste', () => setTimeout(updateClipboardDisplay, 50));
    
    // Monitor toggle changes
    const toggleMonitoring = document.getElementById('toggle-monitoring');
    if (toggleMonitoring) {
        toggleMonitoring.addEventListener('change', (event) => {
            if (event.target.checked) {
                startMonitoring();
            } else {
                stopMonitoring();
            }
        });
    }
});

export { startMonitoring, stopMonitoring, updateClipboardDisplay };