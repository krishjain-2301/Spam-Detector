document.addEventListener('DOMContentLoaded', () => {
    const contentEl = document.getElementById('clipboard-content');
    const resultEl = document.getElementById('clipboard-scan-result');

    // Listen for clipboard content updates
    window.electronAPI.onClipboardContent((event, data) => {
        if (!contentEl || !resultEl) return;

        if (data.status === 'empty') {
            contentEl.textContent = 'Nothing copied yet.';
            contentEl.style.color = '#888';
            resultEl.textContent = 'No scan yet.';
            resultEl.style.color = '#888';
        } else if (data.status === 'analyzing') {
            contentEl.textContent = data.content;
            contentEl.style.color = '#aef';
            resultEl.textContent = '🔄 Analyzing...';
            resultEl.style.color = '#aef';
        } else {
            contentEl.textContent = data.content;
            contentEl.style.color = '#aef';
        }
    });

    // Listen for analysis results
    window.electronAPI.onClipboardAnalysis((event, result) => {
        if (!resultEl) return;

        const score = result.score || 0;
        const isSpam = result.isSpam;
        
        resultEl.textContent = isSpam 
            ? `⚠️ Warning: Suspicious Content • Score: ${score}`
            : `✅ Safe Content • Score: ${score}`;
        resultEl.style.color = isSpam ? '#fb7185' : '#4ade80';
    });

    // Listen for errors
    window.electronAPI.onClipboardError((event, data) => {
        if (!resultEl) return;
        resultEl.textContent = `❌ Error: ${data.error}`;
        resultEl.style.color = '#fb7185';
    });
});