import { ipcRenderer, contextBridge } from 'electron';

// Expose sandbox API to renderer
contextBridge.exposeInMainWorld('sandboxAPI', {
    // Request static and dynamic analysis of a file
    analyzeFile: async (filePath) => {
        return await ipcRenderer.invoke('analyze-in-sandbox', filePath);
    },

    // Run a file in sandbox (simulated by default)
    executeFile: async (filePath, options = {}) => {
        return await ipcRenderer.invoke('execute-file', {
            path: filePath,
            execute: !!options.execute,
            timeout: options.timeout || 15000
        });
    },

    // Verify sandbox availability
    checkSandboxStatus: async () => {
        try {
            await ipcRenderer.invoke('analyze-in-sandbox');
            return { available: true };
        } catch (error) {
            return {
                available: false,
                reason: error.message
            };
        }
    }
});

// Setup sandbox integration when document is ready
document.addEventListener('DOMContentLoaded', () => {
    const sandboxContainer = document.getElementById('sandbox-container');
    const sandboxStatus = document.getElementById('sandbox-status');
    
    if (sandboxContainer && sandboxStatus) {
        // Check and update sandbox availability
        window.sandboxAPI.checkSandboxStatus().then((status) => {
            if (status.available) {
                sandboxStatus.textContent = '✓ Windows Sandbox Ready';
                sandboxStatus.className = 'text-green-500';
                sandboxContainer.classList.remove('sandbox-unavailable');
            } else {
                sandboxStatus.textContent = `⚠️ ${status.reason}`;
                sandboxStatus.className = 'text-yellow-500';
                sandboxContainer.classList.add('sandbox-unavailable');
            }
        });
    }
});