import { contextBridge, ipcRenderer } from 'electron';

// Expose safe APIs for sandbox execution window
contextBridge.exposeInMainWorld('sandboxAPI', {
    // Receive execution results from main process
    onExecutionResults: (callback) => {
        ipcRenderer.on('execution-results', (event, results) => callback(results));
    },

    // Request execution stop
    stopExecution: () => {
        ipcRenderer.invoke('stop-sandbox-execution');
    }
});