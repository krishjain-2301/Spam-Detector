import { contextBridge, ipcRenderer } from 'electron';

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // Clipboard operations
  getClipboardContent: () => ipcRenderer.invoke('get-clipboard-content'),
  scanClipboardNow: () => ipcRenderer.invoke('scan-clipboard-now'),
  
  // Monitoring controls
  toggleMonitoring: () => ipcRenderer.invoke('toggle-monitoring'),
  getMonitoringStatus: () => ipcRenderer.invoke('get-monitoring-status'),
  toggleBackgroundProtection: () => ipcRenderer.invoke('toggle-background-protection'),
  getBackgroundProtection: () => ipcRenderer.invoke('get-background-protection'),
  
  // Auto-launch (startup) controls
  getAutoLaunch: () => ipcRenderer.invoke('get-auto-launch'),
  setAutoLaunch: (enable) => ipcRenderer.invoke('set-auto-launch', enable),

  // Sandbox operations
  runFileSandboxed: (filePath) => ipcRenderer.invoke('run-file-sandboxed', filePath),
  executeFile: (opts) => ipcRenderer.invoke('execute-file', opts),
  openSandboxWindow: (results) => ipcRenderer.invoke('open-sandbox-window', results),
  onSandboxResults: (callback) => ipcRenderer.on('sandbox-inspection-results', (event, results) => callback(results)),
  analyzeInSandbox: (filePath) => ipcRenderer.invoke('analyze-in-sandbox', filePath),
  checkSandboxStatus: () => ipcRenderer.invoke('check-sandbox-status'),

  // Spam detection
  detectSpam: (content) => ipcRenderer.invoke('detect-spam', content),
  scanFile: (filePath) => ipcRenderer.invoke('scan-file', filePath),
  
  // File operations
  showFileDialog: () => ipcRenderer.invoke('show-file-dialog'),
  readFileText: (filePath) => ipcRenderer.invoke('read-file-text', filePath),

  // Notifications
  notify: (payload) => ipcRenderer.invoke('notify', payload)
});