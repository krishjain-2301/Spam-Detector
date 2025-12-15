// This file creates and manages the sandbox inspection results window in Electron
import { BrowserWindow, ipcMain } from 'electron';
import path from 'path';
console.log('[SANDBOX] sandboxWindow.js loaded');
let sandboxWin = null;

function createSandboxWindow() {
  if (sandboxWin) {
    sandboxWin.focus();
    return sandboxWin;
  }
  sandboxWin = new BrowserWindow({
    width: 900,
    height: 800,
    title: 'Sandbox Analysis Results',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    show: false,
    backgroundColor: '#1a1a1a',
    autoHideMenuBar: true,
  });
  const htmlPath = path.join(__dirname, 'sandbox_new.html');
  sandboxWin.loadFile(htmlPath);
  sandboxWin.once('ready-to-show', () => sandboxWin.show());
  sandboxWin.on('closed', () => { sandboxWin = null; });
  return sandboxWin;
}

ipcMain.handle('open-sandbox-window', (event, results) => {
  const win = createSandboxWindow();
  if (results) {
    // Wait for window to be ready, then send results
    win.webContents.once('did-finish-load', () => {
      win.webContents.send('sandbox-inspection-results', results);
    });
    // If already loaded, send immediately
    if (win.webContents.isLoading() === false) {
      win.webContents.send('sandbox-inspection-results', results);
    }
  }
  return { ok: true };
});

ipcMain.on('sandbox-inspection-results', (event, results) => {
  if (sandboxWin) {
    sandboxWin.webContents.send('sandbox-inspection-results', results);
  }
});

export { createSandboxWindow };
