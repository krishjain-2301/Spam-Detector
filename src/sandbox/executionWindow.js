import { BrowserWindow } from 'electron';
import path from 'path';

class ExecutionWindow {
  constructor() {
    this.window = null;
  }

  create() {
    // If window exists, focus it instead of creating new one
    if (this.window) {
      this.window.focus();
      return this.window;
    }

    // Create a new window with secure settings
    this.window = new BrowserWindow({
      width: 800,
      height: 600,
      title: 'Sandbox Execution',
      webPreferences: {
        preload: path.join(__dirname, 'sandboxPreload.js'),
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        webviewTag: false,
        webSecurity: true,
        allowRunningInsecureContent: false,
        enableRemoteModule: false
      },
      // Prevent interference with main window
      parent: null,
      modal: false,
      show: false,
      backgroundColor: '#1a1a1a'
    });

    // Load execution interface
    this.window.loadFile(path.join(__dirname, 'sandbox', 'execution.html'));

    // Handle window closure
    this.window.on('closed', () => {
      this.window = null;
    });

    // Show when ready
    this.window.once('ready-to-show', () => {
      this.window.show();
    });

    return this.window;
  }

  // Show execution results
  showResults(results) {
    if (!this.window) {
      this.create();
    }
    this.window.webContents.send('execution-results', results);
  }

  // Close window if open
  close() {
    if (this.window) {
      this.window.close();
      this.window = null;
    }
  }
}

export const executionWindow = new ExecutionWindow();