import { app, BrowserWindow, Tray, Menu, ipcMain, dialog, nativeImage, Notification, clipboard, globalShortcut } from 'electron';
import path from 'node:path';
import started from 'electron-squirrel-startup';
import { GoogleGenerativeAI } from '@google/generative-ai';
import fs from 'fs';
import notifier from 'node-notifier';
import chokidar from 'chokidar';
import { runFileSandboxed } from './sandbox.js';
import { spawn } from 'child_process';
// Initialize sandbox functionality
const sandboxEnabled = true;
console.log('[MAIN] src/main.js loaded');
// Import sandbox integration
import sandboxIntegration from './sandbox/sandboxIntegration.js';

// IPC handlers for sandbox operations
ipcMain.handle('check-sandbox-status', async () => {
  try {
    await sandboxIntegration.checkWindowsSandbox();
    return { available: true };
  } catch (error) {
    return {
      available: false,
      reason: error.message
    };
  }
});

// Enhanced sandbox execution with both static and dynamic analysis
ipcMain.handle('run-file-sandboxed', async (event, filePath) => {
  try {
    // First do static analysis
    const staticResult = await new Promise((resolve) => {
      runFileSandboxed(filePath, (result) => {
        resolve(result);
      });
    });

    // Then try dynamic analysis if Windows Sandbox is available
    try {
      const { available } = await sandboxIntegration.checkWindowsSandbox();
      if (available) {
        const dynamicResult = await sandboxIntegration.runInSandbox(filePath);
        return {
          ok: true,
          staticAnalysis: staticResult,
          dynamicAnalysis: dynamicResult.result,
          logs: dynamicResult.logs
        };
      }
    } catch (error) {
      console.warn('Windows Sandbox analysis failed:', error.message);
      // Fall back to just static analysis
    }

    // Return static analysis if dynamic analysis not available
    return {
      ok: true,
      staticAnalysis: staticResult,
      dynamicAnalysis: null
    };
  } catch (error) {
    return {
      ok: false,
      error: error.message
    };
  }
});

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (started) {
  app.quit();
}

// Configure cache and user data locations early to avoid Windows access issues
try {
  const tempDir = process.env.TEMP || process.env.TMP || 'C:/Windows/Temp';
  const cacheDir = path.join(tempDir, 'spam-detector-pro-cache');
  app.setPath('userData', path.join(tempDir, 'spam-detector-pro-userdata'));
  app.commandLine.appendSwitch('disk-cache-dir', cacheDir);
  app.commandLine.appendSwitch('disable-gpu-shader-disk-cache');
} catch {}

// Load model configuration (model name and base prompt)
let modelName = 'gemini-2.5-flash';
let dummyPrompt = 'You are a security assistant. Analyze the provided content strictly for spam, phishing, scams, suspicious links, phone numbers, or emails. Consider social-engineering cues, urgency, rewards, link obfuscation, URL shorteners, and mismatched branding. Return only the JSON object described below.';
try {
  const configPath = path.join(process.cwd(), 'model.json');
  if (fs.existsSync(configPath)) {
    const raw = fs.readFileSync(configPath, 'utf8');
    const cfg = JSON.parse(raw);
    if (typeof cfg.model === 'string' && cfg.model.trim()) modelName = cfg.model.trim();
    if (typeof cfg.dummyPrompt === 'string' && cfg.dummyPrompt.trim()) dummyPrompt = cfg.dummyPrompt.trim();
  }
} catch (e) {
  console.warn('Model config load failed, using defaults:', e.message);
}

// Initialize Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: modelName });

let mainWindow;
let tray;
let clipboardInterval;
let isMonitoring = false;
let backgroundProtection = false;
let downloadsWatcher = null;
let autoLaunchEnabled = false;

// Spam detection patterns
const spamPatterns = {
  email: /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/gi,
  phone: /(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})/g,
  url: /(https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)/gi,
  suspicious: /(free|win|prize|congratulations|urgent|limited|offer|click|now|act|fast|guaranteed|no risk|100%|winner|selected|exclusive|deal|discount|save|money|cash|earn|work from home|make money|investment|bitcoin|crypto|loan|credit|debt|refinance)/gi
};

// AI-powered spam detection
async function detectSpamWithAI(content) {
  try {
    const prompt = `${dummyPrompt}\n\nAnalyze this content for spam indicators. Return a JSON response with exactly this shape (no extra keys):\n
    {\n
      \"isSpam\": boolean,\n
      \"confidence\": number,\n
      \"score\": number,\n
      \"verdict\": \"valid\"|\"suspicious\"|\"spam_bot\",\n
      \"reasons\": [string],\n
      \"type\": \"email|phone|url|text\",\n
      \"riskLevel\": \"low|medium|high\"\n
    }\n
    Where score is 0-100 (higher = more spammy). Map to verdict: score < 30 => valid; 30-69 => suspicious; >= 70 => spam_bot. confidence is your subjective certainty (0-100).\n
    Strictly output valid JSON only (no code fences, no commentary).\n\n
    Content to analyze: \"${content}\"\n\n
    Look for: suspicious URLs/domains, phishing, spam keywords, suspicious phones, malicious email patterns, social engineering.`;

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    
    // Try to parse JSON response
    try {
      const parsed = JSON.parse(text);
      const normalized = normalizeResult(parsed, content);
      return normalized;
    } catch {
      // Fallback to pattern-based detection
      return detectSpamPatterns(content);
    }
  } catch (error) {
    console.error('AI detection error:', error);
    return detectSpamPatterns(content);
  }
}

// Pattern-based spam detection fallback
function detectSpamPatterns(content) {
  const reasons = [];
  let spamScore = 0;
  
  // Check for suspicious keywords
  const suspiciousMatches = content.match(spamPatterns.suspicious);
  if (suspiciousMatches) {
    spamScore += suspiciousMatches.length * 10;
    reasons.push(`Contains suspicious keywords: ${suspiciousMatches.slice(0, 3).join(', ')}`);
  }
  
  // Check for multiple URLs
  const urlMatches = content.match(spamPatterns.url);
  if (urlMatches && urlMatches.length > 2) {
    spamScore += 20;
    reasons.push('Multiple URLs detected');
  }
  
  // Check for suspicious domains
  const suspiciousDomains = /(bit\.ly|tinyurl|short\.link|goo\.gl|t\.co|ow\.ly)/gi;
  if (suspiciousDomains.test(content)) {
    spamScore += 30;
    reasons.push('Suspicious URL shortener detected');
  }
  
  // Check for phone numbers with suspicious context
  const phoneMatches = content.match(spamPatterns.phone);
  if (phoneMatches && spamPatterns.suspicious.test(content)) {
    spamScore += 25;
    reasons.push('Phone number with suspicious context');
  }
  
  const score = Math.max(0, Math.min(spamScore, 100));
  const isSpam = score >= 30;
  const confidence = score;
  const riskLevel = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';
  const verdict = score >= 70 ? 'spam_bot' : score >= 30 ? 'suspicious' : 'valid';
  return { isSpam, confidence, score, verdict, reasons, type: 'text', riskLevel };
}

function normalizeResult(result, originalContent) {
  const reasons = Array.isArray(result.reasons) ? result.reasons : [];
  const score = typeof result.score === 'number' ? result.score : (typeof result.confidence === 'number' ? result.confidence : 0);
  const clampedScore = Math.max(0, Math.min(score, 100));
  const verdict = result.verdict || (clampedScore >= 70 ? 'spam_bot' : clampedScore >= 30 ? 'suspicious' : 'valid');
  const isSpam = typeof result.isSpam === 'boolean' ? result.isSpam : clampedScore >= 30;
  const confidence = typeof result.confidence === 'number' ? Math.max(0, Math.min(result.confidence, 100)) : clampedScore;
  const riskLevel = result.riskLevel || (clampedScore >= 70 ? 'high' : clampedScore >= 40 ? 'medium' : 'low');
  const type = result.type || 'text';
  return { isSpam, confidence, score: clampedScore, verdict, reasons, type, riskLevel };
}

// Clipboard monitoring
let lastClipboardContent = '';

function textHasPatterns(text) {
  try {
    const emailMatches = text.match(spamPatterns.email);
    const phoneMatches = text.match(spamPatterns.phone);
    const urlMatches = text.match(spamPatterns.url);
    const keywordMatches = text.match(spamPatterns.suspicious);
    return !!(emailMatches || phoneMatches || urlMatches || keywordMatches);
  } catch {
    return false;
  }
}

function startClipboardMonitoring() {
  if (clipboardInterval) {
    stopClipboardMonitoring();
    return;
  }

  console.log('[Clipboard] Starting monitoring...');
  
  try {
    // Initial clipboard read
    const initialContent = clipboard.readText() || '';
    lastClipboardContent = initialContent;
    
    if (mainWindow && initialContent) {
      mainWindow.webContents.send('clipboard-content', {
        content: initialContent,
        status: 'ready'
      });
    }
  } catch (error) {
    console.error('[Clipboard] Initial clipboard read error:', error);
    lastClipboardContent = '';
  }

  // Set up high-frequency monitoring
  clipboardInterval = setInterval(async () => {
    try {
      const content = clipboard.readText() || '';
      
      // Only process if content has changed
      if (content !== lastClipboardContent) {
        console.log('[Clipboard] Content changed, analyzing...');
        lastClipboardContent = content;

        // Send immediate update to renderer
        if (mainWindow) {
          mainWindow.webContents.send('clipboard-content', {
            content,
            status: 'analyzing'
          });
        }

        if (!content.trim()) {
          // Empty clipboard
          if (mainWindow) {
            mainWindow.webContents.send('clipboard-content', {
              content: '',
              status: 'empty'
            });
          }
          return;
        }

        // Analyze content
        try {
          const result = await detectSpamWithAI(content);
          const score = result.score || result.confidence || 0;
          const isSpam = result.isSpam;
          
          // Send result to renderer
          if (mainWindow) {
            mainWindow.webContents.send('clipboard-analysis', {
              isSpam,
              score,
              verdict: result.verdict || (isSpam ? 'spam' : 'safe'),
              message: `Analysis complete: ${isSpam ? 'Suspicious' : 'Safe'} • Score: ${score}`,
              details: result
            });
          }
          
          // Show notification
          const notification = new Notification({
            title: isSpam ? '⚠️ Warning: Suspicious Content' : '✅ Content Looks Safe',
            body: `Scan complete • Score: ${score}`,
            urgency: isSpam ? 'critical' : 'normal'
          });
          notification.show();
          
        } catch (error) {
          console.error('[Clipboard] Analysis error:', error);
          if (mainWindow) {
            mainWindow.webContents.send('clipboard-error', {
              error: error.message
            });
          }
        }
      }
    } catch (error) {
      console.error('[Clipboard] Monitoring error:', error);
    }
  }, 100); // Check every 100ms for more responsiveness
}

function stopClipboardMonitoring() {
  if (clipboardInterval) {
    clearInterval(clipboardInterval);
    clipboardInterval = null;
  }
  lastClipboardContent = '';
}

// Show spam warning notification
function showSpamWarning(content, result) {
  const notification = new Notification({
    title: '🚨 Spam Detected!',
    body: `Suspicious content detected in clipboard (${result.confidence}% confidence)`,
    urgency: 'critical'
  });
  
  notification.on('click', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });
  
  notification.show();
  
  // Also show system notification
  notifier.notify({
    title: 'Spam Detector Pro',
    message: `Suspicious content: ${content.substring(0, 50)}...`,
    sound: true,
    wait: true
  });
}

// Create system tray
function createTray() {
  // Use default icon if custom icon not available
  let trayIcon;
  try {
    const iconPath = path.join(__dirname, '../assets/tray-icon.png');
    trayIcon = nativeImage.createFromPath(iconPath);
  } catch {
    // Create a simple default icon
    trayIcon = nativeImage.createEmpty();
  }
  tray = new Tray(trayIcon);
  
  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Spam Detector Pro',
      enabled: false
    },
    { type: 'separator' },
    {
      label: isMonitoring ? 'Stop Monitoring' : 'Start Monitoring',
      click: () => {
        isMonitoring = !isMonitoring;
        if (isMonitoring) {
          startClipboardMonitoring();
        } else {
          stopClipboardMonitoring();
        }
        createTray(); // Refresh tray menu
      }
    },
    {
      label: 'Show Window',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        app.quit();
      }
    }
  ]);
  
  tray.setContextMenu(contextMenu);
  tray.setToolTip('Spam Detector Pro - Real-time spam protection');
}

const waitForPreloadIfDev = () => {
  try {
    if (process.env.NODE_ENV !== 'production' && typeof __dirname === 'string') {
      const builtPreload = path.join(__dirname, 'preload.js');
      const start = Date.now();
      while (!fs.existsSync(builtPreload) && Date.now() - start < 3000) {
        // busy-wait briefly to allow vite plugin to emit preload chunk
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
      }
    }
  } catch {}
};

const createWindow = () => {
  waitForPreloadIfDev();
  // Create the browser window.
  mainWindow = new BrowserWindow({
    width: 1000,
    height: 700,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      spellcheck: false,
    },
    show: false
  });

  // and load the index.html of the app.
  if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(MAIN_WINDOW_VITE_DEV_SERVER_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`));
  }

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    // DevTools can be toggled manually with Ctrl+Shift+I if needed
  });

  // Handle window close
  mainWindow.on('close', (event) => {
    if (!app.isQuiting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  // Also allow toggling DevTools via accelerator from window
  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.type === 'keyDown' && input.control && input.shift && input.key.toLowerCase() === 'i') {
      mainWindow.webContents.toggleDevTools();
      event.preventDefault();
    }
  });
};

// IPC handlers
ipcMain.handle('detect-spam', async (event, content) => {
  return await detectSpamWithAI(content);
});

ipcMain.handle('scan-file', async (event, filePath) => {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    return await detectSpamWithAI(content);
  } catch (error) {
    return { error: 'Failed to read file' };
  }
});

// Read file content as text for combined analysis
ipcMain.handle('read-file-text', async (event, filePath) => {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    return { ok: true, content };
  } catch (error) {
    return { ok: false, error: 'Failed to read file' };
  }
});

// Track clipboard content and analysis for UI
let currentClipboardContent = '';
let currentClipboardAnalysis = null;

ipcMain.handle('toggle-monitoring', async (event) => {
  // Flip the monitoring state
  isMonitoring = !isMonitoring;
  console.log('[IPC] toggle-monitoring called. New state:', isMonitoring ? 'Starting' : 'Stopping');
  
  if (isMonitoring) {
    // When toggle is turned ON (right), start monitoring
    console.log('[IPC] Starting clipboard monitoring...');
    startClipboardMonitoring();
  } else {
    // When toggle is turned OFF (left), stop monitoring
    console.log('[IPC] Stopping clipboard monitoring...');
    stopClipboardMonitoring();
  }
  return isMonitoring;
});

// New IPC handlers for clipboard content and analysis
ipcMain.handle('get-clipboard-content', () => {
  try {
    return clipboard.readText() || '';
  } catch (error) {
    console.error('Error reading clipboard:', error);
    return '';
  }
});
ipcMain.handle('get-clipboard-analysis', () => currentClipboardAnalysis);

ipcMain.handle('get-monitoring-status', async (event) => {
  return isMonitoring;
});

// Background Protection toggle: monitors clipboard (already), downloads, and stubs URL checks
ipcMain.handle('toggle-background-protection', async () => {
  backgroundProtection = !backgroundProtection;
  if (backgroundProtection) {
    tryStartDownloadsWatcher();
    if (!clipboardInterval) startClipboardMonitoring();
  } else {
    stopDownloadsWatcher();
  }
  return backgroundProtection;
});

ipcMain.handle('get-background-protection', async () => backgroundProtection);

// File dialog for sandbox analysis
ipcMain.handle('show-file-dialog', async (event) => {
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
      filters: [
        { name: 'All Files', extensions: ['*'] },
        { name: 'Executable Files', extensions: ['exe', 'msi', 'bat', 'cmd', 'ps1', 'sh'] },
        { name: 'Script Files', extensions: ['js', 'py', 'vbs', 'php', 'pl', 'rb'] },
        { name: 'Document Files', extensions: ['txt', 'doc', 'docx', 'pdf', 'rtf'] }
      ],
      title: 'Select File for Sandbox Analysis'
    });
    
    if (!result.canceled && result.filePaths.length > 0) {
      const filePath = result.filePaths[0];
      console.log('[SANDBOX] Selected file:', filePath);
      
      // Run sandbox analysis
      return await new Promise((resolve) => {
        runFileSandboxed(filePath, (sandboxResult) => {
          console.log('[SANDBOX] Analysis result:', sandboxResult);
          resolve({
            filePath,
            sandboxResult
          });
        });
      });
    }
    return null;
  } catch (error) {
    console.error('[SANDBOX] Error in file dialog:', error);
    return { error: error.message };
  }
});

// Generic OS notification from renderer
ipcMain.handle('notify', async (event, { title, body } = {}) => {
  try {
    const notification = new Notification({
      title: typeof title === 'string' && title.trim() ? title.trim() : 'Spam Detector Pro',
      body: typeof body === 'string' && body.trim() ? body.trim() : 'Notification',
      urgency: 'normal'
    });
    notification.show();
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
});

// Auto-launch (startup) controls
ipcMain.handle('get-auto-launch', async () => {
  try {
    const settings = app.getLoginItemSettings();
    return Boolean(settings && (settings.openAtLogin || settings.openAsHidden));
  } catch {
    return false;
  }
});

// Scan clipboard now and notify
ipcMain.handle('scan-clipboard-now', async () => {
  try {
    const text = clipboard.readText();
    if (!text || !text.trim()) {
      currentClipboardContent = '';
      currentClipboardAnalysis = {
        isSpam: false,
        score: 0,
        verdict: 'empty',
        message: 'Clipboard is empty'
      };
      return { ok: false, error: 'Clipboard empty' };
    }

    // Update UI with current content immediately
    currentClipboardContent = text;
    currentClipboardAnalysis = {
      isSpam: false,
      score: 0,
      verdict: 'analyzing',
      message: 'Analyzing content...'
    };

    // Perform AI analysis
    const result = await detectSpamWithAI(text.substring(0, 8000));
    const score = typeof result.score === 'number' ? result.score : (typeof result.confidence === 'number' ? result.confidence : 0);
    const isSpam = result.isSpam;
    
    // Update analysis result
    currentClipboardAnalysis = {
      isSpam,
      score,
      verdict: result.verdict || (isSpam ? 'spam' : 'safe'),
      message: `Analysis complete: ${isSpam ? 'Suspicious' : 'Safe'} • Score: ${score}`,
      details: result
    };

    // Show notification
    const notification = new Notification({
      title: isSpam ? '⚠️ Warning: Suspicious Content' : '✅ Content Looks Safe',
      body: `Scan complete • Score: ${score}`,
      urgency: isSpam ? 'critical' : 'normal'
    });
    notification.show();
    
    return { ok: true, result };
  } catch (e) {
    currentClipboardAnalysis = {
      isSpam: false,
      score: 0,
      verdict: 'error',
      message: 'Error analyzing content: ' + (e.message || String(e))
    };
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
});

ipcMain.handle('set-auto-launch', async (event, enable) => {
  try {
    const shouldEnable = !!enable;
    // On Windows/macOS, this controls login behavior.
    app.setLoginItemSettings({ openAtLogin: shouldEnable, openAsHidden: true });
    autoLaunchEnabled = shouldEnable;
    return { ok: true, enabled: shouldEnable };
  } catch (e) {
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
});

function tryStartDownloadsWatcher() {
  try {
    const downloadsPath = app.getPath('downloads');
    if (downloadsWatcher) return;
    downloadsWatcher = chokidar.watch(downloadsPath, { ignoreInitial: true, depth: 0 });
    downloadsWatcher.on('add', async (filePath) => {
      // Only handle small text-like files for now
      if (!filePath.match(/\.(txt|eml|csv|log|md)$/i)) return;
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const result = await detectSpamWithAI(content);
        if (result && result.isSpam) {
          showSpamWarning(`Downloaded: ${filePath}`, result);
        }
      } catch (e) {
        console.warn('Download scan failed:', e.message);
      }
    });
  } catch (e) {
    console.warn('Downloads watcher failed:', e.message);
  }
}

function stopDownloadsWatcher() {
  if (downloadsWatcher) {
    try { downloadsWatcher.close(); } catch {}
    downloadsWatcher = null;
  }
}


// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
app.whenReady().then(() => {
  createWindow();
  createTray();
  // Global shortcut to toggle DevTools
  try {
    globalShortcut.register('Control+Shift+I', () => {
      if (mainWindow) mainWindow.webContents.toggleDevTools();
    });
  } catch {}
  // Global shortcut for Alt+C to scan clipboard
  try {
    globalShortcut.register('Alt+C', async () => {
      try {
        const text = clipboard.readText();
        if (!text || !text.trim()) {
          const notification = new Notification({ title: 'Scan Clipboard', body: 'Clipboard is empty' });
          notification.show();
          return;
        }
        const result = await detectSpamWithAI(text.substring(0, 8000));
        const score = typeof result.score === 'number' ? result.score : (typeof result.confidence === 'number' ? result.confidence : 0);
        const summary = result.isSpam ? `Spam detected • Score: ${score}` : `Safe • Score: ${score}`;
        const notif = new Notification({
          title: 'Clipboard Scan',
          body: summary
        });
        notif.show();
      } catch (e) {
        const notification = new Notification({ title: 'Scan Clipboard', body: 'Error scanning clipboard' });
        notification.show();
      }
    });
  } catch {}
  
  // Start monitoring by default
  isMonitoring = false;
  // Users can enable monitoring from the tray or UI

  // On OS X it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.isQuiting = true;
    app.quit();
  }
});

// Handle app quit
app.on('before-quit', () => {
  app.isQuiting = true;
  stopClipboardMonitoring();
});

// Export functions needed by other modules
export { detectSpamWithAI };

// Import execution window handler
import { executionWindow } from './sandbox/executionWindow.js';

// Execute a file in a separate window
ipcMain.handle('execute-file', async (event, opts = {}) => {
  try {
    const filePath = opts && (opts.path || opts.filePath);
    const shouldExecute = !!opts.execute;
    const timeoutMs = typeof opts.timeout === 'number' ? Math.max(1000, opts.timeout) : 15000;

    if (!filePath || !fs.existsSync(filePath)) {
      return { ok: false, error: 'File does not exist' };
    }

    // Create execution window
    const execWindow = executionWindow.create();

    // If we are not allowed to actually execute, return a simulated run result
    if (!shouldExecute) {
      const simulated = {
        ok: true,
        simulated: true,
        message: `Simulated execution of ${filePath}`,
        stdout: `Simulated run output for ${filePath}\n(Execution skipped by user settings)`,
        stderr: ''
      };
      execWindow.webContents.send('execution-results', {
        status: 'Simulated Execution',
        output: simulated.stdout
      });
      return simulated;
    }

    // Execute in a separate process with output going to execution window
    return await new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;

      // Send initial status to execution window
      execWindow.webContents.send('execution-results', {
        status: 'Starting execution...',
        running: true
      });

      // Choose execution strategy by extension
      const ext = (filePath.match(/\.([^.\\/]+)$/) || [])[1] || '';
      let child;

      try {
        // For common script types, try to use the interpreter if available
        if (/^py$/i.test(ext)) {
          child = spawn('python', [filePath], { windowsHide: true });
        } else if (/^js$/i.test(ext)) {
          child = spawn('node', [filePath], { windowsHide: true });
        } else if (/^bat|cmd$/i.test(ext)) {
          child = spawn('cmd.exe', ['/c', filePath], { windowsHide: true });
        } else if (/^ps1$/i.test(ext)) {
          child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', filePath], { windowsHide: true });
        } else {
          // Default: try to execute directly (use shell to allow exe and scripts)
          child = spawn(filePath, [], { windowsHide: true, shell: true });
        }
      } catch (err) {
        resolve({ ok: false, error: 'Failed to spawn process: ' + err.message });
        return;
      }

      const killTimer = setTimeout(() => {
        timedOut = true;
        try { child.kill('SIGKILL'); } catch {}
      }, timeoutMs);

      child.stdout && child.stdout.on('data', (d) => { stdout += d.toString(); });
      child.stderr && child.stderr.on('data', (d) => { stderr += d.toString(); });

      child.on('close', (code, signal) => {
        clearTimeout(killTimer);
        resolve({ ok: true, simulated: false, exitCode: code, signal: signal, timedOut, stdout, stderr });
      });

      child.on('error', (err) => {
        clearTimeout(killTimer);
        resolve({ ok: false, error: 'Execution error: ' + err.message });
      });
    });
  } catch (e) {
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
});