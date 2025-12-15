  // Advanced security tool buttons (stub actions)
  const hammerSystemFolder = document.getElementById('hammer-system-folder-monitor');
  const hammerAttachment = document.getElementById('hammer-attachment-inspector');
  const hammerHash = document.getElementById('hammer-hash-verification');
  const hammerHistory = document.getElementById('hammer-scan-history');
  if (hammerSystemFolder) {
    hammerSystemFolder.addEventListener('click', async () => {
      window.electronAPI.notify({ title: 'System Folder Monitor', body: 'System folder monitor triggered.' });
    });
  }
  if (hammerAttachment) {
    hammerAttachment.addEventListener('click', async () => {
      window.electronAPI.notify({ title: 'Attachment Inspector', body: 'Attachment inspector triggered.' });
    });
  }
  if (hammerHash) {
    hammerHash.addEventListener('click', async () => {
      window.electronAPI.notify({ title: 'Hash Verification', body: 'Hash verification triggered.' });
    });
  }
  if (hammerHistory) {
    hammerHistory.addEventListener('click', async () => {
      window.electronAPI.notify({ title: 'Scan History', body: 'Scan history triggered.' });
    });
  }
import './index.css';
import { initializeSandboxHandling } from './sandboxHandler.js';

// DOM elements
const fileDropZone = document.getElementById('file-drop-zone');
const sandboxDropZone = document.getElementById('sandbox-file-drop-zone');
const emailInput = document.getElementById('email-input');
const phoneInput = document.getElementById('phone-input');
const urlInput = document.getElementById('url-input');
const textInput = document.getElementById('text-input');
const monitoringToggle = document.getElementById('monitoring-toggle');
const monitoringStatus = document.getElementById('monitoring-status');
const resultsContainer = document.getElementById('results-container');
const sandboxResultsContainer = document.getElementById('sandbox-results-container');
const settingsButton = document.getElementById('settings-button');
const settingsMenu = document.getElementById('settings-menu');
const startupSwitch = document.getElementById('startup-switch');
const themeToggle = document.getElementById('theme-toggle');
const scanClipboardBtn = document.getElementById('scan-clipboard-btn');
const scanButton = document.getElementById('scan-button');
const filesList = document.getElementById('files-list');
const filesClear = document.getElementById('files-clear');
const sandboxFilesList = document.getElementById('sandbox-files-list');
const sandboxFilesClear = document.getElementById('sandbox-files-clear');
// Background protection toggle (simple)
let bgToggleEl = document.getElementById('bg-toggle');
let droppedFiles = [];
let sandboxFiles = [];

// Ensure the window itself doesn't navigate away on file drop
window.addEventListener('dragover', (e) => { e.preventDefault(); }, false);
window.addEventListener('drop', (e) => { e.preventDefault(); }, false);

// State
let isMonitoring = false;
let dragCounter = 0;

// Initialize app
document.addEventListener('DOMContentLoaded', async () => {
  // Initialize sandbox handling
  initializeSandboxHandling();
  
  // Advanced toggles
  const sandboxToggle = document.getElementById('toggle-sandbox');
  if (sandboxToggle) {
    sandboxToggle.addEventListener('change', async (e) => {
      window.sandboxEnabled = e.target.checked;
    });
  }
  // (Other toggles are handled in index.html inline script)
  console.log('[UI] DOMContentLoaded');
  if (!window.electronAPI || typeof window.electronAPI.detectSpam !== 'function') {
    console.error('[UI] electronAPI bridge missing');
    if (resultsContainer) {
      resultsContainer.innerHTML = `
        <div class="result-item danger">
          <div class="result-header">
            <span class="result-icon">⚠️</span>
            <span class="result-status">Bridge Not Available</span>
          </div>
          <div class="result-details">
            <div>Preload bridge is not available. Ensure contextIsolation is true and preload is set.</div>
          </div>
        </div>
      `;
    }
  }
  // Bind UI events immediately so clicks are not blocked by async errors
  setupEventListeners();
  setupDragAndDrop();
  // Do not let status fetch block the UI if IPC is unavailable
  try {
    await updateMonitoringStatus();
  } catch (e) {
    console.error('[UI] updateMonitoringStatus failed:', e);
  }
  // Initialize startup toggle label
  try {
    if (startupSwitch && window.electronAPI && typeof window.electronAPI.getAutoLaunch === 'function') {
      const enabled = await window.electronAPI.getAutoLaunch();
      startupSwitch.checked = !!enabled;
    }
  } catch (e) {
    console.error('[UI] getAutoLaunch failed:', e);
  }

  // Sandbox button logic
  const sandboxBtn = document.getElementById('sandbox-btn');
  const sandboxModal = document.getElementById('sandbox-modal');
  const sandboxResult = document.getElementById('sandbox-result');
  const sandboxClose = document.getElementById('sandbox-close');
  if (sandboxBtn && sandboxModal && sandboxResult && sandboxClose) {
    sandboxBtn.addEventListener('click', async () => {
      try {
        // showFileDialog may return either a string path or an object { filePath, sandboxResult }
        const picked = await window.electronAPI.showFileDialog();
        if (!picked) return;
        let filePath;
        let precomputedResult = null;
        if (typeof picked === 'string') {
          filePath = picked;
        } else if (picked && typeof picked === 'object') {
          // Newer handler may return { filePath, sandboxResult }
          filePath = picked.filePath || picked.path || null;
          if (picked.sandboxResult) precomputedResult = picked.sandboxResult;
        }
        if (!filePath) return;

        sandboxResult.textContent = 'Running file in sandbox...';
        sandboxModal.style.display = 'flex';

        let result = precomputedResult;
        if (!result) {
          // Only call runFileSandboxed if we don't already have the analysis
          result = await window.electronAPI.runFileSandboxed(filePath);
        }
        sandboxResult.textContent = JSON.stringify(result, null, 2);
      } catch (e) {
        sandboxResult.textContent = 'Error: ' + (e && e.message ? e.message : String(e));
        sandboxModal.style.display = 'flex';
      }
    });
    sandboxClose.addEventListener('click', () => {
      sandboxModal.style.display = 'none';
    });
  }

  // Sandbox trust info tooltip
  const trustInfoBtn = document.getElementById('sandbox-trust-info');
  if (trustInfoBtn) {
    trustInfoBtn.addEventListener('click', () => {
      const msg = `Trust Score (0-100) is an automated heuristic combining:\n
- File type & architecture (compatibility)\n+- Capability detection (network, file-system, system commands)\n+- Entropy (high entropy may indicate packing/encryption)\n+- Suspicious embedded strings (URLs, emails, suspicious keywords)\n+- Digital signature presence and hash checks\n+- File permissions and executability\n\nHigher is safer (>=75 green). Medium (40-74) requires caution. Low (<40) is risky. This is heuristic guidance — always verify with additional tools.`;
      alert(msg);
    });
  }
});

// Setup event listeners
async function setupEventListeners() {
  if (!scanButton) {
    console.error('[UI] scanButton not found in DOM');
    return;
  }
  // Monitoring toggle (single-check mode)
  if (monitoringToggle) {
    console.log('[Renderer] Monitoring toggle element found, attaching event listener');
    monitoringToggle.addEventListener('click', async () => {
      console.log('[Renderer] Monitoring toggle clicked - triggering single check');
      // Trigger single clipboard check
      await window.electronAPI.toggleMonitoring();
      // Reset toggle after a delay (for visual feedback)
      setTimeout(() => {
        monitoringToggle.checked = false;
        monitoringStatus.textContent = 'Ready';
        monitoringStatus.className = 'status-inactive';
      }, 1000);
    });
  } else {
    console.error('[Renderer] Monitoring toggle element NOT found!');
  }

  // Background protection
  if (bgToggleEl) {
    const setBgLabel = (on) => {
      bgToggleEl.textContent = on ? 'Background Protection: On' : 'Background Protection: Off';
    };
    bgToggleEl.addEventListener('click', async () => {
      const status = await window.electronAPI.toggleBackgroundProtection();
      console.log('[UI] Background protection:', status);
      setBgLabel(!!status);
    });
    try {
      const status = await window.electronAPI.getBackgroundProtection();
      setBgLabel(!!status);
    } catch {}
  }

  // Settings menu toggle
  if (settingsButton && settingsMenu) {
    settingsButton.addEventListener('click', (e) => {
      e.stopPropagation();
      const visible = settingsMenu.style.display === 'block';
      settingsMenu.style.display = visible ? 'none' : 'block';
    });
    document.addEventListener('click', (e) => {
      if (settingsMenu.style.display === 'block' && !settingsMenu.contains(e.target) && e.target !== settingsButton) {
        settingsMenu.style.display = 'none';
      }
    });
  }

  // Startup (auto-launch) switch
  if (startupSwitch && window.electronAPI && typeof window.electronAPI.setAutoLaunch === 'function') {
    startupSwitch.addEventListener('change', async () => {
      try {
        const res = await window.electronAPI.setAutoLaunch(startupSwitch.checked);
        if (!res || !res.ok) startupSwitch.checked = !startupSwitch.checked;
      } catch (e) {
        console.error('[UI] setAutoLaunch failed:', e);
        startupSwitch.checked = !startupSwitch.checked;
      }
    });
  }

  // Theme toggle
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const isLight = document.body.classList.toggle('light-theme');
      themeToggle.textContent = isLight ? 'Dark' : 'Light';
    });
  }

  // Scan clipboard on demand
  if (scanClipboardBtn && window.electronAPI && typeof window.electronAPI.scanClipboardNow === 'function') {
    scanClipboardBtn.addEventListener('click', async () => {
      try {
        await window.electronAPI.scanClipboardNow();
      } catch (e) {
        console.error('[UI] scanClipboardNow failed:', e);
      }
    });
  }

  if (filesClear) {
    filesClear.addEventListener('click', () => {
      droppedFiles = [];
      renderFilesList();
    });
  }

  // Real-time validation
  emailInput.addEventListener('input', debounce(validateEmail, 500));
  phoneInput.addEventListener('input', debounce(validatePhone, 500));
  urlInput.addEventListener('input', debounce(validateUrl, 500));
  textInput.addEventListener('input', debounce(validateText, 500));

  // Scan button
  scanButton.addEventListener('click', scanAllInputs);
}

function setStartupLabel(on) {
  if (!startupToggle) return;
  startupToggle.textContent = on ? 'Startup: On' : 'Startup: Off';
}

// Setup drag and drop
function setupDragAndDrop() {
  if (!fileDropZone) {
    console.error('[UI] fileDropZone not found');
    return;
  }
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    fileDropZone.addEventListener(eventName, preventDefaults, false);
  });

  ['dragenter', 'dragover'].forEach(eventName => {
    fileDropZone.addEventListener(eventName, highlight, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    fileDropZone.addEventListener(eventName, unhighlight, false);
  });

  fileDropZone.addEventListener('drop', handleDrop, false);
}

function preventDefaults(e) {
  e.preventDefault();
  e.stopPropagation();
}

function highlight(e) {
  dragCounter++;
  fileDropZone.classList.add('drag-over');
}

function unhighlight(e) {
  dragCounter--;
  if (dragCounter === 0) {
    fileDropZone.classList.remove('drag-over');
  }
}

async function handleDrop(e) {
  dragCounter = 0;
  fileDropZone.classList.remove('drag-over');
  
  const files = e.dataTransfer.files;
  if (files.length > 0) {
    console.log('[UI] File dropped:', { name: files[0].name, type: files[0].type, size: files[0].size, path: files[0].path });
    enqueueFile(files[0]);
  }
}

// File scanning
async function scanFile(file) {
  showLoading('Scanning file...');
  try {
    if (file.path) {
      // Use sandbox analyzer for full-file safety checks (handles binaries and all file types)
      const result = await window.electronAPI.runFileSandboxed(file.path);
      console.log('[UI] runFileSandboxed result:', result);

      // Persist trust score for UI listing
      if (result && result.riskAssessment && typeof result.riskAssessment.trustScore === 'number') {
        file.trustScore = result.riskAssessment.trustScore;
      }

      // Map sandbox result to summary shape for showResult
      const trust = result && result.riskAssessment && typeof result.riskAssessment.trustScore === 'number'
        ? result.riskAssessment.trustScore : null;
      const riskLevel = result && result.riskAssessment && result.riskAssessment.riskLevel ? result.riskAssessment.riskLevel : 'low';
      const summary = {
        isSpam: riskLevel === 'high' || (trust !== null && trust < 40),
        confidence: trust !== null ? 100 - trust : (result && result.riskAssessment && result.riskAssessment.warnings ? 50 : 0),
        score: trust !== null ? trust : 100 - (result && result.riskAssessment && result.riskAssessment.warnings ? result.riskAssessment.warnings.length * 10 : 0),
        verdict: riskLevel === 'high' ? 'spam_bot' : riskLevel === 'medium' ? 'suspicious' : 'valid',
        reasons: (result && result.riskAssessment && result.riskAssessment.warnings) || [],
        type: result && result.fileType ? result.fileType : 'file',
        riskLevel: riskLevel
      };

      // Display detailed sandbox results in the dedicated container if available
      try {
        if (typeof window.displaySandboxResults === 'function') {
          window.displaySandboxResults([{ name: file.name || file.path.split(/[/\\]/).pop(), result }]);
        }
      } catch {}

      showResult(summary);
    } else if (typeof file.text === 'function') {
      const text = await file.text();
      const result = await window.electronAPI.detectSpam(text);
      console.log('[UI] scanFile via content result:', result);
      showResult(result);
    } else {
      showResult({
        isSpam: false,
        confidence: 0,
        score: 0,
        verdict: 'valid',
        reasons: ['Cannot read file content.'],
        type: 'file',
        riskLevel: 'low'
      });
    }
  } catch (error) {
    console.error('[UI] scanFile error:', error);
    showResult({
      isSpam: false,
      confidence: 0,
      score: 0,
      verdict: 'valid',
      reasons: ['Error scanning file: ' + (error && error.message ? error.message : String(error))],
      type: 'file',
      riskLevel: 'low'
    });
  }
}

function enqueueFile(file) {
  droppedFiles.push(file);
  renderFilesList();
}

function renderFilesList() {
  if (!filesList) return;
  filesList.innerHTML = '';
  if (droppedFiles.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No files queued.';
    li.style.color = '#888';
    filesList.appendChild(li);
    return;
  }
  droppedFiles.forEach((f, idx) => {
    const li = document.createElement('li');
    li.style.display = 'flex';
    li.style.alignItems = 'center';
    li.style.justifyContent = 'space-between';
    li.style.gap = '8px';
    li.style.padding = '6px 0';
    const name = document.createElement('span');
    name.textContent = f.name || 'unnamed';
    name.style.flex = '1';
    // Show trust score badge if available
    if (typeof f.trustScore === 'number') {
      const badge = document.createElement('span');
      badge.textContent = `${f.trustScore}/100`;
      badge.className = 'text-sm font-semibold';
      badge.style.marginLeft = '8px';
      badge.style.color = f.trustScore >= 75 ? '#16a34a' : f.trustScore >= 40 ? '#f59e0b' : '#ef4444';
      name.appendChild(badge);
    }
    const del = document.createElement('button');
    del.textContent = 'Remove';
    del.className = 'btn btn-danger';
    del.style.padding = '6px 10px';
    del.style.fontSize = '12px';
    del.style.background = '#991b1b';
    del.style.color = '#fff';
    del.style.borderRadius = '6px';
    del.addEventListener('click', () => {
      droppedFiles.splice(idx, 1);
      renderFilesList();
      // If sandbox inspection is on, re-run it
      if (window.sandboxEnabled && document.getElementById('toggle-sandbox').checked) {
        document.getElementById('toggle-sandbox').dispatchEvent(new Event('change'));
      }
    });
    li.appendChild(name);
    li.appendChild(del);
    filesList.appendChild(li);
  });
}

// Real-time validation functions
async function validateEmail() {
  const email = emailInput.value.trim();
  if (!email) return;
  
  const result = await window.electronAPI.detectSpam(email);
  showInlineResult(emailInput, result);
}

async function validatePhone() {
  const phone = phoneInput.value.trim();
  if (!phone) return;
  
  const result = await window.electronAPI.detectSpam(phone);
  showInlineResult(phoneInput, result);
}

async function validateUrl() {
  const url = urlInput.value.trim();
  if (!url) return;
  
  const result = await window.electronAPI.detectSpam(url);
  showInlineResult(urlInput, result);
}

async function validateText() {
  const text = textInput.value.trim();
  if (!text) return;
  
  const result = await window.electronAPI.detectSpam(text);
  showInlineResult(textInput, result);
}

// Show inline validation results
function showInlineResult(input, result) {
  // Remove existing validation classes
  input.classList.remove('valid', 'warning', 'danger');
  
  // Add appropriate class based on result
  if (result.isSpam) {
    if ((result.score ?? result.confidence) > 70) {
      input.classList.add('danger');
    } else {
      input.classList.add('warning');
    }
  } else {
    input.classList.add('valid');
  }
  
  // Show tooltip with details
  const score = result.score ?? result.confidence ?? 0;
  const verdict = result.verdict ?? (score >= 70 ? 'spam_bot' : score >= 30 ? 'suspicious' : 'valid');
  input.title = result.isSpam 
    ? `Verdict: ${verdict} • Score: ${score} • Reasons: ${result.reasons.join(', ')}`
    : `Verdict: valid • Score: ${score}`;
}

// Scan all inputs
async function scanAllInputs() {
  console.log('[UI] Scan all inputs clicked');
  const inputs = [
    { value: emailInput.value.trim(), label: 'Email' },
    { value: phoneInput.value.trim(), label: 'Phone' },
    { value: urlInput.value.trim(), label: 'URL' },
    { value: textInput.value.trim(), label: 'Text' }
  ].filter(input => input.value);

  // Proceed if either text inputs or queued files are present
  if (inputs.length === 0 && droppedFiles.length === 0) {
    showResult({
      isSpam: false,
      confidence: 0,
      score: 0,
      verdict: 'valid',
      reasons: ['No content to scan'],
      type: 'text',
      riskLevel: 'low'
    });
    return;
  }

  // Button loading state
  const originalText = scanButton.textContent;
  scanButton.textContent = '⏳ Scanning...';
  scanButton.disabled = true;
  showLoading('Scanning all inputs...');
  
  try {
    if (!window.electronAPI || typeof window.electronAPI.detectSpam !== 'function') {
      throw new Error('IPC bridge unavailable (electronAPI.detectSpam not found)');
    }
    let combined = inputs.map(input => `${input.label}: ${input.value}`).join('\n\n');
    if (droppedFiles.length) {
      combined += '\n\n--- Files ---';
      for (const f of droppedFiles) {
        combined += `\n[File: ${f.name || 'unnamed'}]`;
        try {
          if (!f.path && typeof f.text === 'function') {
            const t = await f.text();
            combined += `\n${t.substring(0, 4000)}`;
          } else if (f.path) {
            const read = await window.electronAPI.readFileText(f.path);
            if (read && read.ok && read.content) {
              combined += `\n${read.content.substring(0, 4000)}`;
            }
          }
        } catch {}
      }
    }
    if (!combined.trim()) {
      // As a safety, if nothing accumulated (edge cases), indicate file names
      combined = droppedFiles.map(f => `[File: ${f.name || 'unnamed'}]`).join('\n');
    }
    const result = await window.electronAPI.detectSpam(combined);
    console.log('[UI] Scan result:', result);
    showResult(result);
    // Notify OS after each test/scan
    try {
      const summary = result.isSpam ? 'Spam detected' : 'Safe';
      const score = result.score ?? result.confidence ?? 0;
      await window.electronAPI.notify({ title: 'Scan Complete', body: `${summary} • Score: ${score}` });
    } catch {}
  } catch (error) {
    console.error('[UI] Scan error:', error);
    showResult({
      isSpam: false,
      confidence: 0,
      score: 0,
      verdict: 'valid',
      reasons: ['Error scanning content: ' + (error && error.message ? error.message : String(error))],
      type: 'text',
      riskLevel: 'low'
    });
  } finally {
    scanButton.textContent = originalText;
    scanButton.disabled = false;
  }
}

// Update monitoring status
async function updateMonitoringStatus() {
  isMonitoring = await window.electronAPI.getMonitoringStatus();
  monitoringStatus.textContent = isMonitoring ? 'Active' : 'Inactive';
  monitoringStatus.className = isMonitoring ? 'status-active' : 'status-inactive';
  monitoringToggle.textContent = isMonitoring ? 'Stop Monitoring' : 'Start Monitoring';
  
  // Set up clipboard monitoring if active
  if (isMonitoring) {
    setupClipboardMonitoring();
  }
}

// Set up real-time clipboard monitoring
let lastClipboardContent = '';
let clipboardCheckInterval;

async function setupClipboardMonitoring() {
  const contentEl = document.getElementById('clipboard-content');
  const resultEl = document.getElementById('clipboard-scan-result');
  
  // Clear any existing interval
  if (clipboardCheckInterval) {
    clearInterval(clipboardCheckInterval);
  }
  
  // Function to update clipboard display
  const updateDisplay = async () => {
    try {
      const content = await window.electronAPI.getClipboardContent();
      
      // Only proceed if content has changed
      if (content !== lastClipboardContent) {
        lastClipboardContent = content;
        
        if (content && content.trim()) {
          // Update content immediately
          contentEl.textContent = content;
          contentEl.style.color = '#aef';
          
          // Show analyzing status
          resultEl.textContent = '🔄 Analyzing...';
          resultEl.style.color = '#aef';
          
          // Trigger immediate scan
          const scanResult = await window.electronAPI.scanClipboardNow();
          if (scanResult && scanResult.ok && scanResult.result) {
            const analysis = scanResult.result;
            const score = analysis.score || analysis.confidence || 0;
            const isSpam = analysis.isSpam;
            
            // Update result with emoji and color
            if (isSpam) {
              resultEl.textContent = `⚠️ Warning: Suspicious Content • Score: ${score}`;
              resultEl.style.color = '#fb7185';
            } else {
              resultEl.textContent = `✅ Safe Content • Score: ${score}`;
              resultEl.style.color = '#4ade80';
            }
          }
        } else {
          contentEl.textContent = 'Nothing copied yet.';
          contentEl.style.color = '#888';
          resultEl.textContent = 'No scan yet.';
          resultEl.style.color = '#888';
        }
      }
    } catch (error) {
      console.error('Clipboard monitoring error:', error);
    }
  };
  
  // Set up interval for checking clipboard
  clipboardCheckInterval = setInterval(updateDisplay, 100);
  
  // Do initial check
  await updateDisplay();
  
  // Listen for copy/paste events
  document.addEventListener('copy', () => setTimeout(updateDisplay, 50));
  document.addEventListener('paste', () => setTimeout(updateDisplay, 50));
}

// Show loading state
function showLoading(message) {
  resultsContainer.innerHTML = `
    <div class="result-item loading">
      <div class="spinner"></div>
      <span>${message}</span>
    </div>
  `;
}

// Show scan results
function showResult(result) {
  const riskClass = result.riskLevel === 'high' ? 'danger' : 
                   result.riskLevel === 'medium' ? 'warning' : 'safe';
  
  const icon = result.isSpam ? '🚨' : '✅';
  const status = result.isSpam ? 'SPAM DETECTED' : 'SAFE';
  const score = result.score ?? result.confidence ?? 0;
  const verdict = result.verdict ?? (score >= 70 ? 'spam_bot' : score >= 30 ? 'suspicious' : 'valid');
  
  resultsContainer.innerHTML = `
    <div class="result-item ${riskClass}">
      <div class="result-header">
        <span class="result-icon">${icon}</span>
        <span class="result-status">${status}</span>
        <span class="result-confidence">Score: ${score} • Verdict: ${verdict}</span>
      </div>
      <div class="result-details">
        <div class="result-type">Type: ${result.type}</div>
        <div class="result-risk">Risk Level: ${result.riskLevel}</div>
        ${result.reasons.length > 0 ? `
          <div class="result-reasons">
            <strong>Reasons:</strong>
            <ul>
              ${result.reasons.map(reason => `<li>${reason}</li>`).join('')}
            </ul>
          </div>
        ` : ''}
      </div>
    </div>
  `;
}

// Utility function for debouncing
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Handle file dialog button
document.getElementById('file-dialog-btn').addEventListener('click', async () => {
  try {
    const picked = await window.electronAPI.showFileDialog();
    if (!picked) return;
    let filePath;
    if (typeof picked === 'string') filePath = picked;
    else if (picked && typeof picked === 'object') filePath = picked.filePath || picked.path || null;
    if (!filePath) return;
    const file = { path: filePath };
    await scanFile(file);
  } catch (e) {
    console.error('[UI] file-dialog error:', e);
  }
});

console.log('🚀 Spam Detector Pro initialized');