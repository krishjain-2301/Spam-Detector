// Sandbox file handling functions
let sandboxFiles = [];

export function renderSandboxFilesList() {
  const sandboxFilesList = document.getElementById('sandbox-files-list');
  const analyzeAllBtn = document.getElementById('sandbox-analyze-all');
  if (!sandboxFilesList) return;
  
  sandboxFilesList.innerHTML = '';
  
  if (sandboxFiles.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No files in queue';
    li.className = 'text-slate-500 italic text-center';
    sandboxFilesList.appendChild(li);
    if (analyzeAllBtn) analyzeAllBtn.style.display = 'none';
    return;
  }

  if (analyzeAllBtn) analyzeAllBtn.style.display = 'block';
  
  sandboxFiles.forEach((file, idx) => {
    const li = document.createElement('li');
    li.className = 'flex items-center justify-between p-3 bg-slate-800/40 hover:bg-slate-700/30 rounded-lg gap-2';
    
    const fileInfo = document.createElement('div');
    fileInfo.className = 'flex items-center gap-3 flex-1';
    
    const icon = document.createElement('span');
    icon.textContent = '📄';
    icon.className = 'text-lg';
    
    const fileDetails = document.createElement('div');
    fileDetails.className = 'flex-1';
    
    const name = document.createElement('div');
    name.textContent = file.name;
    name.className = 'font-medium text-slate-200';
    
    const status = document.createElement('div');
    status.textContent = file.status || 'Ready for analysis';
    status.className = 'text-xs ' + 
      (file.status === 'Analyzed' ? 'text-green-400' :
       file.status === 'Analyzing...' ? 'text-yellow-400' :
       file.status === 'Error' ? 'text-red-400' : 'text-slate-400');
    
    fileDetails.appendChild(name);
    fileDetails.appendChild(status);

    // Show trust score badge if available
    if (typeof file.trustScore === 'number') {
      const badge = document.createElement('span');
      badge.textContent = `${file.trustScore}/100`;
      badge.title = 'Trust Score — higher is safer. Click "Run Analysis" for details.';
      badge.className = 'text-sm font-semibold ml-2';
      badge.style.color = file.trustScore >= 75 ? '#16a34a' : file.trustScore >= 40 ? '#f59e0b' : '#ef4444';
      fileDetails.appendChild(badge);
    }
    
    fileInfo.appendChild(icon);
    fileInfo.appendChild(fileDetails);
    
    const controls = document.createElement('div');
    controls.className = 'flex items-center gap-2';
    
    const analyzeSingle = document.createElement('button');
    analyzeSingle.textContent = '🔍';
    analyzeSingle.title = 'Analyze file';
    analyzeSingle.className = 'p-2 hover:bg-slate-700/50 rounded';
    analyzeSingle.addEventListener('click', async () => {
      try {
        file.status = 'Analyzing...';
        renderSandboxFilesList();
        const result = await window.electronAPI.runFileSandboxed(file.path);
        // Persist trust score to file entry if present
        try {
          if (result && result.riskAssessment && typeof result.riskAssessment.trustScore === 'number') {
            file.trustScore = result.riskAssessment.trustScore;
          } else if (result && result.riskAssessment && typeof result.riskAssessment.trustScore === 'undefined' && result.riskAssessment && typeof result.riskAssessment.trustScore !== 'number') {
            // leave as-is
          }
        } catch (e) {}
        file.status = 'Analyzed';
        displaySandboxResults([{ name: file.name, result }]);
      } catch (err) {
        file.status = 'Error';
        displaySandboxResults([{ 
          name: file.name, 
          result: { error: err && err.message ? err.message : String(err) }
        }]);
      }
      renderSandboxFilesList();
    });
    
    const del = document.createElement('button');
    del.textContent = '×';
    del.title = 'Remove from queue';
    del.className = 'p-2 text-red-400 hover:text-red-300 hover:bg-red-900/20 rounded';
    del.addEventListener('click', () => {
      sandboxFiles.splice(idx, 1);
      renderSandboxFilesList();
    });
    
    controls.appendChild(analyzeSingle);
    // Run button (opens terminal-like modal with countdown and optional real execution)
    const runBtn = document.createElement('button');
    runBtn.textContent = '▶';
    runBtn.title = 'Run in sandbox (simulated by default)';
    runBtn.className = 'p-2 hover:bg-slate-700/50 rounded';
    runBtn.addEventListener('click', async () => {
      // Create modal
      let modal = document.getElementById('run-modal');
      if (!modal) {
        modal = document.createElement('div');
        modal.id = 'run-modal';
        modal.style.position = 'fixed';
        modal.style.left = '0';
        modal.style.top = '0';
        modal.style.width = '100%';
        modal.style.height = '100%';
        modal.style.background = 'rgba(0,0,0,0.6)';
        modal.style.display = 'flex';
        modal.style.alignItems = 'center';
        modal.style.justifyContent = 'center';
        modal.style.zIndex = '9999';
        modal.innerHTML = `
          <div id="run-modal-box" style="background:#0b1220;color:#e5e7eb;padding:16px;border-radius:8px;max-width:800px;width:90%;font-family:monospace;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
              <strong id="run-modal-title">Running: ${file.name}</strong>
              <div>
                <label style="font-size:12px;margin-right:8px"><input id="run-real-checkbox" type="checkbox"> Actually execute</label>
                <button id="run-modal-close" style="background:#7f1d1d;color:#fff;border:none;padding:6px;border-radius:4px;">Close</button>
              </div>
            </div>
            <div id="run-modal-output" style="background:#020617;color:#c7d2fe;padding:12px;border-radius:6px;height:320px;overflow:auto;white-space:pre-wrap;"></div>
            <div style="margin-top:8px;text-align:right;"><button id="run-modal-start" style="padding:8px 12px;border-radius:6px;background:#065f46;color:#fff;border:none;">Start</button></div>
          </div>
        `;
        document.body.appendChild(modal);

        // Close handler
        modal.querySelector('#run-modal-close').addEventListener('click', () => { modal.remove(); });
      } else {
        modal.style.display = 'flex';
        modal.querySelector('#run-modal-title').textContent = `Running: ${file.name}`;
      }

      const outEl = modal.querySelector('#run-modal-output');
      const startBtn = modal.querySelector('#run-modal-start');
      const realCheckbox = modal.querySelector('#run-real-checkbox');

      const append = (txt) => { outEl.textContent += txt + '\n'; outEl.scrollTop = outEl.scrollHeight; };

      startBtn.onclick = async () => {
        startBtn.disabled = true;
        append('Preparing sandbox...');
        // Countdown
        for (let i = 5; i >= 1; --i) {
          append(`Executing in ${i}...`);
          await new Promise(r => setTimeout(r, 700));
        }

        append('Starting run...');
        const shouldExecute = !!realCheckbox.checked;
        try {
          const result = await window.electronAPI.executeFile({ path: file.path, execute: shouldExecute, timeout: 15000 });
          if (!result.ok) {
            append('Error: ' + (result.error || 'Unknown error'));
          } else if (result.simulated) {
            append('[SIMULATION] ' + (result.message || 'Simulated run complete'));
            append('\n' + (result.stdout || ''));
          } else {
            append('=== Process finished ===');
            append('Exit code: ' + (typeof result.exitCode !== 'undefined' ? result.exitCode : 'N/A'));
            append('Timed out: ' + (result.timedOut ? 'Yes' : 'No'));
            if (result.stdout) append('\n--- STDOUT ---\n' + result.stdout);
            if (result.stderr) append('\n--- STDERR ---\n' + result.stderr);
          }
        } catch (err) {
          append('Execution failed: ' + (err && err.message ? err.message : String(err)));
        }
        startBtn.disabled = false;
      };
    });
    controls.appendChild(runBtn);
    controls.appendChild(del);
    
    li.appendChild(fileInfo);
    li.appendChild(controls);
    sandboxFilesList.appendChild(li);
  });
}

// Handle sandbox file drop
export async function handleSandboxDrop(e) {
  e.preventDefault();
  unhighlight(e);
  
  const items = e.dataTransfer.items;
  if (!items) return;
  
  for (const item of items) {
    if (item.kind === 'file') {
      const file = item.getAsFile();
      if (file) {
        // Add the file to the queue with metadata
        sandboxFiles.push({
          name: file.name,
          path: file.path,
          size: file.size,
          type: file.type,
          lastModified: file.lastModified,
          status: 'Ready for analysis'
        });
      }
    }
  }
  
  renderSandboxFilesList();
}

// Display sandbox analysis results in a user-friendly format
function formatRiskLevel(level) {
    const colors = { low: '#28a745', medium: '#ffc107', high: '#dc3545' };
    return `<span style="color: ${colors[level]}; font-weight: bold; text-transform: uppercase;">${level}</span>`;
}

function displaySandboxResults(results) {
    const container = document.getElementById('sandbox-results-container');
    if (!container) {
        console.error('Sandbox results container not found');
        return;
    }

    const resultsList = results.map(({name, result}) => {
        if (result.error) {
            return `
                <div class="sandbox-error">
                    <h4>⚠️ Error Analyzing ${name}</h4>
                    <p>${result.error}</p>
                </div>
            `;
        }

      const trustScore = (result.riskAssessment && typeof result.riskAssessment.trustScore === 'number') ? result.riskAssessment.trustScore : null;
      const trustColor = trustScore === null ? '#9CA3AF' : (trustScore >= 75 ? '#16a34a' : trustScore >= 40 ? '#f59e0b' : '#ef4444');
      return `
          <div class="sandbox-analysis">
            <h3>Analysis Results: ${name}</h3>
            <div class="file-info">
              <p><strong>File Type:</strong> ${result.fileType}</p>
              <p><strong>Size:</strong> ${result.fileInfo.size} bytes</p>
              <p><strong>Last Modified:</strong> ${new Date(result.fileInfo.modified).toLocaleString()}</p>
              <p><strong>Risk Level:</strong> ${formatRiskLevel(result.riskAssessment.riskLevel)}</p>
              ${ trustScore !== null ? `<p><strong>Trust Score:</strong> <span style="color:${trustColor}; font-weight:700">${trustScore}/100</span></p>` : `<p><strong>Trust Score:</strong> <span style="color:#9CA3AF">N/A</span></p>` }
            </div>
                
                ${result.contentAnalysis ? `
                    <div class="content-analysis">
                        <h4>Content Analysis</h4>
                        <ul>
                            <li>Lines: ${result.contentAnalysis.lines}</li>
                            <li>Contains Scripts: ${result.contentAnalysis.containsScripts ? '⚠️ Yes' : '✓ No'}</li>
                            <li>Contains URLs: ${result.contentAnalysis.containsUrls.length > 0 ? '⚠️ Yes' : '✓ No'}</li>
                            <li>Contains Base64: ${result.contentAnalysis.containsBase64 ? '⚠️ Yes' : '✓ No'}</li>
                            <li>Contains Shell Commands: ${result.contentAnalysis.containsShellCommands ? '⚠️ Yes' : '✓ No'}</li>
                        </ul>
                        ${Object.entries(result.contentAnalysis.suspiciousPatterns).length > 0 ? `
                            <h5>⚠️ Suspicious Patterns Detected</h5>
                            <ul>
                                ${Object.entries(result.contentAnalysis.suspiciousPatterns)
                                    .map(([key, count]) => `<li>${key}: ${count} occurrence(s)</li>`)
                                    .join('')}
                            </ul>
                        ` : ''}
                    </div>
                ` : ''}
                
                ${result.binaryAnalysis ? `
                    <div class="binary-analysis">
                        <h4>Binary Analysis</h4>
                        <ul>
                            <li>Executable: ${result.binaryAnalysis.isExecutable ? '⚠️ Yes' : '✓ No'}</li>
                            <li>Potentially Harmful: ${result.binaryAnalysis.isPotentiallyHarmful ? '⚠️ Yes' : '✓ No'}</li>
                            <li>Signed: ${result.binaryAnalysis.signatures.isSigned ? '✓ Yes' : '⚠️ No'}</li>
                        </ul>
                    </div>
                ` : ''}
                
                <div class="risk-assessment">
                    <h4>Risk Assessment</h4>
                    ${result.riskAssessment.warnings.length > 0 ? `
                        <div class="warnings">
                            <h5>⚠️ Warnings</h5>
                            <ul>
                                ${result.riskAssessment.warnings.map(warning => `<li>${warning}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    ${result.riskAssessment.recommendations.length > 0 ? `
                        <div class="recommendations">
                            <h5>💡 Recommendations</h5>
                            <ul>
                                ${result.riskAssessment.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('<hr>');

    container.innerHTML = resultsList;
    container.style.display = 'block';
}

// Prevent default behaviors
export function preventDefaults(e) {
  e.preventDefault();
  e.stopPropagation();
}

// Highlight drop zone
export function highlight(e) {
  const dropZone = e.target.closest('.file-drop-zone');
  if (dropZone) {
    dropZone.classList.add('bg-slate-800/60');
  }
}

// Remove highlight from drop zone
export function unhighlight(e) {
  const dropZone = e.target.closest('.file-drop-zone');
  if (dropZone) {
    dropZone.classList.remove('bg-slate-800/60');
  }
}

// Initialize sandbox handling
export function initializeSandboxHandling() {
  const sandboxDropZone = document.getElementById('sandbox-file-drop-zone');
  const sandboxFilesClear = document.getElementById('sandbox-files-clear');
  const sandboxDialogBtn = document.getElementById('sandbox-dialog-btn');
  const sandboxAnalyzeAll = document.getElementById('sandbox-analyze-all');

  // Setup analyze all button
  if (sandboxAnalyzeAll) {
    sandboxAnalyzeAll.addEventListener('click', async () => {
      const results = [];
      for (const file of sandboxFiles) {
        try {
          file.status = 'Analyzing...';
          renderSandboxFilesList();
          const result = await window.electronAPI.runFileSandboxed(file.path);
          // Save trust score back to queue entry
          if (result && result.riskAssessment && typeof result.riskAssessment.trustScore === 'number') {
            file.trustScore = result.riskAssessment.trustScore;
          }
          file.status = 'Analyzed';
          results.push({ name: file.name, result });
        } catch (err) {
          file.status = 'Error';
          results.push({ 
            name: file.name, 
            result: { error: err && err.message ? err.message : String(err) }
          });
        }
        renderSandboxFilesList();
      }
      displaySandboxResults(results);
    });
  }

  // Setup sandbox drag and drop events
  if (sandboxDropZone) {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      sandboxDropZone.addEventListener(eventName, preventDefaults, false);
    });
    
    ['dragenter', 'dragover'].forEach(eventName => {
      sandboxDropZone.addEventListener(eventName, highlight, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
      sandboxDropZone.addEventListener(eventName, unhighlight, false);
    });
    
    sandboxDropZone.addEventListener('drop', handleSandboxDrop, false);
  }

  // Setup sandbox clear button
  if (sandboxFilesClear) {
    sandboxFilesClear.addEventListener('click', () => {
      sandboxFiles = [];
      renderSandboxFilesList();
    });
  }

  // Setup sandbox file dialog button
  if (sandboxDialogBtn) {
    sandboxDialogBtn.addEventListener('click', async () => {
      try {
        const picked = await window.electronAPI.showFileDialog();
        if (!picked) return;

        // showFileDialog may return either a string path or an object { filePath, sandboxResult }
        let filePath;
        let precomputed = null;
        if (typeof picked === 'string') {
          filePath = picked;
        } else if (picked && typeof picked === 'object') {
          filePath = picked.filePath || picked.path || null;
          if (picked.sandboxResult) precomputed = picked.sandboxResult;
        }
        if (!filePath) return;

        const file = {
          name: filePath.split(/[/\\]/).pop(),
          path: filePath,
          size: (precomputed && precomputed.fileInfo && precomputed.fileInfo.size) || null,
          lastModified: (precomputed && precomputed.fileInfo && precomputed.fileInfo.modified) || null,
          status: precomputed ? 'Analyzed' : 'Ready for analysis'
        };

        // If the main handler already returned sandbox analysis, store trust score and show results immediately
        if (precomputed) {
          try {
            if (precomputed.riskAssessment && typeof precomputed.riskAssessment.trustScore === 'number') {
              file.trustScore = precomputed.riskAssessment.trustScore;
            }
          } catch (e) {}
          sandboxFiles.push(file);
          renderSandboxFilesList();
          displaySandboxResults([{ name: file.name, result: precomputed }]);
          return;
        }

        // Otherwise just add to queue for manual analysis
        sandboxFiles.push(file);
        renderSandboxFilesList();
      } catch (err) {
        console.error('Error selecting sandbox file:', err);
      }
    });
  }
}