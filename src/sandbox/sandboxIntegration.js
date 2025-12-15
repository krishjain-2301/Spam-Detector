/**
 * Enhanced sandbox handler with Windows Sandbox integration 
 */
import { BrowserWindow, ipcMain } from 'electron';
import { exec, spawn } from 'child_process';
import { tmpdir } from 'os';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

// Check if Windows Sandbox is available
async function checkWindowsSandbox() {
  if (process.platform !== 'win32') {
    throw new Error('Windows Sandbox is only available on Windows');
  }

  return new Promise((resolve, reject) => {
    exec('powershell.exe Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM"', (error, stdout) => {
      if (error) {
        reject(new Error('Failed to check Windows Sandbox status'));
        return;
      }
      const isEnabled = stdout.includes('Enabled');
      if (!isEnabled) {
        reject(new Error('Windows Sandbox feature is not enabled. Enable it in Windows Features.'));
        return;
      }
      resolve(true);
    });
  });
}

// Run a file in Windows Sandbox with monitoring
async function runInSandbox(filePath) {
  // First check if sandbox is available
  await checkWindowsSandbox();

  // Create a unique temporary directory for sandbox share
  const shareId = crypto.randomBytes(4).toString('hex');
  const shareDir = path.join(tmpdir(), `sandbox-share-${shareId}`);
  fs.mkdirSync(shareDir, { recursive: true });

  try {
    // Copy sandbox configuration and analysis script
    const sandboxPath = path.join(__dirname, 'sandbox');
    fs.copyFileSync(path.join(sandboxPath, 'sandbox-config.wsb'), path.join(shareDir, 'config.wsb'));
    fs.copyFileSync(path.join(sandboxPath, 'run-analysis.ps1'), path.join(shareDir, 'run-analysis.ps1'));
    fs.copyFileSync(filePath, path.join(shareDir, path.basename(filePath)));

    // Update sandbox config to use our share directory
    let config = fs.readFileSync(path.join(shareDir, 'config.wsb'), 'utf8');
    config = config.replace('%TEMP%\\sandbox-share', shareDir);
    fs.writeFileSync(path.join(shareDir, 'config.wsb'), config);

    // Run Windows Sandbox with monitoring
    return new Promise((resolve, reject) => {
      const sandbox = spawn('WindowsSandbox.exe', [path.join(shareDir, 'config.wsb')], {
        windowsHide: true
      });

      let resultWatcher = null;
      let cleanupTimer = null;
      let resultFound = false;

      // Watch for result file
      resultWatcher = fs.watch(shareDir, (eventType, filename) => {
        if (filename === 'result.json' && !resultFound) {
          resultFound = true;
          try {
            // Read results
            const result = JSON.parse(fs.readFileSync(path.join(shareDir, 'result.json'), 'utf8'));
            const logs = fs.existsSync(path.join(shareDir, 'execution.log')) 
              ? fs.readFileSync(path.join(shareDir, 'execution.log'), 'utf8')
              : '';

            cleanup();
            resolve({ ok: true, result, logs });
          } catch (error) {
            cleanup();
            reject(new Error(`Failed to read analysis results: ${error.message}`));
          }
        }
      });

      // Cleanup function
      const cleanup = () => {
        if (resultWatcher) resultWatcher.close();
        if (cleanupTimer) clearTimeout(cleanupTimer);
        try { sandbox.kill('SIGKILL'); } catch {}
        
        // Remove share directory after a delay
        setTimeout(() => {
          try {
            fs.rmSync(shareDir, { recursive: true, force: true });
          } catch {}
        }, 5000);
      };

      // Set timeout
      cleanupTimer = setTimeout(() => {
        if (!resultFound) {
          cleanup();
          reject(new Error('Analysis timed out after 5 minutes'));
        }
      }, 5 * 60 * 1000);

      // Handle sandbox process errors
      sandbox.on('error', (error) => {
        if (!resultFound) {
          cleanup();
          reject(new Error(`Failed to start sandbox: ${error.message}`));
        }
      });

      // Log process output for debugging
      sandbox.stdout.on('data', (data) => {
        console.log('[Sandbox] stdout:', data.toString());
      });

      sandbox.stderr.on('data', (data) => {
        console.error('[Sandbox] stderr:', data.toString());
      });
    });
  } catch (error) {
    // Clean up share directory on error
    try {
      fs.rmSync(shareDir, { recursive: true, force: true });
    } catch {}
    throw error;
  }
}

// IPC handler for sandbox analysis requests
ipcMain.handle('analyze-in-sandbox', async (event, filePath) => {
  try {
    // Basic validation
    if (!filePath || !fs.existsSync(filePath)) {
      throw new Error('File not found');
    }

    // First perform static analysis using existing code
    const staticAnalysis = await window.electronAPI.runFileSandboxed(filePath);

    // Then run in Windows Sandbox for dynamic analysis
    const sandboxResult = await runInSandbox(filePath);

    // Combine static and dynamic analysis results
    return {
      ok: true,
      staticAnalysis,
      dynamicAnalysis: sandboxResult.result,
      logs: sandboxResult.logs
    };

  } catch (error) {
    return {
      ok: false,
      error: error.message
    };
  }
});

// Export functions for use by other modules
export default {
  checkWindowsSandbox,
  runInSandbox
};