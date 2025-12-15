import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

// Run a file in a sandboxed environment with enhanced analysis
export function runFileSandboxed(filePath, callback) {
    if (!fs.existsSync(filePath)) {
        callback({ ok: false, error: 'File does not exist' });
        return;
    }

    const ext = path.extname(filePath).toLowerCase();
    try {
        // Read file metadata
        const stats = fs.statSync(filePath);
        const fileInfo = {
            size: stats.size,
            created: stats.birthtime,
            modified: stats.mtime,
            permissions: stats.mode,
            extension: ext,
            fileName: path.basename(filePath)
        };

        // Read first 4KB to detect file type
        const buffer = Buffer.alloc(4096);
        const fd = fs.openSync(filePath, 'r');
        fs.readSync(fd, buffer, 0, 4096, 0);
        fs.closeSync(fd);

        // Detect file type
        const fileType = detectFileType(buffer);
        
        // For text files, analyze content
        if (isTextFile(ext)) {
            const content = fs.readFileSync(filePath, 'utf8');
            analyzeTextContent(content, fileInfo, fileType, callback);
        } else {
            // For binary files, analyze metadata and structure
            analyzeBinaryFile(filePath, fileInfo, fileType, callback);
        }
    } catch (error) {
        callback({
            ok: false,
            error: 'Error analyzing file: ' + error.message,
            fileInfo: {
                extension: ext
            }
        });
    }
}
function detectFileType(buffer) {
    const signatures = {
        // Executables and Binaries
        '4d5a': 'Windows Executable (EXE/DLL)',
        '7f454c46': 'Linux Executable (ELF)',
        'cafebabe': 'Java Class File',
        'feedface': 'Mach-O Binary (Old)',
        'feedfacf': 'Mach-O Binary (64-bit)',
        'cefaedfe': 'Mach-O Binary (Reverse)',
        'feca0deb': '.NET Assembly',
        
        // Archives and Installers
        '504b0304': 'ZIP Archive/Java JAR/Android APK',
        '526172': 'RAR Archive',
        '377abcaf271c': '7-Zip Archive',
        '1f8b08': 'GZIP Archive',
        '425a68': 'BZIP2 Archive',
        '4d534346': 'Microsoft CAB',
        '53495421': 'Windows Installer (MSI)',
        
        // Documents
        '25504446': 'PDF Document',
        'd0cf11e0': 'Microsoft Office Document (Legacy)',
        '504b0304': 'Microsoft Office Document (Modern)',
        '0000020006': 'Windows Shortcut (LNK)',
        
        // Media
        'ffd8ff': 'JPEG Image',
        '89504e47': 'PNG Image',
        '47494638': 'GIF Image',
        '424d': 'BMP Image',
        '49443304': 'MP3 Audio',
        '52494646': 'WAV/AVI Media',
        '000001ba': 'MPEG Video',
        '1a45dfa3': 'MKV Video',
        
        // Scripts and Code
        '23212f': 'Shell Script (#!)',
        '3c3f786d6c': 'XML Document',
        '696d706f7274': 'Python Source',
        '7061636b616765': 'Java Source',
        '235468697320': 'Perl Script',
        '3c68746d6c': 'HTML Document',
        '2f2f': 'C/C++/JavaScript Source',
        '7573652073': 'Ruby Script'
    };

    // Check for text files with BOM
    if (buffer.slice(0, 3).toString('hex') === 'efbbbf') return 'UTF-8 Text with BOM';
    if (buffer.slice(0, 2).toString('hex') === 'fffe') return 'UTF-16 (LE) Text';
    if (buffer.slice(0, 2).toString('hex') === 'feff') return 'UTF-16 (BE) Text';

    // Check for shebang scripts
    const possibleShebang = buffer.slice(0, 20).toString();
    if (possibleShebang.startsWith('#!')) {
        if (possibleShebang.includes('node')) return 'Node.js Script';
        if (possibleShebang.includes('python')) return 'Python Script';
        if (possibleShebang.includes('ruby')) return 'Ruby Script';
        if (possibleShebang.includes('perl')) return 'Perl Script';
        if (possibleShebang.includes('php')) return 'PHP Script';
        return 'Shell Script';
    }

    // Check file signatures
    for (const [sig, type] of Object.entries(signatures)) {
        if (buffer.slice(0, sig.length / 2).toString('hex') === sig) {
            return type;
        }
    }

    // Check for UTF-8 text
    try {
        const sample = buffer.slice(0, 1024).toString('utf8');
        // If we can decode as UTF-8 and it contains mostly printable characters
        if (sample.split('').filter(c => c.charCodeAt(0) >= 32).length > sample.length * 0.9) {
            return 'Text File';
        }
    } catch {}

    return 'Unknown Binary';
}

function isTextFile(ext) {
    const textExtensions = [
        // Web files
        '.html', '.css', '.js', '.jsx', '.ts', '.tsx', '.json', '.xml', '.svg',
        // Programming languages
        '.py', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.go', '.rs', '.rb', '.php',
        '.scala', '.kt', '.kts', '.swift', '.m', '.mm', '.r', '.pl', '.sh', '.ps1',
        // Config files
        '.ini', '.conf', '.cfg', '.yaml', '.yml', '.toml', '.env',
        // Documentation
        '.txt', '.md', '.rst', '.log', '.csv', '.tsv',
        // Other text formats
        '.sql', '.graphql', '.proto', '.bat', '.cmd', '.vbs'
    ];
    return textExtensions.includes(ext.toLowerCase());
}

function analyzeTextContent(content, fileInfo, fileType, callback) {
    const analysis = {
        ok: true,
        fileInfo,
        fileType,
        contentAnalysis: {
            length: content.length,
            lines: content.split('\n').length,
            containsScripts: /\<script\>|\beval\(|function\s*\(|require\(/.test(content),
            containsUrls: content.match(/https?:\/\/[^\s]+/g) || [],
            containsBase64: /[A-Za-z0-9+/]{64,}/.test(content),
            containsShellCommands: /\bexec\(|\bshell\b|\bcmd\b|\bpowershell\b/.test(content),
            suspiciousPatterns: detectSuspiciousPatterns(content)
        },
        riskAssessment: {
            riskLevel: 'low',
            warnings: [],
            recommendations: []
        }
    };

    // Assess risks
    assessTextRisks(analysis);

    // Calculate a trust score (0-100) for text-based files so every analysis returns a score
    try {
        analysis.riskAssessment.trustScore = calculateTextTrustScore(analysis.contentAnalysis, analysis.riskAssessment);
        // Normalize riskLevel based on trust score if needed
        const ts = analysis.riskAssessment.trustScore;
        if (typeof ts === 'number') {
            if (ts >= 75) analysis.riskAssessment.riskLevel = 'low';
            else if (ts >= 40) analysis.riskAssessment.riskLevel = 'medium';
            else analysis.riskAssessment.riskLevel = 'high';
        }
    } catch (e) {
        // if scoring fails, leave riskAssessment as-is
        analysis.riskAssessment.trustScore = null;
    }

    callback(analysis);
}

// Heuristic trust score for text files
function calculateTextTrustScore(contentAnalysis, riskAssessment) {
    // Start from 100 (most trusted) and subtract penalties
    let score = 100;

    // Penalties (tunable)
    if (contentAnalysis.containsScripts) score -= 25;
    if (contentAnalysis.containsShellCommands) score -= 25;
    if (contentAnalysis.containsBase64) score -= 15;

    // URLs are suspicious; each URL reduces score but cap impact
    const urlCount = Array.isArray(contentAnalysis.containsUrls) ? contentAnalysis.containsUrls.length : 0;
    score -= Math.min(30, urlCount * 10);

    // Suspicious pattern hits
    const suspiciousCount = Object.values(contentAnalysis.suspiciousPatterns || {}).reduce((a,b)=>a+(b||0),0);
    score -= Math.min(40, suspiciousCount * 8);

    // Large files increase risk modestly
    if (contentAnalysis.lines > 500) score -= 10;
    if (contentAnalysis.length > 20000) score -= 10;

    // If there are explicit warnings recorded, penalize further
    if (Array.isArray(riskAssessment.warnings) && riskAssessment.warnings.length > 0) {
        score -= Math.min(20, riskAssessment.warnings.length * 5);
    }

    // Clamp and return integer
    score = Math.max(0, Math.min(100, Math.round(score)));
    return score;
}

function analyzeBinaryFile(filePath, fileInfo, fileType, callback) {
    const analysis = {
        ok: true,
        fileInfo,
        fileType,
        binaryAnalysis: {
            // Basic properties
            isExecutable: /\.(exe|dll|sys|so|dylib|bat|cmd|sh|ps1)$/i.test(filePath),
            isPotentiallyHarmful: isPotentiallyHarmfulFile(filePath),
            signatures: checkFileSignatures(filePath),
            
            // Enhanced analysis
            format: detectBinaryFormat(filePath),
            dependencies: detectDependencies(filePath),
            capabilities: detectCapabilities(filePath),
            entropy: calculateFileEntropy(filePath),
            strings: extractSuspiciousStrings(filePath),
            resources: analyzeEmbeddedResources(filePath),
            permissions: checkFilePermissions(filePath)
        },
        riskAssessment: {
            riskLevel: 'medium',
            warnings: [],
            recommendations: [],
            trustScore: 0
        }
    };

    // Deep binary analysis
    deepAnalyzeBinary(analysis);
    
    // Calculate trust score
    analysis.riskAssessment.trustScore = calculateTrustScore(analysis);

    callback(analysis);
}

function detectSuspiciousPatterns(content) {
    const patterns = {
        systemCommands: /\b(system|exec|spawn|shell|cmd|powershell)\b/g,
        networkAccess: /\b(http|socket|request|fetch|curl|wget)\b/g,
        fileOperations: /\b(writeFile|readFile|unlink|rmdir|chmod)\b/g,
        encryption: /\b(crypto|cipher|encrypt|decrypt)\b/g,
        eval: /\b(eval|Function|setTimeout|setInterval)\(/g,
        base64: /\b(atob|btoa|base64)\b/g
    };

    const found = {};
    for (const [key, pattern] of Object.entries(patterns)) {
        const matches = content.match(pattern);
        if (matches) found[key] = matches.length;
    }
    return found;
}

function assessTextRisks(analysis) {
    const { contentAnalysis } = analysis;
    const warnings = analysis.riskAssessment.warnings;
    const recommendations = analysis.riskAssessment.recommendations;

    if (contentAnalysis.containsScripts) {
        warnings.push('File contains script code that could be executed');
        recommendations.push('Review script code carefully before execution');
    }

    if (contentAnalysis.containsUrls.length > 0) {
        warnings.push(`File contains ${contentAnalysis.containsUrls.length} URLs`);
        recommendations.push('Verify all URLs are trusted sources');
    }

    if (contentAnalysis.containsBase64) {
        warnings.push('File contains Base64 encoded content');
        recommendations.push('Decode and inspect Base64 content before proceeding');
    }

    if (contentAnalysis.containsShellCommands) {
        warnings.push('File contains shell commands');
        recommendations.push('Review shell commands for potential system risks');
    }

    let riskLevel = 'low';
    if (warnings.length > 3) riskLevel = 'high';
    else if (warnings.length > 1) riskLevel = 'medium';

    analysis.riskAssessment.riskLevel = riskLevel;
}

function assessBinaryRisks(analysis) {
    const { binaryAnalysis } = analysis;
    const warnings = analysis.riskAssessment.warnings;
    const recommendations = analysis.riskAssessment.recommendations;

    if (binaryAnalysis.isExecutable) {
        warnings.push('File is executable and could modify system');
        recommendations.push('Run only in isolated environment');
    }

    if (binaryAnalysis.isPotentiallyHarmful) {
        warnings.push('File type is potentially harmful');
        recommendations.push('Exercise extreme caution with this file type');
    }

    if (!binaryAnalysis.signatures.isSigned) {
        warnings.push('File is not digitally signed');
        recommendations.push('Verify file source before execution');
    }

    let riskLevel = 'medium';
    if (binaryAnalysis.isExecutable || binaryAnalysis.isPotentiallyHarmful) riskLevel = 'high';
    
    analysis.riskAssessment.riskLevel = riskLevel;
}

function isPotentiallyHarmfulFile(filePath) {
    const riskCategories = {
        highRisk: [
            '.exe', '.dll', '.sys', '.ocx', '.drv',  // Windows executables
            '.dmg', '.pkg', '.app',                  // macOS packages
            '.so', '.dylib',                         // Unix shared libraries
            '.msi', '.msp', '.msix',                // Windows installers
            '.bat', '.cmd', '.ps1', '.vbs',         // Windows scripts
            '.sh', '.bash', '.ksh', '.zsh',         // Unix scripts
            '.jar', '.war', '.jnlp',                // Java executables
            '.pyc', '.pyo', '.pyd',                 // Python compiled
            '.apk', '.dex',                         // Android
            '.ipa',                                 // iOS
            '.crx', '.xpi',                        // Browser extensions
        ],
        mediumRisk: [
            '.py', '.rb', '.pl', '.php',           // Scripting languages
            '.js', '.jsx', '.ts', '.tsx',          // JavaScript/TypeScript
            '.class', '.java',                     // Java source
            '.reg', '.inf',                        // Windows registry/setup
            '.app', '.gadget',                     // Applications
            '.action', '.workflow',                // Automation
        ],
        lowRisk: [
            '.html', '.htm', '.css',               // Web files
            '.txt', '.log', '.csv',                // Text files
            '.json', '.xml', '.yaml', '.yml',      // Data files
            '.md', '.rst', '.doc', '.docx',        // Documents
            '.jpg', '.png', '.gif', '.svg',        // Images
            '.mp3', '.wav', '.mp4', '.avi',        // Media
        ]
    };

    const ext = path.extname(filePath).toLowerCase();
    
    if (riskCategories.highRisk.includes(ext)) return 'high';
    if (riskCategories.mediumRisk.includes(ext)) return 'medium';
    if (riskCategories.lowRisk.includes(ext)) return 'low';
    
    // Unknown extension - treat as medium risk
    return 'medium';
}

// Advanced binary analysis functions
function detectBinaryFormat(filePath) {
    try {
        const buffer = Buffer.alloc(4096);
        const fd = fs.openSync(filePath, 'r');
        fs.readSync(fd, buffer, 0, 4096, 0);
        fs.closeSync(fd);

        const format = {
            architecture: 'unknown',
            bitness: 'unknown',
            format: 'unknown',
            compiler: 'unknown'
        };

        // Detect PE (Windows) executables
        if (buffer.slice(0, 2).toString('hex') === '4d5a') {
            format.format = 'PE';
            // Read PE header offset
            const peOffset = buffer.readUInt32LE(0x3c);
            if (peOffset < buffer.length - 4) {
                const peHeader = buffer.slice(peOffset);
                if (peHeader.slice(0, 4).toString('hex') === '50450000') {
                    const machine = peHeader.readUInt16LE(4);
                    format.architecture = machine === 0x8664 ? 'x64' : 
                                       machine === 0x014c ? 'x86' : 
                                       machine === 0x0200 ? 'IA64' : 'unknown';
                    format.bitness = machine === 0x8664 || machine === 0x0200 ? '64-bit' : '32-bit';
                }
            }
        }
        // Detect ELF (Linux) executables
        else if (buffer.slice(0, 4).toString('hex') === '7f454c46') {
            format.format = 'ELF';
            const class_ = buffer[4];
            format.bitness = class_ === 1 ? '32-bit' : class_ === 2 ? '64-bit' : 'unknown';
            const machine = buffer[0x12];
            format.architecture = machine === 0x3e ? 'x86_64' :
                               machine === 0x03 ? 'x86' :
                               machine === 0xb7 ? 'ARM' :
                               machine === 0xf3 ? 'RISC-V' : 'unknown';
        }
        // Detect Mach-O (macOS) executables
        else if (['feedface', 'feedfacf', 'cefaedfe', 'cffaedfe'].includes(buffer.slice(0, 4).toString('hex'))) {
            format.format = 'Mach-O';
            format.bitness = buffer.slice(0, 4).toString('hex').includes('f') ? '64-bit' : '32-bit';
            const cpuType = buffer.readUInt32LE(4);
            format.architecture = cpuType === 0x7 ? 'x86' :
                               cpuType === 0x01000007 ? 'x86_64' :
                               cpuType === 0x0c ? 'ARM' :
                               cpuType === 0x0100000c ? 'ARM64' : 'unknown';
        }

        return format;
    } catch (error) {
        return { error: 'Format detection failed: ' + error.message };
    }
}

function detectDependencies(filePath) {
    const deps = {
        libraries: [],
        frameworks: [],
        runtimeDependencies: []
    };

    try {
        const ext = path.extname(filePath).toLowerCase();
        const content = fs.readFileSync(filePath);

        // Check for DLL dependencies in PE files
        if (ext === '.exe' || ext === '.dll') {
            const dllPattern = /([a-zA-Z0-9_-]+\.(dll|ocx|sys))/gi;
            const matches = content.toString('utf8').match(dllPattern) || [];
            deps.libraries.push(...new Set(matches));
        }
        
        // Check for shared library dependencies in ELF files
        if (content.slice(0, 4).toString('hex') === '7f454c46') {
            const soPattern = /lib[a-zA-Z0-9_-]+\.so(\.[0-9]+)?/g;
            const matches = content.toString('utf8').match(soPattern) || [];
            deps.libraries.push(...new Set(matches));
        }

        // Check for framework dependencies
        const frameworkPatterns = {
            '.net': /\.(NET|System\.|Microsoft\.)/i,
            'java': /^(java|javax|org\.springframework)/m,
            'python': /^(import|from)\s+[a-zA-Z0-9_.]+/m,
            'node': /require\(['"][@a-zA-Z0-9-/]+['"]\)|import\s+.*\s+from/
        };

        for (const [framework, pattern] of Object.entries(frameworkPatterns)) {
            if (pattern.test(content.toString('utf8'))) {
                deps.frameworks.push(framework);
            }
        }

    } catch (error) {
        deps.error = 'Dependency detection failed: ' + error.message;
    }

    return deps;
}

function detectCapabilities(filePath) {
    const capabilities = {
        networkAccess: false,
        fileSystemAccess: false,
        systemCommands: false,
        browserAccess: false,
        databaseAccess: false,
        systemServices: false
    };

    try {
        const content = fs.readFileSync(filePath, 'utf8');
        
        // Network patterns
        capabilities.networkAccess = /socket|http|ftp|tcp|udp|dns|network|url|download|upload/i.test(content);
        
        // File system patterns
        capabilities.fileSystemAccess = /file|directory|folder|path|read|write|delete|create|copy|move/i.test(content);
        
        // System command patterns
        capabilities.systemCommands = /exec|spawn|system|cmd|shell|powershell|bash|sudo/i.test(content);
        
        // Browser access patterns
        capabilities.browserAccess = /window\.|document\.|navigator\.|location\.|chrome\.|browser\./i.test(content);
        
        // Database patterns
        capabilities.databaseAccess = /sql|database|mongo|redis|oracle|mysql|postgresql/i.test(content);
        
        // System service patterns
        capabilities.systemServices = /service|daemon|registry|regedit|systemctl|launchd/i.test(content);

    } catch {
        // If we can't read as text, it's likely a binary
        // Attempt basic capability detection from binary patterns
        try {
            const buffer = fs.readFileSync(filePath);
            const str = buffer.toString('utf8');
            capabilities.networkAccess = /socket|http|tcp|udp/i.test(str);
            capabilities.fileSystemAccess = /file|directory|path/i.test(str);
            capabilities.systemCommands = /exec|system|cmd|shell/i.test(str);
        } catch (error) {
            capabilities.error = 'Capability detection failed: ' + error.message;
        }
    }

    return capabilities;
}

function calculateFileEntropy(filePath) {
    try {
        const buffer = fs.readFileSync(filePath);
        const byteFrequency = new Array(256).fill(0);
        
        // Count frequency of each byte value
        for (const byte of buffer) {
            byteFrequency[byte]++;
        }
        
        // Calculate entropy
        let entropy = 0;
        const fileSize = buffer.length;
        
        for (const frequency of byteFrequency) {
            if (frequency === 0) continue;
            const probability = frequency / fileSize;
            entropy -= probability * Math.log2(probability);
        }
        
        return {
            entropy: entropy,
            // High entropy (>7.0) often indicates encryption or compression
            isEncrypted: entropy > 7.0,
            isCompressed: entropy > 6.5,
            score: Math.min(10, entropy)
        };
    } catch (error) {
        return { error: 'Entropy calculation failed: ' + error.message };
    }
}

function extractSuspiciousStrings(filePath) {
    try {
        const buffer = fs.readFileSync(filePath);
        const strings = {
            urls: [],
            emails: [],
            ipAddresses: [],
            suspiciousPatterns: [],
            base64Strings: []
        };

        // Convert buffer to string, handling both text and binary files
        let content = buffer.toString('utf8');
        
        // Extract URLs
        const urlPattern = /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/g;
        strings.urls = [...new Set(content.match(urlPattern) || [])];
        
        // Extract email addresses
        const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        strings.emails = [...new Set(content.match(emailPattern) || [])];
        
        // Extract IP addresses
        const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
        strings.ipAddresses = [...new Set(content.match(ipPattern) || [])];
        
        // Check for suspicious patterns
        const suspiciousPatterns = [
            /password|passwd|pwd|credentials/i,
            /backdoor|exploit|hack|malware|virus/i,
            /admin|root|sudo|system32/i,
            /\\x[0-9a-f]{2}|%[0-9a-f]{2}/i
        ];
        
        for (const pattern of suspiciousPatterns) {
            const matches = content.match(pattern);
            if (matches) strings.suspiciousPatterns.push(...matches);
        }
        
        // Look for Base64 strings
        const base64Pattern = /[A-Za-z0-9+/]{40,}={0,3}/g;
        strings.base64Strings = [...new Set(content.match(base64Pattern) || [])];

        return strings;
    } catch (error) {
        return { error: 'String extraction failed: ' + error.message };
    }
}

function analyzeEmbeddedResources(filePath) {
    const resources = {
        images: [],
        icons: [],
        strings: [],
        signatures: [],
        overlays: [],
        certificates: []
    };

    try {
        const buffer = fs.readFileSync(filePath);
        
        // Check for PE resources
        if (buffer.slice(0, 2).toString('hex') === '4d5a') {
            // Scan for image headers
            const pngPattern = Buffer.from([0x89, 0x50, 0x4E, 0x47]);
            const jpegPattern = Buffer.from([0xFF, 0xD8, 0xFF]);
            const icoPattern = Buffer.from([0x00, 0x00, 0x01, 0x00]);
            
            let offset = 0;
            while (offset < buffer.length) {
                if (buffer.slice(offset, offset + 4).equals(pngPattern)) {
                    resources.images.push({ type: 'PNG', offset });
                }
                if (buffer.slice(offset, offset + 3).equals(jpegPattern)) {
                    resources.images.push({ type: 'JPEG', offset });
                }
                if (buffer.slice(offset, offset + 4).equals(icoPattern)) {
                    resources.icons.push({ offset });
                }
                offset++;
            }
            
            // Look for digital signatures
            const certPattern = Buffer.from([0x30, 0x82]);
            offset = 0;
            while (offset < buffer.length - 2) {
                if (buffer.slice(offset, offset + 2).equals(certPattern)) {
                    resources.certificates.push({ offset });
                }
                offset++;
            }
        }
        
        return resources;
    } catch (error) {
        return { error: 'Resource analysis failed: ' + error.message };
    }
}

function checkFilePermissions(filePath) {
    try {
        const stats = fs.statSync(filePath);
        return {
            mode: stats.mode,
            uid: stats.uid,
            gid: stats.gid,
            isExecutable: !!(stats.mode & 0o111),
            isWritable: !!(stats.mode & 0o222),
            isReadable: !!(stats.mode & 0o444),
            permissions: {
                user: {
                    read: !!(stats.mode & 0o400),
                    write: !!(stats.mode & 0o200),
                    execute: !!(stats.mode & 0o100)
                },
                group: {
                    read: !!(stats.mode & 0o040),
                    write: !!(stats.mode & 0o020),
                    execute: !!(stats.mode & 0o010)
                },
                others: {
                    read: !!(stats.mode & 0o004),
                    write: !!(stats.mode & 0o002),
                    execute: !!(stats.mode & 0o001)
                }
            }
        };
    } catch (error) {
        return { error: 'Permission check failed: ' + error.message };
    }
}

function deepAnalyzeBinary(analysis) {
    const warnings = analysis.riskAssessment.warnings;
    const recommendations = analysis.riskAssessment.recommendations;
    const binary = analysis.binaryAnalysis;

    // Check format risks
    if (binary.format.bitness === 'unknown') {
        warnings.push('Unable to determine binary architecture');
        recommendations.push('Verify binary compatibility with your system');
    }

    // Check capabilities
    if (binary.capabilities.systemCommands) {
        warnings.push('File can execute system commands');
        recommendations.push('Run in isolated environment only');
    }
    if (binary.capabilities.networkAccess) {
        warnings.push('File can access network');
        recommendations.push('Monitor network activity when running');
    }

    // Check entropy
    if (binary.entropy.isEncrypted) {
        warnings.push('File appears to be encrypted or packed');
        recommendations.push('Use virus scanner to check for malware');
    }

    // Check strings
    if (binary.strings.suspiciousPatterns.length > 0) {
        warnings.push(`Found ${binary.strings.suspiciousPatterns.length} suspicious code patterns`);
        recommendations.push('Review suspicious patterns before execution');
    }
    if (binary.strings.urls.length > 0) {
        warnings.push(`File contains ${binary.strings.urls.length} URLs`);
        recommendations.push('Verify all embedded URLs are trusted');
    }

    // Check resources
    if (binary.resources.certificates.length === 0) {
        warnings.push('File is not digitally signed');
        recommendations.push('Verify file source and integrity');
    }

    // Check permissions
    if (binary.permissions.isExecutable && binary.permissions.isWritable) {
        warnings.push('File has both execute and write permissions');
        recommendations.push('Review file permissions');
    }
}

function calculateTrustScore(analysis) {
    let score = 100;
    const binary = analysis.binaryAnalysis;

    // Format checks (-5 to -15)
    if (binary.format.bitness === 'unknown') score -= 15;
    if (!binary.format.architecture) score -= 10;
    
    // Capability penalties (-5 to -20 each)
    if (binary.capabilities.systemCommands) score -= 20;
    if (binary.capabilities.networkAccess) score -= 10;
    if (binary.capabilities.fileSystemAccess) score -= 10;
    
    // Entropy penalties (-10 to -30)
    if (binary.entropy.isEncrypted) score -= 30;
    if (binary.entropy.isCompressed) score -= 10;
    
    // String analysis penalties (-5 to -15 each)
    score -= Math.min(30, binary.strings.suspiciousPatterns.length * 5);
    score -= Math.min(20, binary.strings.urls.length * 3);
    
    // Resource checks (-10 to -20)
    if (binary.resources.certificates.length === 0) score -= 20;
    
    // Permission penalties (-5 to -15)
    if (binary.permissions.isExecutable && binary.permissions.isWritable) score -= 15;
    
    // Dependencies check (-5 to -15)
    if (binary.dependencies.libraries.length === 0) score -= 5;
    
    return Math.max(0, Math.min(100, score));
}

function checkFileSignatures(filePath) {
    try {
        const stats = fs.statSync(filePath);
        const buffer = fs.readFileSync(filePath);
        
        return {
            isSigned: false, // Placeholder for actual signature check
            signatureType: 'none',
            trusted: false,
            size: stats.size,
            created: stats.birthtime,
            modified: stats.mtime,
            hash: {
                md5: crypto.createHash('md5').update(buffer).digest('hex'),
                sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
                sha256: crypto.createHash('sha256').update(buffer).digest('hex')
            }
        };
    } catch (error) {
        return {
            isSigned: false,
            signatureType: 'none',
            trusted: false,
            error: error.message
        };
    }
}
