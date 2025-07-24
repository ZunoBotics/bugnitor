import { SecurityFinding } from './types';

export interface DangerousAPIPattern {
  id: string;
  name: string;
  category: string;
  description: string;
  patterns: RegExp[];
  contextPatterns?: RegExp[];
  excludePatterns?: RegExp[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  fileTypes: string[];
  cwe: string;
  owasp: string;
  impact: string;
  remediation: {
    description: string;
    effort: 'low' | 'medium' | 'high';
    codeExample?: string;
  };
}

export const dangerousAPIPatterns: DangerousAPIPattern[] = [
  {
    id: 'eval-usage',
    name: 'Dynamic Code Execution via eval()',
    category: 'Code Injection',
    description: 'Use of eval() function which can execute arbitrary code',
    patterns: [
      /\beval\s*\(/gi,
      /new\s+Function\s*\(/gi,
      /setTimeout\s*\(\s*['"`][^'"`]*['"`]\s*,/gi,
      /setInterval\s*\(\s*['"`][^'"`]*['"`]\s*,/gi
    ],
    contextPatterns: [
      /user|input|request|params|query|body/gi
    ],
    excludePatterns: [
      /test|spec|mock|example/gi
    ],
    severity: 'critical',
    confidence: 0.9,
    fileTypes: ['js', 'ts', 'jsx', 'tsx'],
    cwe: 'CWE-94',
    owasp: 'A03:2021 – Injection',
    impact: 'Arbitrary code execution, complete application compromise',
    remediation: {
      description: 'Replace eval() with safe alternatives like JSON.parse() for data parsing',
      effort: 'medium',
      codeExample: `// Instead of:
eval("(" + userInput + ")");

// Use:
JSON.parse(userInput);`
    }
  },
  {
    id: 'child-process-exec',
    name: 'Command Execution via child_process',
    category: 'Command Injection',
    description: 'Use of child_process.exec() which can execute system commands',
    patterns: [
      /child_process\.exec\s*\(/gi,
      /exec\s*\(/gi,
      /spawn\s*\(/gi,
      /execSync\s*\(/gi,
      /spawnSync\s*\(/gi
    ],
    contextPatterns: [
      /user|input|request|params|query|body/gi
    ],
    severity: 'critical',
    confidence: 0.95,
    fileTypes: ['js', 'ts'],
    cwe: 'CWE-78',
    owasp: 'A03:2021 – Injection',
    impact: 'Command injection, system compromise',
    remediation: {
      description: 'Use safer alternatives with proper input validation and sanitization',
      effort: 'high',
      codeExample: `// Instead of:
exec(\`ls \${userInput}\`);

// Use:
const { spawn } = require('child_process');
spawn('ls', [sanitizedInput]);`
    }
  },
  {
    id: 'fs-user-input',
    name: 'File System Access with User Input',
    category: 'Path Traversal',
    description: 'Direct file system operations with user-controlled paths',
    patterns: [
      /fs\.readFile\s*\([^,)]*req\./gi,
      /fs\.writeFile\s*\([^,)]*req\./gi,
      /fs\.readFileSync\s*\([^,)]*req\./gi,
      /fs\.writeFileSync\s*\([^,)]*req\./gi,
      /fs\.unlink\s*\([^,)]*req\./gi,
      /fs\.access\s*\([^,)]*req\./gi
    ],
    severity: 'high',
    confidence: 0.9,
    fileTypes: ['js', 'ts'],
    cwe: 'CWE-22',
    owasp: 'A01:2021 – Broken Access Control',
    impact: 'Unauthorized file access, path traversal attacks',
    remediation: {
      description: 'Validate and sanitize file paths, use path.resolve() and whitelist allowed directories',
      effort: 'medium',
      codeExample: `// Instead of:
fs.readFile(req.params.filename);

// Use:
const path = require('path');
const safePath = path.resolve('./uploads', path.basename(req.params.filename));
if (!safePath.startsWith('./uploads')) throw new Error('Invalid path');
fs.readFile(safePath);`
    }
  },
  {
    id: 'vm-module-usage',
    name: 'VM Module Code Execution',
    category: 'Code Injection',
    description: 'Use of vm module for dynamic code execution',
    patterns: [
      /vm\.runInNewContext\s*\(/gi,
      /vm\.runInThisContext\s*\(/gi,
      /vm\.createScript\s*\(/gi,
      /vm\.Script\s*\(/gi
    ],
    contextPatterns: [
      /user|input|request|params|query|body/gi
    ],
    severity: 'critical',
    confidence: 0.9,
    fileTypes: ['js', 'ts'],
    cwe: 'CWE-94',
    owasp: 'A03:2021 – Injection',
    impact: 'Sandbox escape, arbitrary code execution',
    remediation: {
      description: 'Avoid vm module with user input. Use safer sandboxing solutions or validate input strictly',
      effort: 'high'
    }
  },
  {
    id: 'require-dynamic',
    name: 'Dynamic Module Loading',
    category: 'Code Injection',
    description: 'Dynamic require() calls that can load arbitrary modules',
    patterns: [
      /require\s*\([^)]*\+[^)]*\)/gi,
      /require\s*\([^)]*\$\{[^}]*\}[^)]*\)/gi,
      /require\s*\([^)]*req\./gi,
      /import\s*\([^)]*req\./gi
    ],
    severity: 'high',
    confidence: 0.8,
    fileTypes: ['js', 'ts'],
    cwe: 'CWE-829',
    owasp: 'A06:2021 – Vulnerable and Outdated Components',
    impact: 'Arbitrary module loading, code injection',
    remediation: {
      description: 'Use static require() statements or validate module names against a whitelist',
      effort: 'medium'
    }
  },
  {
    id: 'python-exec-eval',
    name: 'Python Code Execution Functions',
    category: 'Code Injection',
    description: 'Use of exec() or eval() in Python which can execute arbitrary code',
    patterns: [
      /\bexec\s*\(/gi,
      /\beval\s*\(/gi,
      /compile\s*\([^,)]*request\./gi,
      /__import__\s*\([^)]*request\./gi
    ],
    contextPatterns: [
      /request|user|input|form/gi
    ],
    severity: 'critical',
    confidence: 0.95,
    fileTypes: ['py'],
    cwe: 'CWE-94',
    owasp: 'A03:2021 – Injection',
    impact: 'Arbitrary Python code execution',
    remediation: {
      description: 'Use safe alternatives like ast.literal_eval() for data parsing',
      effort: 'medium',
      codeExample: `# Instead of:
exec(user_input)

# Use:
import ast
ast.literal_eval(user_input)  # Only for literals`
    }
  },
  {
    id: 'subprocess-shell-true',
    name: 'Subprocess with Shell Execution',
    category: 'Command Injection',
    description: 'Use of subprocess with shell=True which can lead to command injection',
    patterns: [
      /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/gi,
      /os\.system\s*\(/gi,
      /os\.popen\s*\(/gi
    ],
    contextPatterns: [
      /request|user|input|form/gi
    ],
    severity: 'critical',
    confidence: 0.9,
    fileTypes: ['py'],
    cwe: 'CWE-78',
    owasp: 'A03:2021 – Injection',
    impact: 'Command injection, system compromise',
    remediation: {
      description: 'Use subprocess without shell=True and pass arguments as a list',
      effort: 'medium',
      codeExample: `# Instead of:
subprocess.call(f"ls {user_input}", shell=True)

# Use:
subprocess.call(["ls", user_input])`
    }
  },
  {
    id: 'pickle-unsafe',
    name: 'Unsafe Pickle Deserialization',
    category: 'Insecure Deserialization',
    description: 'Use of pickle.loads() which can execute arbitrary code during deserialization',
    patterns: [
      /pickle\.loads?\s*\(/gi,
      /cPickle\.loads?\s*\(/gi,
      /pickle\.Unpickler\s*\(/gi
    ],
    contextPatterns: [
      /request|user|input|form|file/gi
    ],
    severity: 'critical',
    confidence: 0.95,
    fileTypes: ['py'],
    cwe: 'CWE-502',
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    impact: 'Arbitrary code execution during deserialization',
    remediation: {
      description: 'Use safe serialization formats like JSON or implement custom serialization',
      effort: 'high',
      codeExample: `# Instead of:
pickle.loads(user_data)

# Use:
import json
json.loads(user_data)  # Only for trusted data`
    }
  },
  {
    id: 'yaml-unsafe-load',
    name: 'Unsafe YAML Loading',
    category: 'Insecure Deserialization',
    description: 'Use of yaml.load() without safe loader which can execute arbitrary code',
    patterns: [
      /yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/gi,
      /yaml\.load_all\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/gi
    ],
    severity: 'high',
    confidence: 0.9,
    fileTypes: ['py'],
    cwe: 'CWE-502',
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    impact: 'Code execution via YAML deserialization',
    remediation: {
      description: 'Use yaml.safe_load() instead of yaml.load()',
      effort: 'low',
      codeExample: `# Instead of:
yaml.load(user_input)

# Use:
yaml.safe_load(user_input)`
    }
  },
  {
    id: 'reflected-xss-node',
    name: 'Reflected XSS in Node.js',
    category: 'Cross-Site Scripting',
    description: 'Direct output of user input without encoding',
    patterns: [
      /res\.send\s*\([^)]*req\.(params|query|body)/gi,
      /res\.write\s*\([^)]*req\.(params|query|body)/gi,
      /response\.write\s*\([^)]*request\./gi
    ],
    severity: 'high',
    confidence: 0.8,
    fileTypes: ['js', 'ts'],
    cwe: 'CWE-79',
    owasp: 'A03:2021 – Injection',
    impact: 'Cross-site scripting attacks, session hijacking',
    remediation: {
      description: 'Encode output and use templating engines with auto-escaping',
      effort: 'low',
      codeExample: `// Instead of:
res.send(req.params.name);

// Use:
const escapeHtml = require('escape-html');
res.send(escapeHtml(req.params.name));`
    }
  }
];

export class DangerousAPIDetector {
  detectDangerousAPIs(content: string, filename: string): Array<{
    pattern: DangerousAPIPattern;
    matches: Array<{
      match: RegExpMatchArray;
      confidence: number;
      context: string;
    }>;
  }> {
    const fileExtension = filename.split('.').pop()?.toLowerCase();
    if (!fileExtension) return [];

    const results: Array<{
      pattern: DangerousAPIPattern;
      matches: Array<{
        match: RegExpMatchArray;
        confidence: number;
        context: string;
      }>;
    }> = [];

    for (const pattern of dangerousAPIPatterns) {
      if (!pattern.fileTypes.includes(fileExtension)) continue;

      const matches: Array<{
        match: RegExpMatchArray;
        confidence: number;
        context: string;
      }> = [];

      for (const regex of pattern.patterns) {
        let match;
        while ((match = regex.exec(content)) !== null) {
          const context = this.getMatchContext(content, match.index || 0);
          const confidence = this.calculateConfidence(pattern, match, context, filename);
          
          // Skip low confidence matches
          if (confidence < 0.5) continue;

          matches.push({
            match,
            confidence,
            context
          });
          
          if (!regex.global) break;
        }
        regex.lastIndex = 0;
      }

      if (matches.length > 0) {
        results.push({ pattern, matches });
      }
    }

    return results;
  }

  private getMatchContext(content: string, index: number, contextSize: number = 150): string {
    const start = Math.max(0, index - contextSize);
    const end = Math.min(content.length, index + contextSize);
    return content.substring(start, end);
  }

  private calculateConfidence(
    pattern: DangerousAPIPattern,
    match: RegExpMatchArray,
    context: string,
    filename: string
  ): number {
    let confidence = pattern.confidence;

    // File type adjustments
    if (filename.includes('test') || filename.includes('spec') || filename.includes('mock')) {
      confidence *= 0.6;
    }
    if (filename.includes('example') || filename.includes('demo') || filename.includes('sample')) {
      confidence *= 0.5;
    }

    // Context pattern matching
    if (pattern.contextPatterns) {
      let hasContext = false;
      for (const contextPattern of pattern.contextPatterns) {
        if (contextPattern.test(context)) {
          hasContext = true;
          confidence *= 1.2;
          break;
        }
      }
      if (!hasContext) {
        confidence *= 0.7;
      }
    }

    // Exclude pattern matching
    if (pattern.excludePatterns) {
      for (const excludePattern of pattern.excludePatterns) {
        if (excludePattern.test(match[0]) || excludePattern.test(context)) {
          confidence *= 0.4;
          break;
        }
      }
    }

    // Check for security-focused contexts
    const securityContexts = [
      /sanitize|validate|escape|encode/gi,
      /security|auth|permission/gi
    ];

    for (const securityContext of securityContexts) {
      if (securityContext.test(context)) {
        confidence *= 0.8;
        break;
      }
    }

    return Math.min(1.0, Math.max(0.0, confidence));
  }
}