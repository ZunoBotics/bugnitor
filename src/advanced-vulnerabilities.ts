import { SecurityFinding } from './types';

export interface AdvancedVulnerabilityRule {
  id: string;
  name: string;
  category: string;
  type: SecurityFinding['type'];
  description: string;
  patterns: RegExp[];
  severity: SecurityFinding['severity'];
  confidence: number;
  fileTypes: string[];
  recommendation: string;
  cwe?: string;
  owasp?: string;
  impact: string;
  effort: SecurityFinding['effort'];
  contextPatterns?: {
    before?: RegExp[];
    after?: RegExp[];
  };
}

export const advancedVulnerabilityRules: AdvancedVulnerabilityRule[] = [
  // A) Injection & Syntax Attacks
  {
    id: 'sql-injection-concat',
    name: 'SQL Injection via String Concatenation',
    category: 'SQL Injection',
    type: 'injection',
    description: 'SQL query constructed using string concatenation with user input',
    patterns: [
      /(query|execute|prepare)\s*\(\s*["'`][^"'`]*\+[^"'`]*["'`]/gi,
      /(query|execute|prepare)\s*\(\s*["'`][^"'`]*\$\{[^}]*\}[^"'`]*["'`]/gi,
      /(SELECT|INSERT|UPDATE|DELETE)[^;]*\+\s*(req\.|request\.|params\.|body\.|query\.)/gi,
      /(SELECT|INSERT|UPDATE|DELETE)[^;]*\$\{[^}]*\}/gi
    ],
    severity: 'critical',
    confidence: 0.9,
    fileTypes: ['js', 'ts', 'py', 'php', 'java', 'cs', 'go'],
    recommendation: 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
    cwe: 'CWE-89',
    owasp: 'A03:2021 – Injection',
    impact: 'Complete database compromise, data theft, data manipulation',
    effort: 'medium'
  },
  {
    id: 'nosql-injection',
    name: 'NoSQL Injection',
    category: 'NoSQL Injection',
    type: 'injection',
    description: 'NoSQL query injection vulnerability',
    patterns: [
      /\$where.*req\./gi,
      /\$regex.*req\./gi,
      /find\([^)]*req\./gi,
      /aggregate\([^)]*req\./gi
    ],
    severity: 'high',
    confidence: 0.8,
    fileTypes: ['js', 'ts', 'py'],
    recommendation: 'Validate and sanitize input before using in NoSQL queries. Use query builders or ODM/ORM.',
    cwe: 'CWE-943',
    owasp: 'A03:2021 – Injection',
    impact: 'Database manipulation, unauthorized data access',
    effort: 'medium'
  },
  {
    id: 'xss-dom',
    name: 'DOM-based Cross-Site Scripting',
    category: 'Cross-Site Scripting',
    type: 'injection',
    description: 'User input rendered directly into DOM without sanitization',
    patterns: [
      /(innerHTML|outerHTML)\s*[=+]\s*[^;]*\$\{[^}]*\}/gi,
      /(innerHTML|outerHTML)\s*[=+]\s*[^;]*(req\.|request\.|params\.)/gi,
      /document\.write\s*\([^)]*\$\{[^}]*\}/gi,
      /\$\([^)]*\)\.html\([^)]*req\./gi
    ],
    severity: 'high',
    confidence: 0.85,
    fileTypes: ['js', 'ts', 'jsx', 'tsx', 'html'],
    recommendation: 'Use safe DOM manipulation methods like textContent or sanitize HTML input with a trusted library.',
    cwe: 'CWE-79',
    owasp: 'A03:2021 – Injection',
    impact: 'Session hijacking, credential theft, defacement',
    effort: 'low'
  },
  {
    id: 'stored-xss',
    name: 'Stored Cross-Site Scripting',
    category: 'Cross-Site Scripting',
    type: 'injection',
    description: 'User input stored and rendered without proper encoding',
    patterns: [
      /render\([^)]*\{[^}]*user[^}]*\}/gi,
      /<%=.*user.*%>/gi,
      /\{\{.*user.*\}\}/gi,
      /echo\s+\$_POST/gi
    ],
    severity: 'high',
    confidence: 0.7,
    fileTypes: ['php', 'jsp', 'erb', 'ejs', 'handlebars'],
    recommendation: 'Encode output based on context (HTML, attribute, JavaScript). Use templating engines with auto-escaping.',
    cwe: 'CWE-79',
    owasp: 'A03:2021 – Injection',
    impact: 'Persistent malicious scripts affecting all users',
    effort: 'medium'
  },
  {
    id: 'command-injection',
    name: 'Command Injection',
    category: 'Command Injection',
    type: 'injection',
    description: 'System command execution with unsanitized user input',
    patterns: [
      /(exec|system|shell_exec|passthru|popen)\s*\([^)]*\$[^)]*\)/gi,
      /(os\.system|subprocess\.call|subprocess\.run)\s*\([^)]*req\./gi,
      /(Runtime\.getRuntime\(\)\.exec)\s*\([^)]*req\./gi,
      /child_process\.(exec|spawn)\s*\([^)]*req\./gi
    ],
    severity: 'critical',
    confidence: 0.95,
    fileTypes: ['php', 'py', 'java', 'js', 'ts', 'go', 'rb'],
    recommendation: 'Avoid system commands with user input. Use APIs instead. If necessary, validate input against strict whitelist.',
    cwe: 'CWE-78',
    owasp: 'A03:2021 – Injection',
    impact: 'Complete system compromise, arbitrary code execution',
    effort: 'high'
  },
  {
    id: 'template-injection',
    name: 'Server-Side Template Injection',
    category: 'Template Injection',
    type: 'injection',
    description: 'User input processed by template engine without proper sandboxing',
    patterns: [
      /Template\([^)]*req\./gi,
      /render_template_string\([^)]*req\./gi,
      /\{\{.*request\..*\}\}/gi,
      /<%.*request\..*%>/gi
    ],
    severity: 'critical',
    confidence: 0.8,
    fileTypes: ['py', 'js', 'ts', 'java', 'php'],
    recommendation: 'Use safe template rendering. Sandbox template execution or precompile templates.',
    cwe: 'CWE-94',
    owasp: 'A03:2021 – Injection',
    impact: 'Remote code execution, server compromise',
    effort: 'high'
  },
  {
    id: 'code-injection-eval',
    name: 'Code Injection via eval()',
    category: 'Code Injection',
    type: 'injection',
    description: 'Dynamic code execution with user-controlled input',
    patterns: [
      /eval\s*\([^)]*req\./gi,
      /exec\s*\([^)]*req\./gi,
      /Function\s*\([^)]*req\./gi,
      /compile\s*\([^)]*req\./gi
    ],
    severity: 'critical',
    confidence: 0.9,
    fileTypes: ['js', 'ts', 'py', 'php'],
    recommendation: 'Never use eval() with user input. Use safe alternatives like JSON.parse() for data parsing.',
    cwe: 'CWE-94',
    owasp: 'A03:2021 – Injection',
    impact: 'Arbitrary code execution, complete application compromise',
    effort: 'high'
  },

  // B) Broken Access & Authorization
  {
    id: 'missing-auth-check',
    name: 'Missing Authorization Check',
    category: 'Broken Access Control',
    type: 'broken_access',
    description: 'Sensitive operation without proper authorization verification',
    patterns: [
      /(?:DELETE\s+FROM|DROP\s+TABLE|\.delete\s*\()\s*(?!.*(?:auth|permission|role|check|verify|token))/gi,
      /admin\s*=\s*true(?!.*(?:auth|permission|check|verify))/gi,
      /router\.(delete|put)\s*\([^)]*\)\s*(?!.*(?:auth|middleware|permission|verify))/gi
    ],
    severity: 'high',
    confidence: 0.7,
    fileTypes: ['js', 'ts', 'py', 'java', 'php', 'go'],
    recommendation: 'Implement proper authorization checks before sensitive operations. Use middleware or decorators.',
    cwe: 'CWE-862',
    owasp: 'A01:2021 – Broken Access Control',
    impact: 'Unauthorized access to sensitive functionality',
    effort: 'medium'
  },
  {
    id: 'insecure-direct-object-ref',
    name: 'Insecure Direct Object Reference',
    category: 'Insecure Direct Object Reference',
    type: 'broken_access',
    description: 'Direct access to internal objects without authorization',
    patterns: [
      /findById\s*\([^)]*req\.params/gi,
      /getUser\s*\([^)]*req\.params/gi,
      /file\s*=\s*req\.params/gi,
      /path\s*=\s*req\.query/gi
    ],
    severity: 'medium',
    confidence: 0.7,
    fileTypes: ['js', 'ts', 'py', 'java', 'php'],
    recommendation: 'Validate user ownership of requested resources. Use indirect references or access control lists.',
    cwe: 'CWE-639',
    owasp: 'A01:2021 – Broken Access Control',
    impact: 'Unauthorized access to other users\' data',
    effort: 'medium'
  },

  // C) Sensitive Data & Secret Exposure  
  {
    id: 'hardcoded-crypto-key',
    name: 'Hardcoded Cryptographic Key',
    category: 'Hardcoded Secrets',
    type: 'sensitive_data',
    description: 'Cryptographic key or secret hardcoded in source code',
    patterns: [
      /(key|secret|password|token)\s*[:=]\s*["'][A-Za-z0-9+/=]{16,}["']/gi,
      /AES\.encrypt\s*\([^,]*,\s*["'][^"']{8,}["']/gi,
      /createCipher\s*\([^,]*,\s*["'][^"']{8,}["']/gi
    ],
    severity: 'critical',
    confidence: 0.8,
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php', 'rb'],
    recommendation: 'Store cryptographic keys in environment variables or secure key management systems.',
    cwe: 'CWE-798',
    owasp: 'A02:2021 – Cryptographic Failures',
    impact: 'Complete compromise of encrypted data',
    effort: 'low'
  },
  {
    id: 'logging-sensitive-data',
    name: 'Sensitive Data in Logs',
    category: 'Information Disclosure',
    type: 'sensitive_data',
    description: 'Logging of sensitive information like passwords or tokens',
    patterns: [
      /(console\.log|logger\.|print|echo)\s*\([^)]*password[^)]*\)/gi,
      /(console\.log|logger\.|print|echo)\s*\([^)]*token[^)]*\)/gi,
      /(console\.log|logger\.|print|echo)\s*\([^)]*secret[^)]*\)/gi,
      /log\.[^(]*\([^)]*req\.body[^)]*\)/gi
    ],
    severity: 'medium',
    confidence: 0.7,
    fileTypes: ['js', 'ts', 'py', 'java', 'php', 'go'],
    recommendation: 'Remove or sanitize sensitive data before logging. Use structured logging with field filtering.',
    cwe: 'CWE-532',
    owasp: 'A09:2021 – Security Logging and Monitoring Failures',
    impact: 'Sensitive data exposure in log files',
    effort: 'low'
  },

  // D) Deserialization & Remote Code Execution
  {
    id: 'unsafe-deserialization',
    name: 'Unsafe Deserialization',
    category: 'Insecure Deserialization',
    type: 'deserialization',
    description: 'Deserialization of untrusted data without proper validation',
    patterns: [
      /pickle\.loads?\s*\(/gi,
      /yaml\.load\s*\(/gi,
      /unserialize\s*\([^)]*\$_/gi,
      /ObjectInputStream\s*\([^)]*req\./gi,
      /JSON\.parse\s*\([^)]*req\.body\)/gi
    ],
    severity: 'critical',
    confidence: 0.85,
    fileTypes: ['py', 'php', 'java', 'js', 'ts'],
    recommendation: 'Use safe deserialization methods. Validate data types and implement whitelist filtering.',
    cwe: 'CWE-502',
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    impact: 'Remote code execution, complete system compromise',
    effort: 'high'
  },
  {
    id: 'log4j-jndi-lookup',
    name: 'Log4Shell JNDI Lookup Vulnerability',
    category: 'JNDI Injection',
    type: 'deserialization',
    description: 'Unsafe logging that could trigger JNDI lookups',
    patterns: [
      /log\.[^(]*\([^)]*\$\{jndi:/gi,
      /logger\.[^(]*\([^)]*req\.[^)]*\)/gi,
      /LOG\.[^(]*\([^)]*\$\{/gi
    ],
    severity: 'critical',
    confidence: 0.9,
    fileTypes: ['java'],
    recommendation: 'Update Log4j to latest version. Disable JNDI lookups. Sanitize logged user input.',
    cwe: 'CWE-917',
    owasp: 'A06:2021 – Vulnerable and Outdated Components',
    impact: 'Remote code execution via JNDI injection',
    effort: 'low'
  },

  // E) File, Path & Resource Manipulation
  {
    id: 'path-traversal',
    name: 'Path Traversal Attack',
    category: 'Directory Traversal',
    type: 'file_path',
    description: 'File path manipulation allowing access to unauthorized directories',
    patterns: [
      /(readFile|writeFile|open|include|require)\s*\([^)]*\.\.\//gi,
      /(readFile|writeFile|open)\s*\([^)]*req\.(params|query|body)/gi,
      /file\s*=\s*req\.[^;]*\.\.\//gi,
      /path\s*=\s*.*\.\.\//gi
    ],
    severity: 'high',
    confidence: 0.8,
    fileTypes: ['js', 'ts', 'py', 'php', 'java', 'cs', 'go'],
    recommendation: 'Validate and normalize file paths. Use path.resolve() and check against whitelist.',
    cwe: 'CWE-22',
    owasp: 'A01:2021 – Broken Access Control',
    impact: 'Unauthorized file system access, sensitive file disclosure',
    effort: 'medium'
  },
  {
    id: 'unrestricted-file-upload',
    name: 'Unrestricted File Upload',
    category: 'File Upload',
    type: 'file_path',
    description: 'File upload without proper type or size restrictions',
    patterns: [
      /multer\s*\(\s*\{[^}]*(?!fileFilter|limits)/gi,
      /move_uploaded_file\s*\([^)]*(?!.*filter)/gi,
      /req\.files?\.[^.]*\.(?!mimetype|size)/gi
    ],
    severity: 'high',
    confidence: 0.6,
    fileTypes: ['js', 'ts', 'php', 'py'],
    recommendation: 'Implement file type validation, size limits, and store uploads outside web root.',
    cwe: 'CWE-434',
    owasp: 'A01:2021 – Broken Access Control',
    impact: 'Malicious file upload, potential code execution',
    effort: 'medium'
  },

  // F) Memory & Language-Specific Weaknesses
  {
    id: 'buffer-overflow',
    name: 'Buffer Overflow Risk',
    category: 'Buffer Overflow',
    type: 'memory',
    description: 'Unsafe memory operations that could lead to buffer overflow',
    patterns: [
      /strcpy\s*\([^)]*(?!strncpy)/gi,
      /sprintf\s*\([^)]*(?!snprintf)/gi,
      /gets\s*\(/gi,
      /scanf\s*\([^)]*%s/gi
    ],
    severity: 'critical',
    confidence: 0.9,
    fileTypes: ['c', 'cpp', 'h'],
    recommendation: 'Use safe string functions like strncpy, snprintf. Implement bounds checking.',
    cwe: 'CWE-120',
    owasp: 'A06:2021 – Vulnerable and Outdated Components',
    impact: 'Memory corruption, potential code execution',
    effort: 'high'
  },

  // G) Cryptography & Configuration
  {
    id: 'weak-crypto-algorithm',
    name: 'Weak Cryptographic Algorithm',
    category: 'Weak Cryptography',
    type: 'cryptography',
    description: 'Use of deprecated or weak cryptographic algorithms',
    patterns: [
      /(?:crypto\.|hashlib\.|MessageDigest\.|Cipher\.)(md5|sha1|des|rc4)\s*\(/gi,
      /createHash\s*\(\s*["'](md5|sha1)["']/gi,
      /MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA1|DES)["']/gi,
      /Cipher\.getInstance\s*\(\s*["'](DES|RC4)["']/gi,
      /new\s+(MD5|SHA1|DES|RC4)\s*\(/gi
    ],
    severity: 'medium',
    confidence: 0.9,
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php'],
    recommendation: 'Use strong algorithms: SHA-256/SHA-3 for hashing, AES for encryption, bcrypt for passwords.',
    cwe: 'CWE-327',
    owasp: 'A02:2021 – Cryptographic Failures',
    impact: 'Cryptographic data compromise, hash collisions',
    effort: 'low'
  },
  {
    id: 'insecure-random',
    name: 'Cryptographically Insecure Random Numbers',
    category: 'Weak Random Generation',
    type: 'cryptography',
    description: 'Use of predictable random number generators for security',
    patterns: [
      /Math\.random\(\)(?=.*password|.*token|.*key|.*nonce)/gi,
      /random\.Random\(\)(?=.*password|.*token)/gi,
      /rand\(\)(?=.*password|.*token)/gi
    ],
    severity: 'medium',
    confidence: 0.7,
    fileTypes: ['js', 'ts', 'py', 'java', 'php', 'go'],
    recommendation: 'Use cryptographically secure random generators: crypto.randomBytes(), SecureRandom, os.urandom().',
    cwe: 'CWE-338',
    owasp: 'A02:2021 – Cryptographic Failures',
    impact: 'Predictable tokens, session fixation',
    effort: 'low'
  },
  {
    id: 'insecure-ssl-tls',
    name: 'Insecure SSL/TLS Configuration',
    category: 'TLS Configuration',
    type: 'cryptography',
    description: 'Weak SSL/TLS configuration or disabled certificate validation',
    patterns: [
      /rejectUnauthorized\s*:\s*false/gi,
      /verify\s*:\s*false/gi,
      /CURLOPT_SSL_VERIFYPEER.*false/gi,
      /SSLContext.*TLS.*v1\./gi
    ],
    severity: 'high',
    confidence: 0.8,
    fileTypes: ['js', 'ts', 'py', 'php', 'java', 'go'],
    recommendation: 'Enable certificate validation. Use TLS 1.2+ with strong cipher suites.',
    cwe: 'CWE-295',
    owasp: 'A02:2021 – Cryptographic Failures',
    impact: 'Man-in-the-middle attacks, data interception',
    effort: 'low'
  }
];

export function checkAdvancedVulnerabilities(content: string, filename: string): Array<{
  rule: AdvancedVulnerabilityRule;
  matches: RegExpMatchArray[];
}> {
  const fileExtension = filename.split('.').pop()?.toLowerCase();
  if (!fileExtension) return [];

  const results: Array<{
    rule: AdvancedVulnerabilityRule;
    matches: RegExpMatchArray[];
  }> = [];

  for (const rule of advancedVulnerabilityRules) {
    if (!rule.fileTypes.includes(fileExtension)) continue;

    const matches: RegExpMatchArray[] = [];
    
    for (const pattern of rule.patterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        matches.push(match);
        if (!pattern.global) break;
      }
      pattern.lastIndex = 0;
    }
    
    if (matches.length > 0) {
      results.push({ rule, matches });
    }
  }

  return results;
}