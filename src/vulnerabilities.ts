import { VulnerabilityRule } from './types';

export const vulnerabilityRules: VulnerabilityRule[] = [
  {
    id: 'sql-injection',
    name: 'SQL Injection Risk',
    description: 'Potential SQL injection vulnerability detected',
    pattern: /(query|execute)\s*\(\s*["'`][^"'`]*\$\{[^}]*\}[^"'`]*["'`]/gi,
    severity: 'high',
    fileTypes: ['js', 'ts', 'jsx', 'tsx', 'php', 'py', 'java', 'cs'],
    recommendation: 'Use parameterized queries or prepared statements instead of string concatenation'
  },
  {
    id: 'xss-risk',
    name: 'Cross-Site Scripting (XSS) Risk',
    description: 'Potential XSS vulnerability detected',
    pattern: /(innerHTML|outerHTML|document\.write)\s*[=+]\s*[^;]*\$\{[^}]*\}/gi,
    severity: 'high',
    fileTypes: ['js', 'ts', 'jsx', 'tsx', 'html'],
    recommendation: 'Use safe DOM manipulation methods or sanitize user input'
  },
  {
    id: 'command-injection',
    name: 'Command Injection Risk',
    description: 'Potential command injection vulnerability detected',
    pattern: /(exec|spawn|system|shell_exec)\s*\([^)]*\$\{[^}]*\}/gi,
    severity: 'critical',
    fileTypes: ['js', 'ts', 'py', 'php', 'rb', 'go'],
    recommendation: 'Validate and sanitize input before executing system commands'
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal Risk',
    description: 'Potential path traversal vulnerability detected',
    pattern: /(readFile|writeFile|open|include|require)\s*\([^)]*\.\.\//gi,
    severity: 'medium',
    fileTypes: ['js', 'ts', 'py', 'php', 'java', 'cs'],
    recommendation: 'Validate file paths and use path normalization'
  },
  {
    id: 'weak-crypto',
    name: 'Weak Cryptographic Algorithm',
    description: 'Use of weak or deprecated cryptographic algorithm',
    pattern: /(md5|sha1|des|rc4)\s*\(/gi,
    severity: 'medium',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php'],
    recommendation: 'Use strong cryptographic algorithms like SHA-256, AES, or bcrypt'
  },
  {
    id: 'insecure-random',
    name: 'Insecure Random Number Generation',
    description: 'Use of insecure random number generator',
    pattern: /(Math\.random|random\.Random)\(\)/gi,
    severity: 'low',
    fileTypes: ['js', 'ts', 'py', 'java'],
    recommendation: 'Use cryptographically secure random number generators for security-sensitive operations'
  },
  {
    id: 'http-without-https',
    name: 'Insecure HTTP Communication',
    description: 'HTTP communication detected instead of HTTPS',
    pattern: /["']http:\/\/[^"']+["']/gi,
    severity: 'medium',
    fileTypes: ['js', 'ts', 'jsx', 'tsx', 'html', 'py', 'java', 'cs'],
    recommendation: 'Use HTTPS for all network communications'
  },
  {
    id: 'eval-usage',
    name: 'Code Injection via eval()',
    description: 'Use of eval() function detected',
    pattern: /eval\s*\(/gi,
    severity: 'high',
    fileTypes: ['js', 'ts', 'jsx', 'tsx'],
    recommendation: 'Avoid using eval(). Use safer alternatives like JSON.parse() for data parsing'
  },
  {
    id: 'dangerous-file-permissions',
    name: 'Dangerous File Permissions',
    description: 'Overly permissive file permissions detected',
    pattern: /(chmod|os\.chmod)\s*\([^,)]*,\s*0?777\)/gi,
    severity: 'medium',
    fileTypes: ['py', 'js', 'ts', 'sh', 'bash'],
    recommendation: 'Use restrictive file permissions (e.g., 644 for files, 755 for directories)'
  },
  {
    id: 'hardcoded-secrets',
    name: 'Hardcoded Secrets',
    description: 'Hardcoded sensitive information detected',
    pattern: /(token|key|password|secret)\s*[:=]\s*["'][A-Za-z0-9+/=]{10,}["']/gi,
    severity: 'high',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php', 'rb'],
    recommendation: 'Store secrets in environment variables or secure configuration files'
  },
  {
    id: 'cors-wildcard',
    name: 'CORS Wildcard Origin',
    description: 'CORS configured with wildcard origin (*)',
    pattern: /Access-Control-Allow-Origin["'\s]*:["'\s]*\*/gi,
    severity: 'medium',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php'],
    recommendation: 'Specify explicit allowed origins instead of using wildcard'
  },
  {
    id: 'debug-info-leak',
    name: 'Debug Information Disclosure',
    description: 'Debug information or stack traces exposed',
    pattern: /(console\.log|print|echo|System\.out\.println)\s*\([^)]*error[^)]*\)/gi,
    severity: 'low',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php'],
    recommendation: 'Remove debug statements from production code'
  },
  {
    id: 'unsafe-deserialization',
    name: 'Unsafe Deserialization',
    description: 'Unsafe deserialization detected',
    pattern: /(pickle\.loads|yaml\.load|unserialize)\s*\(/gi,
    severity: 'high',
    fileTypes: ['py', 'php', 'java'],
    recommendation: 'Use safe deserialization methods and validate input data'
  },
  {
    id: 'ldap-injection',
    name: 'LDAP Injection Risk',
    description: 'Potential LDAP injection vulnerability',
    pattern: /ldap[^;]*search[^;]*\$\{[^}]*\}/gi,
    severity: 'medium',
    fileTypes: ['js', 'ts', 'java', 'cs', 'py'],
    recommendation: 'Properly escape LDAP special characters in user input'
  },
  {
    id: 'xxe-risk',
    name: 'XML External Entity (XXE) Risk',
    description: 'Potential XXE vulnerability in XML parsing',
    pattern: /(XMLHttpRequest|DOMParser|xml\.etree|DocumentBuilder).*<!ENTITY/gi,
    severity: 'high',
    fileTypes: ['js', 'ts', 'java', 'cs', 'py', 'xml'],
    recommendation: 'Disable external entity processing in XML parsers'
  }
];

export function checkVulnerabilities(content: string, filename: string): Array<{
  rule: VulnerabilityRule;
  matches: RegExpMatchArray[];
}> {
  const fileExtension = filename.split('.').pop()?.toLowerCase();
  if (!fileExtension) return [];

  const results: Array<{
    rule: VulnerabilityRule;
    matches: RegExpMatchArray[];
  }> = [];

  for (const rule of vulnerabilityRules) {
    if (!rule.fileTypes.includes(fileExtension)) continue;

    const matches: RegExpMatchArray[] = [];
    let match;
    
    while ((match = rule.pattern.exec(content)) !== null) {
      matches.push(match);
      if (!rule.pattern.global) break;
    }
    
    if (matches.length > 0) {
      results.push({ rule, matches });
    }
    
    rule.pattern.lastIndex = 0;
  }

  return results;
}