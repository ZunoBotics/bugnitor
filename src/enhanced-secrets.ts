import { SecurityFinding } from './types';

export interface EnhancedSecretPattern {
  id: string;
  name: string;
  patterns: RegExp[];
  contextPatterns?: RegExp[];
  excludePatterns?: RegExp[];
  confidence: number;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cwe: string;
  owasp: string;
  examples: string[];
  remediation: {
    description: string;
    effort: 'low' | 'medium' | 'high';
    codeExample?: string;
  };
}

export const enhancedSecretPatterns: EnhancedSecretPattern[] = [
  {
    id: 'database-url',
    name: 'Database Connection String',
    patterns: [
      /(postgresql|mysql|mongodb|redis|sqlite):\/\/[^\s"'`;<>{}|\[\]\\^]+/gi,
      /(postgres|mysql|mongo|redis):\/\/[^\s"'`;<>{}|\[\]\\^]+/gi,
      /(?:database_url|db_url|connection_string)\s*[:=]\s*["']([^"']+)["']/gi
    ],
    contextPatterns: [
      /(?:database|db|connection|url)/gi
    ],
    excludePatterns: [
      /localhost|127\.0\.0\.1|example\.com|test\.db|mock/gi
    ],
    confidence: 0.9,
    description: 'Database connection string with embedded credentials',
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'A02:2021 – Cryptographic Failures',
    examples: [
      'postgresql://username:password@localhost:5432/database',
      'mongodb://user:pass@mongo.example.com:27017/mydb'
    ],
    remediation: {
      description: 'Use environment variables or secure configuration management',
      effort: 'low',
      codeExample: `// Instead of:
const dbUrl = "postgresql://user:pass@localhost:5432/db";

// Use:
const dbUrl = process.env.DATABASE_URL;`
    }
  },
  {
    id: 'aws-credentials',
    name: 'AWS Credentials',
    patterns: [
      /AKIA[0-9A-Z]{16}/g,
      /(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["']?([A-Z0-9]{20})["']?/gi,
      /(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi
    ],
    contextPatterns: [
      /aws|amazon|s3|ec2|lambda/gi
    ],
    confidence: 0.95,
    description: 'AWS access credentials detected',
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'A02:2021 – Cryptographic Failures',
    examples: [
      'AKIAIOSFODNN7EXAMPLE',
      'aws_access_key_id = AKIAIOSFODNN7EXAMPLE'
    ],
    remediation: {
      description: 'Use AWS IAM roles or environment variables',
      effort: 'medium',
      codeExample: `// Use AWS SDK with IAM roles or environment variables
const aws = require('aws-sdk');
aws.config.update({ region: 'us-east-1' }); // Credentials from environment`
    }
  },
  {
    id: 'jwt-secret',
    name: 'JWT Secret Key',
    patterns: [
      /(?:jwt[_-]?secret|token[_-]?secret|signing[_-]?key)\s*[:=]\s*["']([^"']{8,})["']/gi,
      /jwt\.sign\s*\([^,]+,\s*["']([^"']{8,})["']/gi
    ],
    contextPatterns: [
      /jwt|jsonwebtoken|token|signing/gi
    ],
    confidence: 0.85,
    description: 'JWT signing secret detected',
    severity: 'high',
    cwe: 'CWE-798',
    owasp: 'A02:2021 – Cryptographic Failures',
    examples: [
      'jwt_secret = "my-super-secret-key"',
      'jwt.sign(payload, "hardcoded-secret")'
    ],
    remediation: {
      description: 'Use environment variables for JWT secrets',
      effort: 'low',
      codeExample: `// Use environment variable
const token = jwt.sign(payload, process.env.JWT_SECRET);`
    }
  },
  {
    id: 'api-keys',
    name: 'API Keys',
    patterns: [
      /(?:api[_-]?key|apikey)\s*[:=]\s*["']([A-Za-z0-9_-]{16,})["']/gi,
      /(?:secret[_-]?key|secretkey)\s*[:=]\s*["']([A-Za-z0-9_-]{16,})["']/gi,
      /(?:access[_-]?token|accesstoken)\s*[:=]\s*["']([A-Za-z0-9_.-]{16,})["']/gi
    ],
    contextPatterns: [
      /api|key|token|secret/gi
    ],
    excludePatterns: [
      /test|example|demo|placeholder|your-api-key|xxx/gi
    ],
    confidence: 0.8,
    description: 'Generic API key or secret detected',
    severity: 'high',
    cwe: 'CWE-798',
    owasp: 'A02:2021 – Cryptographic Failures',
    examples: [
      'api_key = "sk_live_abcdef123456"',
      'const apiKey = "your-secret-api-key-here";'
    ],
    remediation: {
      description: 'Store API keys in environment variables or secure vault',
      effort: 'low',
      codeExample: `// Use environment variable
const apiKey = process.env.API_KEY;`
    }
  },
  {
    id: 'private-keys',
    name: 'Private Key',
    patterns: [
      /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi,
      /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----/gi
    ],
    confidence: 0.95,
    description: 'Private key detected in source code',
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'A02:2021 – Cryptographic Failures',
    examples: [
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...'
    ],
    remediation: {
      description: 'Never store private keys in source code. Use secure key management.',
      effort: 'high',
      codeExample: `// Load from secure file system or key management service
const privateKey = fs.readFileSync(process.env.PRIVATE_KEY_PATH);`
    }
  },
  {
    id: 'password-fields',
    name: 'Hardcoded Password',
    patterns: [
      /(?:password|pwd|pass)\s*[:=]\s*["']([^"']{4,})["']/gi,
      /(?:user|username)\s*[:=]\s*["'][^"']+["']\s*[,;]\s*(?:password|pwd|pass)\s*[:=]\s*["']([^"']{4,})["']/gi
    ],
    contextPatterns: [
      /password|credentials|auth|login/gi
    ],
    excludePatterns: [
      /\*+|password|123|test|demo|example/gi
    ],
    confidence: 0.7,
    description: 'Hardcoded password detected',
    severity: 'high',
    cwe: 'CWE-798',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    examples: [
      'password: "admin123"',
      'const pwd = "mySecretPassword";'
    ],
    remediation: {
      description: 'Use environment variables or secure credential storage',
      effort: 'low',
      codeExample: `// Use environment variable
const password = process.env.DB_PASSWORD;`
    }
  },
  {
    id: 'github-tokens',
    name: 'GitHub Token',
    patterns: [
      /ghp_[A-Za-z0-9]{36}/g,
      /gho_[A-Za-z0-9]{36}/g,
      /ghu_[A-Za-z0-9]{36}/g,
      /ghs_[A-Za-z0-9]{36}/g,
      /ghr_[A-Za-z0-9]{36}/g
    ],
    confidence: 0.95,
    description: 'GitHub personal access token detected',
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'A02:2021 – Cryptographic Failures',
    examples: [
      'ghp_1234567890abcdef1234567890abcdef123456'
    ],
    remediation: {
      description: 'Revoke token immediately and use GitHub secrets in workflows',
      effort: 'low',
      codeExample: `# In GitHub Actions
env:
  GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}`
    }
  },
  {
    id: 'slack-tokens',
    name: 'Slack Token',
    patterns: [
      /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
      /(?:slack[_-]?token|slack[_-]?webhook)\s*[:=]\s*["']([^"']+)["']/gi
    ],
    confidence: 0.9,
    description: 'Slack API token or webhook URL detected',
    severity: 'high',
    cwe: 'CWE-798',
    owasp: 'A02:2021 – Cryptographic Failures',
    examples: [
      'xoxb-1234567890-1234567890-abcdef123456',
      'slack_token = "xoxp-1234567890-abcdef"'
    ],
    remediation: {
      description: 'Use environment variables for Slack tokens',
      effort: 'low'
    }
  }
];

export class EnhancedSecretDetector {
  detectSecrets(content: string, filename: string): Array<{
    pattern: EnhancedSecretPattern;
    matches: Array<{
      match: RegExpMatchArray;
      confidence: number;
      context: string;
    }>;
  }> {
    const results: Array<{
      pattern: EnhancedSecretPattern;
      matches: Array<{
        match: RegExpMatchArray;
        confidence: number;
        context: string;
      }>;
    }> = [];

    for (const pattern of enhancedSecretPatterns) {
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
          if (confidence < 0.4) continue;

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

  private getMatchContext(content: string, index: number, contextSize: number = 100): string {
    const start = Math.max(0, index - contextSize);
    const end = Math.min(content.length, index + contextSize);
    return content.substring(start, end);
  }

  private calculateConfidence(
    pattern: EnhancedSecretPattern,
    match: RegExpMatchArray,
    context: string,
    filename: string
  ): number {
    let confidence = pattern.confidence;

    // File type adjustments
    if (filename.includes('.env') || filename.includes('config')) {
      confidence *= 1.2;
    }
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
          confidence *= 1.1;
          break;
        }
      }
      if (!hasContext) {
        confidence *= 0.8;
      }
    }

    // Exclude pattern matching
    if (pattern.excludePatterns) {
      for (const excludePattern of pattern.excludePatterns) {
        if (excludePattern.test(match[0]) || excludePattern.test(context)) {
          confidence *= 0.3;
          break;
        }
      }
    }

    // Length-based confidence for generic patterns
    const matchLength = match[0].length;
    if (matchLength < 8) {
      confidence *= 0.7;
    } else if (matchLength > 32) {
      confidence *= 1.1;
    }

    // Check for common placeholder patterns
    const placeholderPatterns = [
      /^[x]+$/i,
      /^[0]+$/i,
      /^(test|example|placeholder|your[-_])/i,
      /^[a-z]{1,3}$/i
    ];

    for (const placeholderPattern of placeholderPatterns) {
      if (placeholderPattern.test(match[0])) {
        confidence *= 0.2;
        break;
      }
    }

    return Math.min(1.0, Math.max(0.0, confidence));
  }
}