import { SecretPattern } from './types';

export const secretPatterns: SecretPattern[] = [
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    confidence: 0.9,
    description: 'AWS Access Key ID detected'
  },
  {
    name: 'AWS Secret Key',
    pattern: /(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|secretkey)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi,
    confidence: 0.85,
    description: 'AWS Secret Access Key detected'
  },
  {
    name: 'GitHub Token',
    pattern: /ghp_[A-Za-z0-9]{36}/g,
    confidence: 0.95,
    description: 'GitHub Personal Access Token'
  },
  {
    name: 'GitHub OAuth Token',
    pattern: /gho_[A-Za-z0-9]{36}/g,
    confidence: 0.95,
    description: 'GitHub OAuth Access Token'
  },
  {
    name: 'OpenAI API Key',
    pattern: /sk-[A-Za-z0-9]{48}/g,
    confidence: 0.9,
    description: 'OpenAI API Key'
  },
  {
    name: 'Stripe API Key',
    pattern: /sk_live_[0-9a-zA-Z]{24}/g,
    confidence: 0.9,
    description: 'Stripe Live API Key'
  },
  {
    name: 'Stripe Test Key',
    pattern: /sk_test_[0-9a-zA-Z]{24}/g,
    confidence: 0.85,
    description: 'Stripe Test API Key'
  },
  {
    name: 'Google API Key',
    pattern: /AIza[0-9A-Za-z\\-_]{35}/g,
    confidence: 0.85,
    description: 'Google API Key'
  },
  {
    name: 'Firebase Token',
    pattern: /[A-Za-z0-9_-]{1,4}:[A-Za-z0-9_-]{140}/g,
    confidence: 0.8,
    description: 'Firebase Token'
  },
  {
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*/g,
    confidence: 0.75,
    description: 'JSON Web Token (JWT)'
  },
  {
    name: 'SSH Private Key',
    pattern: /-----BEGIN [A-Z]+ PRIVATE KEY-----[\\s\\S]*?-----END [A-Z]+ PRIVATE KEY-----/g,
    confidence: 0.95,
    description: 'SSH Private Key'
  },
  {
    name: 'Database URL',
    pattern: /(mongodb|mysql|postgresql|redis):\/\/[^\s"'`]+/gi,
    confidence: 0.8,
    description: 'Database Connection String'
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
    confidence: 0.9,
    description: 'Slack Token'
  },
  {
    name: 'Discord Bot Token',
    pattern: /[MN][A-Za-z\\d]{23}\\.[\\w-]{6}\\.[\\w-]{27}/g,
    confidence: 0.9,
    description: 'Discord Bot Token'
  },
  {
    name: 'Twilio Account SID',
    pattern: /AC[a-z0-9]{32}/g,
    confidence: 0.85,
    description: 'Twilio Account SID'
  },
  {
    name: 'Twilio Auth Token',
    pattern: /[a-z0-9]{32}/g,
    confidence: 0.6,
    description: 'Potential Twilio Auth Token'
  },
  {
    name: 'Generic API Key',
    pattern: /(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)["\s]*[:=]\s*["'][A-Za-z0-9+/=]{20,}["']/gi,
    confidence: 0.7,
    description: 'Generic API Key or Secret'
  },
  {
    name: 'Password in Code',
    pattern: /(password|pwd|pass)["\s]*[:=]\s*["'][^"']{4,}["']/gi,
    confidence: 0.6,
    description: 'Hard-coded password'
  },
  {
    name: 'Email and Password Combo',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["\s]*[:,]\s*["'][^"']{4,}["']/g,
    confidence: 0.7,
    description: 'Email and password combination'
  }
];

export function detectSecrets(content: string, filename: string): Array<{
  pattern: SecretPattern;
  matches: RegExpMatchArray[];
}> {
  const results: Array<{
    pattern: SecretPattern;
    matches: RegExpMatchArray[];
  }> = [];

  for (const pattern of secretPatterns) {
    const matches: RegExpMatchArray[] = [];
    let match;
    
    while ((match = pattern.pattern.exec(content)) !== null) {
      matches.push(match);
      if (!pattern.pattern.global) break;
    }
    
    if (matches.length > 0) {
      results.push({ pattern, matches });
    }
    
    pattern.pattern.lastIndex = 0;
  }

  return results;
}