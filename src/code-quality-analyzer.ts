import { SecurityFinding } from './types';

export interface CodeQualityMetric {
  id: string;
  name: string;
  category: string;
  description: string;
  patterns: RegExp[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  impact: string;
  fileTypes: string[];
  recommendation: string;
  weight: number; // Weight for overall score calculation
}

export interface QualityScore {
  overall: number; // 0-100
  maintainability: number;
  readability: number;
  complexity: number;
  security: number;
  breakdown: {
    [key: string]: {
      score: number;
      issues: number;
      description: string;
    };
  };
}

export const codeQualityMetrics: CodeQualityMetric[] = [
  {
    id: 'long-functions',
    name: 'Overly Long Functions',
    category: 'Maintainability',
    description: 'Functions with too many lines of code are hard to maintain',
    patterns: [
      /function\s+\w+\s*\([^)]*\)\s*\{[\s\S]{1000,}\}/gi,
      /=>\s*\{[\s\S]{800,}\}/gi,
      /def\s+\w+\s*\([^)]*\):[\s\S]{1200,}(?=\n\S|\n*$)/gi
    ],
    severity: 'medium',
    impact: 'Reduced maintainability and testability',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go'],
    recommendation: 'Break down large functions into smaller, focused functions',
    weight: 3
  },
  {
    id: 'deep-nesting',
    name: 'Deep Nesting',
    category: 'Complexity',
    description: 'Deeply nested code blocks increase cognitive complexity',
    patterns: [
      /(\s{8,}|\t{4,})(if|for|while|try|with)/gi,
      /\{\s*\n\s*\{\s*\n\s*\{\s*\n\s*\{/gi
    ],
    severity: 'medium',
    impact: 'Increased cognitive load and bug risk',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php'],
    recommendation: 'Reduce nesting using early returns, guard clauses, or extracted functions',
    weight: 2
  },
  {
    id: 'magic-numbers',
    name: 'Magic Numbers',
    category: 'Readability',
    description: 'Unexplained numeric literals reduce code readability',
    patterns: [
      /(?<!const\s+\w+\s*=\s*)\b(?!0|1)\d{2,}\b(?!\s*[;,\)\]\}])/gi,
      /\b\d+\.\d{2,}\b(?!\s*[;,\)\]\}])/gi
    ],
    severity: 'low',
    impact: 'Reduced code readability and maintainability',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php'],
    recommendation: 'Replace magic numbers with named constants',
    weight: 1
  },
  {
    id: 'long-parameter-lists',
    name: 'Long Parameter Lists',
    category: 'Maintainability',
    description: 'Functions with too many parameters are hard to use and maintain',
    patterns: [
      /function\s+\w+\s*\(([^)]*,){5,}[^)]*\)/gi,
      /def\s+\w+\s*\(([^)]*,){5,}[^)]*\)/gi,
      /\w+\s*\(([^)]*,){6,}[^)]*\)\s*=>/gi
    ],
    severity: 'medium',
    impact: 'Difficult to use and maintain functions',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go'],
    recommendation: 'Use parameter objects or break down functionality',
    weight: 2
  },
  {
    id: 'duplicate-code',
    name: 'Code Duplication',
    category: 'Maintainability',
    description: 'Repeated code blocks that should be refactored',
    patterns: [
      // This is simplified - real duplicate detection would need AST analysis
      /(\w+\s*=\s*[^;]{20,};[\s\n]*){3,}/gi
    ],
    severity: 'medium',
    impact: 'Maintenance burden and inconsistency risk',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php'],
    recommendation: 'Extract common code into reusable functions or modules',
    weight: 3
  },
  {
    id: 'missing-error-handling',
    name: 'Missing Error Handling',
    category: 'Reliability',
    description: 'Operations that can fail without proper error handling',
    patterns: [
      /(?:JSON\.parse|fs\.readFile|fetch|axios\.get|requests\.get)\s*\([^)]*\)(?!\s*\.catch)(?!\s*,\s*function)(?![\s\S]{0,100}(try|catch|except))/gi,
      /await\s+(?!.*try)(?!.*catch)/gi
    ],
    severity: 'high',
    impact: 'Application crashes and poor user experience',
    fileTypes: ['js', 'ts', 'py'],
    recommendation: 'Add proper error handling with try-catch blocks or error callbacks',
    weight: 4
  },
  {
    id: 'console-logs',
    name: 'Debug Code Left in Production',
    category: 'Code Hygiene',
    description: 'Debug statements that should be removed',
    patterns: [
      /console\.(log|debug|info|warn|error)\s*\(/gi,
      /print\s*\(/gi,
      /debugger\s*;/gi,
      /var_dump\s*\(/gi
    ],
    severity: 'low',
    impact: 'Performance impact and information leakage',
    fileTypes: ['js', 'ts', 'py', 'php'],
    recommendation: 'Remove debug statements or use proper logging frameworks',
    weight: 1
  },
  {
    id: 'large-files',
    name: 'Overly Large Files',
    category: 'Maintainability',
    description: 'Files with too many lines are hard to navigate and maintain',
    patterns: [], // This will be checked based on line count
    severity: 'medium',
    impact: 'Difficult navigation and maintenance',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php'],
    recommendation: 'Split large files into smaller, focused modules',
    weight: 2
  },
  {
    id: 'missing-documentation',
    name: 'Missing Documentation',
    category: 'Maintainability',
    description: 'Public functions without documentation comments',
    patterns: [
      /(?:export\s+)?(?:public\s+)?(?:function\s+\w+|class\s+\w+|def\s+\w+)(?![\s\S]{0,50}\/\*\*|[\s\S]{0,50}"""|[\s\S]{0,50}#)/gi
    ],
    severity: 'low',
    impact: 'Poor maintainability and developer experience',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go'],
    recommendation: 'Add JSDoc, docstrings, or equivalent documentation',
    weight: 1
  },
  {
    id: 'unused-variables',
    name: 'Unused Variables',
    category: 'Code Hygiene',
    description: 'Variables declared but never used',
    patterns: [
      /(?:var|let|const)\s+(\w+)(?![\s\S]*\1(?!\s*[=:]))/gi,
      /function\s+\w+\s*\([^)]*(\w+)[^)]*\)[\s\S]*?\{(?![\s\S]*\1)[\s\S]*?\}/gi
    ],
    severity: 'low',
    impact: 'Code bloat and confusion',
    fileTypes: ['js', 'ts'],
    recommendation: 'Remove unused variables or prefix with underscore if intentionally unused',
    weight: 1
  },
  {
    id: 'hardcoded-values',
    name: 'Hardcoded Configuration Values',
    category: 'Maintainability',
    description: 'Configuration values that should be externalized',
    patterns: [
      /(?:url|endpoint|server|host)\s*[:=]\s*["`'][^"`']*localhost[^"`']*["`']/gi,
      /(?:url|endpoint|server|host)\s*[:=]\s*["`'][^"`']*:\d{4,5}[^"`']*["`']/gi,
      /timeout\s*[:=]\s*\d{4,}/gi
    ],
    severity: 'medium',
    impact: 'Difficult environment-specific configuration',
    fileTypes: ['js', 'ts', 'py', 'java', 'cs', 'go', 'php'],
    recommendation: 'Move configuration to environment variables or config files',
    weight: 2
  }
];

export class CodeQualityAnalyzer {
  analyzeCodeQuality(content: string, filename: string, lineCount: number): {
    findings: SecurityFinding[];
    qualityScore: QualityScore;
  } {
    const fileExtension = filename.split('.').pop()?.toLowerCase();
    if (!fileExtension) return { findings: [], qualityScore: this.getDefaultScore() };

    const findings: SecurityFinding[] = [];
    const metricScores: { [key: string]: { score: number; issues: number; description: string } } = {};

    for (const metric of codeQualityMetrics) {
      if (!metric.fileTypes.includes(fileExtension)) continue;

      const issues = this.findMetricIssues(content, filename, lineCount, metric);
      findings.push(...issues);

      // Calculate score for this metric (0-100, where 100 is perfect)
      const issueCount = issues.length;
      const penalty = Math.min(issueCount * 10, 80); // Max 80% penalty
      const score = Math.max(100 - penalty, 20); // Min 20% score

      metricScores[metric.category] = metricScores[metric.category] || {
        score: 0,
        issues: 0,
        description: ''
      };

      metricScores[metric.category].score = Math.min(metricScores[metric.category].score + score * metric.weight, 100);
      metricScores[metric.category].issues += issueCount;
      metricScores[metric.category].description = this.getCategoryDescription(metric.category);
    }

    // Normalize scores by weight
    for (const category in metricScores) {
      const totalWeight = codeQualityMetrics
        .filter(m => m.category === category && m.fileTypes.includes(fileExtension))
        .reduce((sum, m) => sum + m.weight, 0);
      
      if (totalWeight > 0) {
        metricScores[category].score = metricScores[category].score / totalWeight;
      }
    }

    const qualityScore = this.calculateOverallScore(metricScores);

    return { findings, qualityScore };
  }

  private findMetricIssues(content: string, filename: string, lineCount: number, metric: CodeQualityMetric): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Special handling for large files
    if (metric.id === 'large-files' && lineCount > 500) {
      findings.push({
        type: 'config',
        category: metric.category,
        severity: lineCount > 1000 ? 'high' : 'medium',
        title: metric.name,
        description: `File has ${lineCount} lines (recommended: <500)`,
        file: filename,
        line: 1,
        column: 1,
        code: `File length: ${lineCount} lines`,
        codeContext: { before: '', after: '' },
        recommendation: metric.recommendation,
        confidence: 1.0,
        impact: metric.impact,
        effort: 'medium'
      });
      return findings;
    }

    // Pattern-based detection
    for (const pattern of metric.patterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const line = this.getLineNumber(content, match.index || 0);
        const column = this.getColumnNumber(content, match.index || 0);
        const codeContext = this.getCodeContext(content, match.index || 0);

        findings.push({
          type: 'config',
          category: metric.category,
          severity: metric.severity,
          title: metric.name,
          description: metric.description,
          file: filename,
          line,
          column,
          code: codeContext.matchedCode,
          codeContext: {
            before: codeContext.contextBefore,
            after: codeContext.contextAfter
          },
          recommendation: metric.recommendation,
          confidence: 0.8,
          impact: metric.impact,
          effort: 'low'
        });

        if (!pattern.global) break;
      }
      pattern.lastIndex = 0;
    }

    return findings;
  }

  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }

  private getColumnNumber(content: string, index: number): number {
    const lines = content.substring(0, index).split('\n');
    return lines[lines.length - 1].length + 1;
  }

  private getCodeContext(content: string, index: number): { matchedCode: string; contextBefore: string; contextAfter: string } {
    const lines = content.split('\n');
    const currentLineIndex = this.getLineNumber(content, index) - 1;
    
    const contextBefore = currentLineIndex > 0 ? lines[currentLineIndex - 1] : '';
    const currentLine = lines[currentLineIndex] || '';
    const contextAfter = currentLineIndex < lines.length - 1 ? lines[currentLineIndex + 1] : '';
    
    return {
      matchedCode: currentLine.trim(),
      contextBefore: contextBefore.trim(),
      contextAfter: contextAfter.trim()
    };
  }

  private calculateOverallScore(metricScores: { [key: string]: { score: number; issues: number; description: string } }): QualityScore {
    const categories = Object.keys(metricScores);
    
    if (categories.length === 0) {
      return this.getDefaultScore();
    }

    const maintainability = metricScores['Maintainability']?.score || 100;
    const readability = metricScores['Readability']?.score || 100;
    const complexity = metricScores['Complexity']?.score || 100;
    const reliability = metricScores['Reliability']?.score || 100;
    const codeHygiene = metricScores['Code Hygiene']?.score || 100;

    // Weighted overall score
    const overall = Math.round(
      (maintainability * 0.3 + 
       readability * 0.2 + 
       complexity * 0.2 + 
       reliability * 0.2 + 
       codeHygiene * 0.1)
    );

    return {
      overall,
      maintainability: Math.round(maintainability),
      readability: Math.round(readability),
      complexity: Math.round(complexity),
      security: Math.round(reliability), // Using reliability as security proxy
      breakdown: metricScores
    };
  }

  private getDefaultScore(): QualityScore {
    return {
      overall: 100,
      maintainability: 100,
      readability: 100,
      complexity: 100,
      security: 100,
      breakdown: {}
    };
  }

  private getCategoryDescription(category: string): string {
    const descriptions: { [key: string]: string } = {
      'Maintainability': 'How easy the code is to modify and extend',
      'Readability': 'How easy the code is to read and understand',
      'Complexity': 'How complex the code structure is',
      'Reliability': 'How robust the code is against errors',
      'Code Hygiene': 'How clean and well-organized the code is'
    };
    return descriptions[category] || 'Code quality metric';
  }
}