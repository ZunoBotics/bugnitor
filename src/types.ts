export interface SecurityFinding {
  type: 'injection' | 'broken_access' | 'sensitive_data' | 'deserialization' | 'file_path' | 'memory' | 'cryptography' | 'dependency' | 'cicd' | 'config';
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  file: string;
  line?: number;
  column?: number;
  code?: string;
  codeContext?: {
    before: string;
    after: string;
  };
  recommendation: string;
  confidence: number;
  cwe?: string;
  owasp?: string;
  impact: string;
  effort: 'low' | 'medium' | 'high';
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

export interface FileAnalysis {
  filePath: string;
  absolutePath: string;
  relativePath: string;
  size: number;
  findings: SecurityFinding[];
  linesOfCode: number;
  fileType: string;
  qualityScore?: QualityScore;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

export interface FolderAnalysis {
  folderPath: string;
  files: FileAnalysis[];
  subFolders: FolderAnalysis[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
    filesScanned: number;
    filesWithIssues: number;
  };
}

export interface SecurityGrade {
  overall: 'A' | 'B' | 'C' | 'D' | 'F';
  categories: {
    injection: 'A' | 'B' | 'C' | 'D' | 'F';
    access_control: 'A' | 'B' | 'C' | 'D' | 'F';
    sensitive_data: 'A' | 'B' | 'C' | 'D' | 'F';
    cryptography: 'A' | 'B' | 'C' | 'D' | 'F';
    dependencies: 'A' | 'B' | 'C' | 'D' | 'F';
    configuration: 'A' | 'B' | 'C' | 'D' | 'F';
  };
  score: number; // 0-100
  recommendations: string[];
}

export interface ScanResult {
  projectPath: string;
  scanTime: Date;
  findings: SecurityFinding[];
  fileAnalyses: FileAnalysis[];
  folderStructure: FolderAnalysis;
  securityGrade: SecurityGrade;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
    filesScanned: number;
    filesWithIssues: number;
    foldersScanned: number;
    byCategory: Record<string, number>;
    averageConfidence: number;
  };
  nextSteps: string[];
}

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  confidence: number;
  description: string;
}

export interface VulnerabilityRule {
  id: string;
  name: string;
  description: string;
  pattern: RegExp;
  severity: SecurityFinding['severity'];
  fileTypes: string[];
  recommendation: string;
}

export interface ScanOptions {
  path: string;
  excludePatterns?: string[];
  includePatterns?: string[];
  secretsOnly?: boolean;
  vulnerabilitiesOnly?: boolean;
  minSeverity?: SecurityFinding['severity'];
  outputFormat?: 'json' | 'text' | 'sarif';
}