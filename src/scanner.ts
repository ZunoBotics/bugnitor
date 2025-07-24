import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import micromatch from 'micromatch';
import { SecurityFinding, ScanResult, ScanOptions, FileAnalysis, FolderAnalysis } from './types';
import { detectSecrets } from './secrets';
import { EnhancedSecretDetector } from './enhanced-secrets';
import { DangerousAPIDetector } from './dangerous-api-detector';
import { CodeQualityAnalyzer } from './code-quality-analyzer';
import { AIVulnerabilityDetector } from './ai-vulnerability-detector';
import { checkVulnerabilities } from './vulnerabilities';
import { checkAdvancedVulnerabilities } from './advanced-vulnerabilities';
import { DependencyAnalyzer } from './dependency-analyzer';
import { CICDAnalyzer } from './cicd-analyzer';
import { SecurityGrader } from './security-grader';

export class SecurityScanner {
  private defaultExcludePatterns = [
    'node_modules/**',
    '.git/**',
    'dist/**',
    'build/**',
    '*.min.js',
    '*.map',
    '.env.example',
    'package-lock.json',
    'yarn.lock',
    '*.log'
  ];

  private dependencyAnalyzer = new DependencyAnalyzer();
  private cicdAnalyzer = new CICDAnalyzer();
  private securityGrader = new SecurityGrader();
  private enhancedSecretDetector = new EnhancedSecretDetector();
  private dangerousAPIDetector = new DangerousAPIDetector();
  private codeQualityAnalyzer = new CodeQualityAnalyzer();
  private aiVulnerabilityDetector = new AIVulnerabilityDetector();

  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }

  private getColumnNumber(content: string, index: number): number {
    const lines = content.substring(0, index).split('\n');
    return lines[lines.length - 1].length + 1;
  }

  async scan(options: ScanOptions): Promise<ScanResult> {
    const findings: SecurityFinding[] = [];
    const fileAnalyses: FileAnalysis[] = [];
    const excludePatterns = [...this.defaultExcludePatterns, ...(options.excludePatterns || [])];
    
    const pattern = options.includePatterns?.length 
      ? `{${options.includePatterns.join(',')}}`
      : '**/*';

    const files = await glob(pattern, {
      cwd: options.path,
      absolute: true,
      ignore: excludePatterns,
      dot: false
    });

    console.log(`\n📊 Scanning ${files.length} files...`);
    let processedFiles = 0;

    for (const file of files) {
      try {
        const stats = fs.statSync(file);
        if (!stats.isFile()) continue;

        // Skip very large files (over 10MB) to avoid performance issues
        const maxFileSize = 10 * 1024 * 1024; // 10MB
        if (stats.size > maxFileSize) {
          console.warn(`\nSkipping large file: ${path.relative(options.path, file)} (${Math.round(stats.size / 1024 / 1024)}MB)`);
          continue;
        }

        // Skip binary files that shouldn't contain secrets
        const fileExtension = path.extname(file).toLowerCase();
        const binaryExtensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.pdf', '.zip', '.exe', '.dll', '.so', '.dylib', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.avi', '.mov'];
        
        if (binaryExtensions.includes(fileExtension)) {
          continue;
        }

        processedFiles++;
        
        // Check if file is binary by reading first few bytes
        const buffer = fs.readFileSync(file);
        if (this.isBinaryFile(buffer, file)) {
          continue;
        }

        const content = buffer.toString('utf-8');
        const relativePath = path.relative(options.path, file);
        const absolutePath = path.resolve(file);
        
        // Show progress
        if (processedFiles % 10 === 0 || processedFiles === files.length) {
          process.stdout.write(`\r📁 Processed: ${processedFiles}/${files.length} files`);
        }

        const fileFindings: SecurityFinding[] = [];

        if (!options.vulnerabilitiesOnly) {
          const secretFindings = this.scanForSecrets(content, relativePath, absolutePath);
          const enhancedSecretFindings = this.scanForEnhancedSecrets(content, relativePath, absolutePath);
          fileFindings.push(...secretFindings);
          fileFindings.push(...enhancedSecretFindings);
        }

        if (!options.secretsOnly) {
          const vulnerabilityFindings = this.scanForVulnerabilities(content, relativePath, absolutePath);
          const advancedVulnFindings = this.scanForAdvancedVulnerabilities(content, relativePath, absolutePath);
          const dangerousAPIFindings = this.scanForDangerousAPIs(content, relativePath, absolutePath);
          const aiVulnFindings = this.scanForAIVulnerabilities(content, relativePath, absolutePath);
          fileFindings.push(...vulnerabilityFindings);
          fileFindings.push(...advancedVulnFindings);
          fileFindings.push(...dangerousAPIFindings);
          fileFindings.push(...aiVulnFindings);
        }

        // Analyze code quality
        const qualityAnalysis = this.codeQualityAnalyzer.analyzeCodeQuality(
          content, 
          relativePath, 
          content.split('\n').length
        );
        fileFindings.push(...qualityAnalysis.findings);

        // Create file analysis
        const fileAnalysis: FileAnalysis = {
          filePath: relativePath,
          absolutePath: absolutePath,
          relativePath: relativePath,
          size: stats.size,
          findings: fileFindings,
          linesOfCode: content.split('\n').length,
          fileType: path.extname(file).substring(1) || 'unknown',
          qualityScore: qualityAnalysis.qualityScore,
          summary: this.generateSummary(fileFindings)
        };

        fileAnalyses.push(fileAnalysis);
        findings.push(...fileFindings);

      } catch (error) {
        console.warn(`\nWarning: Could not scan file ${file}: ${error}`);
      }
    }

    console.log('\n'); // New line after progress

    // Analyze dependencies
    console.log('🔍 Analyzing dependencies...');
    const dependencyResult = await this.dependencyAnalyzer.analyzeDependencies(options.path);
    findings.push(...dependencyResult.findings);

    // Analyze CI/CD configurations
    console.log('🔍 Analyzing CI/CD configurations...');
    const cicdResult = await this.cicdAnalyzer.analyzeCICD(options.path);
    findings.push(...cicdResult.findings);

    const filteredFindings = this.filterBySeverity(findings, options.minSeverity);
    const filteredFileAnalyses = fileAnalyses.map(fa => ({
      ...fa,
      findings: this.filterBySeverity(fa.findings, options.minSeverity),
      summary: this.generateSummary(this.filterBySeverity(fa.findings, options.minSeverity))
    }));

    const folderStructure = this.buildFolderStructure(filteredFileAnalyses, options.path);
    
    // Calculate security grade
    console.log('📊 Calculating security grade...');
    const securityGrade = this.securityGrader.calculateSecurityGrade(filteredFindings, fileAnalyses.length);
    const nextSteps = this.securityGrader.generateNextSteps(filteredFindings, securityGrade);

    return {
      projectPath: options.path,
      scanTime: new Date(),
      findings: filteredFindings,
      fileAnalyses: filteredFileAnalyses,
      folderStructure,
      securityGrade,
      summary: {
        ...this.generateSummary(filteredFindings),
        filesScanned: fileAnalyses.length,
        filesWithIssues: filteredFileAnalyses.filter(fa => fa.findings.length > 0).length,
        foldersScanned: this.countFolders(folderStructure),
        byCategory: this.generateCategorySummary(filteredFindings),
        averageConfidence: this.calculateAverageConfidence(filteredFindings)
      },
      nextSteps
    };
  }

  private scanForSecrets(content: string, filename: string, absolutePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const results = detectSecrets(content, filename);

    for (const result of results) {
      for (const match of result.matches) {
        const line = this.getLineNumber(content, match.index || 0);
        const column = this.getColumnNumber(content, match.index || 0);
        const codeContext = this.getCodeContext(content, match.index || 0);

        // Calculate context-aware confidence
        const contextAwareConfidence = this.calculateContextAwareConfidence(
          result.pattern.confidence,
          codeContext.matchedCode,
          codeContext.contextBefore,
          codeContext.contextAfter,
          filename
        );

        // Skip findings with very low confidence
        if (contextAwareConfidence < 0.5) continue;

        findings.push({
          type: 'sensitive_data',
          category: 'Exposed Secrets',
          severity: contextAwareConfidence > 0.8 ? 'critical' : 'high',
          title: result.pattern.name,
          description: result.pattern.description,
          file: filename,
          line,
          column,
          code: codeContext.matchedCode,
          codeContext: {
            before: codeContext.contextBefore,
            after: codeContext.contextAfter
          },
          recommendation: 'Remove hardcoded secrets and use environment variables or secure configuration management',
          confidence: contextAwareConfidence,
          cwe: 'CWE-798',
          owasp: 'A02:2021 – Cryptographic Failures',
          impact: 'Credential compromise, unauthorized access',
          effort: 'low'
        });
      }
    }

    return findings;
  }

  private scanForEnhancedSecrets(content: string, filename: string, absolutePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const results = this.enhancedSecretDetector.detectSecrets(content, filename);

    for (const result of results) {
      for (const match of result.matches) {
        const line = this.getLineNumber(content, match.match.index || 0);
        const column = this.getColumnNumber(content, match.match.index || 0);
        const codeContext = this.getCodeContext(content, match.match.index || 0);

        findings.push({
          type: 'sensitive_data',
          category: result.pattern.name,
          severity: result.pattern.severity,
          title: result.pattern.name,
          description: result.pattern.description,
          file: filename,
          line,
          column,
          code: codeContext.matchedCode,
          codeContext: {
            before: codeContext.contextBefore,
            after: codeContext.contextAfter
          },
          recommendation: result.pattern.remediation.description,
          confidence: match.confidence,
          cwe: result.pattern.cwe,
          owasp: result.pattern.owasp,
          impact: 'Credential compromise, unauthorized access',
          effort: result.pattern.remediation.effort
        });
      }
    }

    return findings;
  }

  private scanForDangerousAPIs(content: string, filename: string, absolutePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const results = this.dangerousAPIDetector.detectDangerousAPIs(content, filename);

    for (const result of results) {
      for (const match of result.matches) {
        const line = this.getLineNumber(content, match.match.index || 0);
        const column = this.getColumnNumber(content, match.match.index || 0);
        const codeContext = this.getCodeContext(content, match.match.index || 0);

        findings.push({
          type: 'injection',
          category: result.pattern.category,
          severity: result.pattern.severity,
          title: result.pattern.name,
          description: result.pattern.description,
          file: filename,
          line,
          column,
          code: codeContext.matchedCode,
          codeContext: {
            before: codeContext.contextBefore,
            after: codeContext.contextAfter
          },
          recommendation: result.pattern.remediation.description,
          confidence: match.confidence,
          cwe: result.pattern.cwe,
          owasp: result.pattern.owasp,
          impact: result.pattern.impact,
          effort: result.pattern.remediation.effort
        });
      }
    }

    return findings;
  }

  private scanForAIVulnerabilities(content: string, filename: string, absolutePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const results = this.aiVulnerabilityDetector.detectAIVulnerabilities(content, filename);

    for (const result of results) {
      for (const match of result.matches) {
        const line = this.getLineNumber(content, match.match.index || 0);
        const column = this.getColumnNumber(content, match.match.index || 0);
        const codeContext = this.getCodeContext(content, match.match.index || 0);

        findings.push({
          type: 'injection',
          category: `AI-Generated: ${result.pattern.category}`,
          severity: result.pattern.severity,
          title: `🤖 ${result.pattern.name}`,
          description: `${result.pattern.description} | AI Context: ${result.pattern.aiContext}`,
          file: filename,
          line,
          column,
          code: codeContext.matchedCode,
          codeContext: {
            before: codeContext.contextBefore,
            after: codeContext.contextAfter
          },
          recommendation: result.pattern.remediation.description,
          confidence: match.confidence,
          cwe: result.pattern.cwe,
          owasp: result.pattern.owasp,
          impact: result.pattern.impact,
          effort: result.pattern.remediation.effort
        });
      }
    }

    return findings;
  }

  private scanForVulnerabilities(content: string, filename: string, absolutePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const results = checkVulnerabilities(content, filename);

    for (const result of results) {
      for (const match of result.matches) {
        const line = this.getLineNumber(content, match.index || 0);
        const column = this.getColumnNumber(content, match.index || 0);
        const codeContext = this.getCodeContext(content, match.index || 0);

        findings.push({
          type: 'config',
          category: 'Legacy Vulnerability',
          severity: result.rule.severity,
          title: result.rule.name,
          description: result.rule.description,
          file: filename,
          line,
          column,
          code: codeContext.matchedCode,
          codeContext: {
            before: codeContext.contextBefore,
            after: codeContext.contextAfter
          },
          recommendation: result.rule.recommendation,
          confidence: 0.8,
          impact: 'Security vulnerability',
          effort: 'medium'
        });
      }
    }

    return findings;
  }

  private scanForAdvancedVulnerabilities(content: string, filename: string, absolutePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const results = checkAdvancedVulnerabilities(content, filename);

    for (const result of results) {
      for (const match of result.matches) {
        const line = this.getLineNumber(content, match.index || 0);
        const column = this.getColumnNumber(content, match.index || 0);
        const codeContext = this.getCodeContext(content, match.index || 0);

        findings.push({
          type: result.rule.type,
          category: result.rule.category,
          severity: result.rule.severity,
          title: result.rule.name,
          description: result.rule.description,
          file: filename,
          line,
          column,
          code: codeContext.matchedCode,
          codeContext: {
            before: codeContext.contextBefore,
            after: codeContext.contextAfter
          },
          recommendation: result.rule.recommendation,
          confidence: result.rule.confidence,
          cwe: result.rule.cwe,
          owasp: result.rule.owasp,
          impact: result.rule.impact,
          effort: result.rule.effort
        });
      }
    }

    return findings;
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

  private buildFolderStructure(fileAnalyses: FileAnalysis[], basePath: string): FolderAnalysis {
    const folderMap = new Map<string, FolderAnalysis>();
    
    // Initialize root folder
    const rootFolder: FolderAnalysis = {
      folderPath: basePath,
      files: [],
      subFolders: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0, filesScanned: 0, filesWithIssues: 0 }
    };
    folderMap.set(basePath, rootFolder);

    // Process each file
    for (const fileAnalysis of fileAnalyses) {
      const filePath = path.resolve(basePath, fileAnalysis.relativePath);
      const folderPath = path.dirname(filePath);
      
      // Create folder structure if it doesn't exist
      this.ensureFolderExists(folderMap, folderPath, basePath);
      
      // Add file to its folder
      const folder = folderMap.get(folderPath)!;
      folder.files.push(fileAnalysis);
      
      // Update folder statistics
      this.updateFolderSummary(folder, fileAnalysis);
    }

    // Build folder hierarchy
    this.buildFolderHierarchy(folderMap, basePath);
    
    return rootFolder;
  }

  private ensureFolderExists(folderMap: Map<string, FolderAnalysis>, folderPath: string, basePath: string): void {
    if (folderMap.has(folderPath)) return;

    const folder: FolderAnalysis = {
      folderPath,
      files: [],
      subFolders: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0, filesScanned: 0, filesWithIssues: 0 }
    };
    
    folderMap.set(folderPath, folder);
    
    // Recursively create parent folders
    const parentPath = path.dirname(folderPath);
    if (parentPath !== folderPath && parentPath.startsWith(basePath)) {
      this.ensureFolderExists(folderMap, parentPath, basePath);
    }
  }

  private buildFolderHierarchy(folderMap: Map<string, FolderAnalysis>, basePath: string): void {
    for (const [folderPath, folder] of folderMap) {
      if (folderPath === basePath) continue;
      
      const parentPath = path.dirname(folderPath);
      const parent = folderMap.get(parentPath);
      
      if (parent && !parent.subFolders.includes(folder)) {
        parent.subFolders.push(folder);
        
        // Update parent summary with child folder data
        parent.summary.critical += folder.summary.critical;
        parent.summary.high += folder.summary.high;
        parent.summary.medium += folder.summary.medium;
        parent.summary.low += folder.summary.low;
        parent.summary.total += folder.summary.total;
        parent.summary.filesScanned += folder.summary.filesScanned;
        parent.summary.filesWithIssues += folder.summary.filesWithIssues;
      }
    }
  }

  private updateFolderSummary(folder: FolderAnalysis, fileAnalysis: FileAnalysis): void {
    folder.summary.filesScanned++;
    if (fileAnalysis.findings.length > 0) {
      folder.summary.filesWithIssues++;
    }
    
    folder.summary.critical += fileAnalysis.summary.critical;
    folder.summary.high += fileAnalysis.summary.high;
    folder.summary.medium += fileAnalysis.summary.medium;
    folder.summary.low += fileAnalysis.summary.low;
    folder.summary.total += fileAnalysis.summary.total;
  }

  private countFolders(folder: FolderAnalysis): number {
    let count = 1;
    for (const subFolder of folder.subFolders) {
      count += this.countFolders(subFolder);
    }
    return count;
  }

  private filterBySeverity(findings: SecurityFinding[], minSeverity?: SecurityFinding['severity']): SecurityFinding[] {
    if (!minSeverity) return findings;

    const severityLevels = { low: 0, medium: 1, high: 2, critical: 3 };
    const minLevel = severityLevels[minSeverity];

    return findings.filter(finding => severityLevels[finding.severity] >= minLevel);
  }

  private generateSummary(findings: SecurityFinding[]) {
    const summary = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
    
    for (const finding of findings) {
      summary[finding.severity]++;
    }

    return summary;
  }

  private generateCategorySummary(findings: SecurityFinding[]): Record<string, number> {
    const categorySummary: Record<string, number> = {};
    
    for (const finding of findings) {
      const category = finding.category || finding.type;
      categorySummary[category] = (categorySummary[category] || 0) + 1;
    }

    return categorySummary;
  }

  private calculateAverageConfidence(findings: SecurityFinding[]): number {
    if (findings.length === 0) return 0;
    
    const totalConfidence = findings.reduce((sum, finding) => sum + finding.confidence, 0);
    return Math.round((totalConfidence / findings.length) * 100) / 100;
  }

  private isBinaryFile(buffer: Buffer, filename: string): boolean {
    // Check for common binary file signatures
    const signatures = [
      [0xFF, 0xD8, 0xFF], // JPEG
      [0x89, 0x50, 0x4E, 0x47], // PNG
      [0x47, 0x49, 0x46], // GIF
      [0x25, 0x50, 0x44, 0x46], // PDF
      [0x50, 0x4B], // ZIP/Office files
      [0x4D, 0x5A] // Windows executable
    ];

    // Check file signatures
    for (const sig of signatures) {
      if (buffer.length >= sig.length) {
        let matches = true;
        for (let i = 0; i < sig.length; i++) {
          if (buffer[i] !== sig[i]) {
            matches = false;
            break;
          }
        }
        if (matches) return true;
      }
    }

    // Check for high percentage of non-printable characters in first 1KB
    const sampleSize = Math.min(1024, buffer.length);
    let nonPrintableCount = 0;
    
    for (let i = 0; i < sampleSize; i++) {
      const byte = buffer[i];
      // Count bytes that are not printable ASCII or common whitespace
      if (byte < 32 && byte !== 9 && byte !== 10 && byte !== 13) {
        nonPrintableCount++;
      } else if (byte > 126) {
        nonPrintableCount++;
      }
    }
    
    // If more than 30% non-printable, likely binary
    return (nonPrintableCount / sampleSize) > 0.3;
  }

  private calculateContextAwareConfidence(
    baseConfidence: number,
    matchedCode: string,
    contextBefore: string,
    contextAfter: string,
    filename: string
  ): number {
    let confidence = baseConfidence;

    // Reduce confidence for test files
    if (filename.includes('test') || filename.includes('spec') || filename.includes('mock')) {
      confidence *= 0.7;
    }

    // Reduce confidence for example/demo files
    if (filename.includes('example') || filename.includes('demo') || filename.includes('sample')) {
      confidence *= 0.6;
    }

    // Increase confidence if in config/environment files
    if (filename.includes('config') || filename.includes('.env') || filename.includes('settings')) {
      confidence *= 1.2;
    }

    // Look for context indicators that suggest it's a real secret
    const secretIndicators = ['api_key', 'secret', 'token', 'password', 'credential', 'auth'];
    const testIndicators = ['example', 'test', 'dummy', 'fake', 'mock', 'placeholder'];

    const fullContext = (contextBefore + ' ' + matchedCode + ' ' + contextAfter).toLowerCase();

    // Increase confidence if secret indicators are present
    for (const indicator of secretIndicators) {
      if (fullContext.includes(indicator)) {
        confidence *= 1.1;
        break;
      }
    }

    // Decrease confidence if test indicators are present
    for (const indicator of testIndicators) {
      if (fullContext.includes(indicator)) {
        confidence *= 0.5;
        break;
      }
    }

    // Reduce confidence for very short or very common patterns
    if (matchedCode.length < 10) {
      confidence *= 0.8;
    }

    // Check for common placeholder patterns
    if (/^[a-z]{1,3}$|^test|^example|^placeholder|^your-|^my-/.test(matchedCode.toLowerCase())) {
      confidence *= 0.3;
    }

    return Math.min(1.0, Math.max(0.0, confidence));
  }
}