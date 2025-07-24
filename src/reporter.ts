import * as fs from 'fs';
import * as path from 'path';
import { ScanResult, SecurityFinding, FileAnalysis, FolderAnalysis } from './types';
import chalk from 'chalk';

export class Reporter {
  generateTextReport(result: ScanResult): string {
    let report = '';
    
    report += chalk.bold.blue('🔍 Bugnitor Security Scan Report\n');
    report += chalk.gray('━'.repeat(80) + '\n\n');
    
    report += chalk.bold('📊 Project Analysis\n');
    report += chalk.gray(`Project Path: ${result.projectPath}\n`);
    report += chalk.gray(`Scan Time: ${result.scanTime.toISOString()}\n`);
    report += chalk.gray(`Files Scanned: ${result.summary.filesScanned}\n`);
    report += chalk.gray(`Files with Issues: ${result.summary.filesWithIssues}\n`);
    report += chalk.gray(`Folders Analyzed: ${result.summary.foldersScanned}\n\n`);
    
    report += chalk.bold('🎯 Security Summary\n');
    report += chalk.red(`  🔴 Critical: ${result.summary.critical}\n`);
    report += chalk.yellow(`  🟡 High: ${result.summary.high}\n`);
    report += chalk.blue(`  🔵 Medium: ${result.summary.medium}\n`);
    report += chalk.gray(`  ⚪ Low: ${result.summary.low}\n`);
    report += chalk.bold(`  📋 Total Issues: ${result.summary.total}\n`);
    report += chalk.gray(`  🎯 Average Confidence: ${Math.round(result.summary.averageConfidence * 100)}%\n\n`);

    // Security Grade
    report += chalk.bold('🏆 Security Grade\n');
    const gradeColor = this.getGradeColor(result.securityGrade.overall);
    report += gradeColor(`  Overall Grade: ${result.securityGrade.overall} (${result.securityGrade.score}/100)\n`);
    report += chalk.gray('  Category Breakdown:\n');
    report += chalk.gray(`    • Injection Security: ${result.securityGrade.categories.injection}\n`);
    report += chalk.gray(`    • Access Control: ${result.securityGrade.categories.access_control}\n`);
    report += chalk.gray(`    • Sensitive Data: ${result.securityGrade.categories.sensitive_data}\n`);
    report += chalk.gray(`    • Cryptography: ${result.securityGrade.categories.cryptography}\n`);
    report += chalk.gray(`    • Dependencies: ${result.securityGrade.categories.dependencies}\n`);
    report += chalk.gray(`    • Configuration: ${result.securityGrade.categories.configuration}\n\n`);

    if (result.findings.length === 0) {
      report += chalk.green('✅ No security issues found! Your codebase looks secure.\n');
      return report;
    }

    // Show folder structure with issues
    report += this.generateFolderStructureReport(result.folderStructure, 0);
    
    // Detailed file-by-file analysis
    report += chalk.bold('\n📂 Detailed File Analysis\n');
    report += chalk.gray('━'.repeat(80) + '\n');
    
    const filesWithIssues = result.fileAnalyses.filter(fa => fa.findings.length > 0);
    
    for (const fileAnalysis of filesWithIssues) {
      report += this.generateFileReport(fileAnalysis);
    }

    // Security Recommendations
    if (result.securityGrade.recommendations.length > 0) {
      report += chalk.bold('\n💡 Security Recommendations\n');
      report += chalk.gray('━'.repeat(80) + '\n');
      for (const recommendation of result.securityGrade.recommendations) {
        report += `${recommendation}\n`;
      }
    }

    // Next Steps
    if (result.nextSteps.length > 0) {
      report += chalk.bold('\n📋 Next Steps\n');
      report += chalk.gray('━'.repeat(80) + '\n');
      for (let i = 0; i < result.nextSteps.length; i++) {
        report += `${i + 1}. ${result.nextSteps[i]}\n`;
      }
    }

    // Category Summary
    report += chalk.bold('\n📊 Issues by Category\n');
    report += chalk.gray('━'.repeat(80) + '\n');
    const sortedCategories = Object.entries(result.summary.byCategory)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10);
    
    for (const [category, count] of sortedCategories) {
      report += chalk.gray(`  ${category}: ${count}\n`);
    }

    report += '\n' + chalk.gray('━'.repeat(80) + '\n');
    report += chalk.yellow('⚡ Powered by Bugnitor - AI-Era Security Scanner\n');
    report += chalk.gray('💡 Secure your code, protect your future!\n');
    
    return report;
  }

  private generateFolderStructureReport(folder: FolderAnalysis, depth: number): string {
    let report = '';
    const indent = '  '.repeat(depth);
    const folderName = depth === 0 ? 'Root' : path.basename(folder.folderPath);
    
    if (depth === 0) {
      report += chalk.bold('📁 Folder Structure & Issue Distribution\n');
      report += chalk.gray('━'.repeat(80) + '\n');
    }
    
    if (folder.summary.total > 0) {
      const issueColor = folder.summary.critical > 0 ? chalk.red : 
                        folder.summary.high > 0 ? chalk.yellow : 
                        folder.summary.medium > 0 ? chalk.blue : chalk.gray;
      
      report += `${indent}${issueColor('📁 ' + folderName)} `;
      report += chalk.gray(`(${folder.summary.filesScanned} files, ${folder.summary.total} issues)`);
      
      if (folder.summary.critical > 0) report += chalk.red(` 🔴${folder.summary.critical}`);
      if (folder.summary.high > 0) report += chalk.yellow(` 🟡${folder.summary.high}`);
      if (folder.summary.medium > 0) report += chalk.blue(` 🔵${folder.summary.medium}`);
      if (folder.summary.low > 0) report += chalk.gray(` ⚪${folder.summary.low}`);
      
      report += '\n';

      // Show files with issues in this folder
      const filesWithIssues = folder.files.filter(f => f.findings.length > 0);
      for (const file of filesWithIssues) {
        const fileIssueColor = file.summary.critical > 0 ? chalk.red : 
                              file.summary.high > 0 ? chalk.yellow : 
                              file.summary.medium > 0 ? chalk.blue : chalk.gray;
        
        report += `${indent}  ${fileIssueColor('📄 ' + path.basename(file.filePath))} `;
        report += chalk.gray(`(${file.summary.total} issues)`);
        
        if (file.summary.critical > 0) report += chalk.red(` 🔴${file.summary.critical}`);
        if (file.summary.high > 0) report += chalk.yellow(` 🟡${file.summary.high}`);
        if (file.summary.medium > 0) report += chalk.blue(` 🔵${file.summary.medium}`);
        if (file.summary.low > 0) report += chalk.gray(` ⚪${file.summary.low}`);
        
        report += '\n';
      }
    }
    
    // Recursively show subfolders
    for (const subFolder of folder.subFolders) {
      if (subFolder.summary.total > 0) {
        report += this.generateFolderStructureReport(subFolder, depth + 1);
      }
    }
    
    return report;
  }

  private generateFileReport(fileAnalysis: FileAnalysis): string {
    let report = '';
    
    report += chalk.bold.underline(`\n📄 ${fileAnalysis.relativePath}\n`);
    report += chalk.gray(`Path: ${fileAnalysis.absolutePath}\n`);
    report += chalk.gray(`Size: ${this.formatFileSize(fileAnalysis.size)} | `);
    report += chalk.gray(`Lines: ${fileAnalysis.linesOfCode} | `);
    report += chalk.gray(`Type: ${fileAnalysis.fileType}\n`);
    
    report += chalk.gray(`Issues: `);
    if (fileAnalysis.summary.critical > 0) report += chalk.red(`🔴 ${fileAnalysis.summary.critical} Critical `);
    if (fileAnalysis.summary.high > 0) report += chalk.yellow(`🟡 ${fileAnalysis.summary.high} High `);
    if (fileAnalysis.summary.medium > 0) report += chalk.blue(`🔵 ${fileAnalysis.summary.medium} Medium `);
    if (fileAnalysis.summary.low > 0) report += chalk.gray(`⚪ ${fileAnalysis.summary.low} Low `);
    report += '\n\n';
    
    // Group findings by type
    const secrets = fileAnalysis.findings.filter(f => f.type === 'sensitive_data');
    const vulnerabilities = fileAnalysis.findings.filter(f => f.type !== 'sensitive_data');
    
    if (secrets.length > 0) {
      report += chalk.bold('🔐 Exposed Secrets:\n');
      for (const finding of secrets) {
        report += this.generateFindingReport(finding);
      }
    }
    
    if (vulnerabilities.length > 0) {
      report += chalk.bold('⚠️  Security Vulnerabilities:\n');
      for (const finding of vulnerabilities) {
        report += this.generateFindingReport(finding);
      }
    }
    
    return report;
  }

  private generateFindingReport(finding: SecurityFinding): string {
    let report = '';
    const severityColor = this.getSeverityColor(finding.severity);
    const typeIcon = this.getTypeIcon(finding.type);
    
    report += `\n  ${typeIcon} ${severityColor(finding.title)} [${finding.severity.toUpperCase()}]\n`;
    report += `     ${chalk.gray('Category:')} ${finding.category}\n`;
    report += `     ${chalk.gray('Description:')} ${finding.description}\n`;
    report += `     ${chalk.gray('Location:')} Line ${finding.line}, Column ${finding.column}\n`;
    report += `     ${chalk.gray('Code:')} ${chalk.cyan(finding.code)}\n`;
    
    if (finding.codeContext) {
      if (finding.codeContext.before) {
        report += `     ${chalk.gray('Before:')} ${chalk.dim(finding.codeContext.before)}\n`;
      }
      if (finding.codeContext.after) {
        report += `     ${chalk.gray('After:')} ${chalk.dim(finding.codeContext.after)}\n`;
      }
    }
    
    report += `     ${chalk.gray('Fix:')} ${finding.recommendation}\n`;
    report += `     ${chalk.gray('Impact:')} ${finding.impact}\n`;
    report += `     ${chalk.gray('Effort:')} ${finding.effort}\n`;
    
    if (finding.confidence) {
      report += `     ${chalk.gray('Confidence:')} ${Math.round(finding.confidence * 100)}%\n`;
    }
    
    if (finding.cwe) {
      report += `     ${chalk.gray('CWE:')} ${finding.cwe}\n`;
    }
    
    if (finding.owasp) {
      report += `     ${chalk.gray('OWASP:')} ${finding.owasp}\n`;
    }
    
    return report;
  }

  private getTypeIcon(type: string): string {
    const icons: Record<string, string> = {
      injection: '💉',
      broken_access: '🔓',
      sensitive_data: '🔐',
      deserialization: '📦',
      file_path: '📁',
      memory: '🧠',
      cryptography: '🔑',
      dependency: '📚',
      cicd: '🔄',
      config: '⚙️'
    };
    return icons[type] || '⚠️';
  }

  private getGradeColor(grade: string) {
    switch (grade) {
      case 'A': return chalk.green.bold;
      case 'B': return chalk.blue.bold;
      case 'C': return chalk.yellow.bold;
      case 'D': return chalk.red.bold;
      case 'F': return chalk.red.bold.underline;
      default: return chalk.gray;
    }
  }

  private formatFileSize(bytes: number): string {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + ' KB';
    return Math.round(bytes / (1024 * 1024)) + ' MB';
  }

  generateJsonReport(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }

  generateSarifReport(result: ScanResult): string {
    const sarif = {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'Bugnitor',
            version: '1.0.0',
            informationUri: 'https://github.com/bugnitor/bugnitor',
            rules: this.generateSarifRules(result.findings)
          }
        },
        results: result.findings.map(finding => ({
          ruleId: this.generateRuleId(finding),
          message: {
            text: finding.description
          },
          level: this.mapSeverityToSarifLevel(finding.severity),
          locations: [{
            physicalLocation: {
              artifactLocation: {
                uri: finding.file
              },
              region: {
                startLine: finding.line || 1,
                startColumn: finding.column || 1
              }
            }
          }]
        }))
      }]
    };

    return JSON.stringify(sarif, null, 2);
  }

  async saveReport(result: ScanResult, format: 'json' | 'text' | 'sarif', outputPath?: string): Promise<void> {
    let content: string;
    let extension: string;

    switch (format) {
      case 'json':
        content = this.generateJsonReport(result);
        extension = 'json';
        break;
      case 'sarif':
        content = this.generateSarifReport(result);
        extension = 'sarif';
        break;
      default:
        content = this.generateTextReport(result);
        extension = 'txt';
    }

    if (outputPath) {
      fs.writeFileSync(outputPath, content);
    } else {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `bugnitor-report-${timestamp}.${extension}`;
      fs.writeFileSync(filename, content);
      console.log(chalk.green(`Report saved to: ${filename}`));
    }
  }

  private groupFindingsByFile(findings: SecurityFinding[]): Record<string, SecurityFinding[]> {
    const grouped: Record<string, SecurityFinding[]> = {};
    
    for (const finding of findings) {
      if (!grouped[finding.file]) {
        grouped[finding.file] = [];
      }
      grouped[finding.file].push(finding);
    }
    
    return grouped;
  }

  private getSeverityColor(severity: SecurityFinding['severity']) {
    switch (severity) {
      case 'critical': return chalk.red.bold;
      case 'high': return chalk.red;
      case 'medium': return chalk.yellow;
      case 'low': return chalk.blue;
      default: return chalk.gray;
    }
  }

  private generateRuleId(finding: SecurityFinding): string {
    return finding.title.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
  }

  private generateSarifRules(findings: SecurityFinding[]) {
    const uniqueRules = new Map();
    
    for (const finding of findings) {
      const ruleId = this.generateRuleId(finding);
      if (!uniqueRules.has(ruleId)) {
        uniqueRules.set(ruleId, {
          id: ruleId,
          name: finding.title,
          shortDescription: {
            text: finding.title
          },
          fullDescription: {
            text: finding.description
          },
          help: {
            text: finding.recommendation
          },
          defaultConfiguration: {
            level: this.mapSeverityToSarifLevel(finding.severity)
          }
        });
      }
    }

    return Array.from(uniqueRules.values());
  }

  private mapSeverityToSarifLevel(severity: SecurityFinding['severity']): string {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'note';
      default:
        return 'info';
    }
  }
}