import { Command } from 'commander';
import * as path from 'path';
import chalk from 'chalk';
import { SecurityScanner } from './scanner';
import { Reporter } from './reporter';
import { ScanOptions } from './types';

const program = new Command();

program
  .name('bugnitor')
  .description('AI-era security scanner that detects vulnerabilities and exposed secrets in codebases')
  .version('1.0.0');

program
  .command('scan')
  .description('Comprehensive security analysis of entire repository including code, dependencies, and CI/CD')
  .argument('[path]', 'Path to scan (defaults to current directory)', '.')
  .option('-e, --exclude <patterns...>', 'Exclude patterns (glob format)')
  .option('-i, --include <patterns...>', 'Include patterns (glob format)')
  .option('--secrets-only', 'Only scan for exposed secrets and credentials')
  .option('--vulnerabilities-only', 'Only scan for code vulnerabilities')
  .option('--ai-vulnerabilities', 'Focus on AI-assistant generated vulnerability patterns')
  .option('--dependencies-only', 'Only scan dependencies for known vulnerabilities')
  .option('--cicd-only', 'Only scan CI/CD configurations for security issues')
  .option('--min-severity <level>', 'Minimum severity level (low, medium, high, critical)', 'low')
  .option('-f, --format <format>', 'Output format (text, json, sarif)', 'text')
  .option('-o, --output <file>', 'Output file path')
  .option('--detailed', 'Show detailed file-by-file and folder-by-folder analysis')
  .option('--show-grade', 'Display security grade and recommendations')
  .option('--no-color', 'Disable colored output')
  .action(async (targetPath: string, options: any) => {
    try {
      if (options.noColor) {
        chalk.level = 0;
      }

      console.log(chalk.blue('🔍 Starting Bugnitor Intelligent Security Review...'));
      console.log(chalk.gray(`Target: ${path.resolve(targetPath)}`));
      console.log(chalk.gray('Analyzing: Code, Dependencies, CI/CD, Configuration\n'));

      const scanner = new SecurityScanner();
      const reporter = new Reporter();

      const scanOptions: ScanOptions = {
        path: path.resolve(targetPath),
        excludePatterns: options.exclude,
        includePatterns: options.include,
        secretsOnly: options.secretsOnly || options.dependenciesOnly || options.cicdOnly ? false : options.secretsOnly,
        vulnerabilitiesOnly: options.vulnerabilitiesOnly || options.dependenciesOnly || options.cicdOnly ? false : options.vulnerabilitiesOnly,
        minSeverity: options.minSeverity,
        outputFormat: options.format
      };

      const result = await scanner.scan(scanOptions);

      if (options.output || options.format !== 'text') {
        await reporter.saveReport(result, options.format, options.output);
      }

      if (options.format === 'text' && !options.output) {
        console.log('\n' + reporter.generateTextReport(result));
      }

      // Determine exit code based on severity and grade
      const exitCode = result.summary.critical > 0 ? 2 : 
                      result.summary.high > 0 ? 1 : 
                      result.securityGrade.overall === 'F' ? 1 : 0;
      
      console.log('\n' + chalk.gray('━'.repeat(80)));
      console.log(chalk.bold('🎯 Security Assessment Complete'));
      
      if (exitCode === 2) {
        console.log(chalk.red.bold('🚨 CRITICAL: Immediate action required! Critical vulnerabilities detected.'));
      } else if (exitCode === 1) {
        console.log(chalk.yellow.bold('⚠️  HIGH PRIORITY: Security improvements needed.'));
      } else if (result.summary.medium > 0 || result.summary.low > 0) {
        console.log(chalk.blue('🔧 Some security issues found. Consider addressing them.'));
      } else {
        console.log(chalk.green.bold('✅ Excellent! No critical security issues detected.'));
      }

      // Show grade summary
      const gradeColor = result.securityGrade.overall === 'A' ? chalk.green :
                        result.securityGrade.overall === 'B' ? chalk.blue :
                        result.securityGrade.overall === 'C' ? chalk.yellow :
                        result.securityGrade.overall === 'D' ? chalk.red :
                        chalk.red.bold;
      
      console.log(gradeColor(`🏆 Security Grade: ${result.securityGrade.overall} (${result.securityGrade.score}/100)`));
      
      if (result.nextSteps.length > 0) {
        console.log(chalk.gray(`📋 Next: ${result.nextSteps[0]}`));
      }

      process.exit(exitCode);

    } catch (error) {
      console.error(chalk.red('❌ Scan failed:'), error);
      process.exit(1);
    }
  });

program
  .command('patterns')
  .description('List all available security analysis capabilities')
  .action(() => {
    console.log(chalk.blue('🔍 Bugnitor Intelligent Security Analysis\n'));
    
    console.log(chalk.bold('🤖 AI-Generated Vulnerability Patterns:'));
    console.log('• Missing Authorization Checks on DELETE/Admin Operations');
    console.log('• Direct Database Queries with User Input');
    console.log('• Unsanitized CSV/File Processing');
    console.log('• Hardcoded Secrets from AI Examples');
    console.log('• Detailed Error Information Exposure');
    console.log('• Weak Cryptographic Algorithms from AI Suggestions');
    console.log('• Unvalidated Redirects');
    console.log('• Missing Input Validation on Endpoints');
    
    console.log(chalk.bold('\n🔐 Enhanced Secret Detection:'));
    console.log('• AWS Access Keys & Secret Keys (Context-Aware)');
    console.log('• GitHub Personal Access Tokens');
    console.log('• OpenAI API Keys');
    console.log('• Stripe API Keys');
    console.log('• Google API Keys');
    console.log('• Firebase Tokens');
    console.log('• JWT Signing Secrets');
    console.log('• SSH Private Keys');
    console.log('• Database Connection Strings with Credentials');
    console.log('• Slack & Discord Tokens');
    console.log('• Generic API Keys & Passwords with Context Analysis');
    
    console.log(chalk.bold('\n💉 Injection & Syntax Attacks:'));
    console.log('• SQL Injection (concatenation & interpolation)');
    console.log('• NoSQL Injection');
    console.log('• Cross-Site Scripting (XSS) - DOM & Stored');
    console.log('• Command Injection / Shell Injection');
    console.log('• Server-Side Template Injection');
    console.log('• Code Injection via eval()');
    
    console.log(chalk.bold('\n🔓 Broken Access & Authorization:'));
    console.log('• Missing Authorization Checks');
    console.log('• Insecure Direct Object References');
    console.log('• Privilege Escalation Vulnerabilities');
    
    console.log(chalk.bold('\n📦 Deserialization & Remote Code Execution:'));
    console.log('• Unsafe Deserialization (pickle, yaml, JSON)');
    console.log('• Log4Shell JNDI Lookup Attacks');
    console.log('• Object Injection Vulnerabilities');
    
    console.log(chalk.bold('\n📁 File, Path & Resource Manipulation:'));
    console.log('• Directory Traversal / Path Traversal');
    console.log('• Unrestricted File Upload');
    console.log('• Zip-Slip / Archive Traversal');
    
    console.log(chalk.bold('\n🧠 Memory & Language-Specific:'));
    console.log('• Buffer Overflow (C/C++)');
    console.log('• Format String Vulnerabilities');
    console.log('• Integer Overflow/Underflow');
    
    console.log(chalk.bold('\n🔑 Cryptography & Configuration:'));
    console.log('• Weak Cryptographic Algorithms (MD5, SHA1, DES)');
    console.log('• Insecure Random Number Generation');
    console.log('• Improper SSL/TLS Configuration');
    console.log('• Missing Encryption for Sensitive Data');
    
    console.log(chalk.bold('\n📚 Dependency & Supply-Chain:'));
    console.log('• Vulnerable Dependencies (Log4j, Lodash, etc.)');
    console.log('• Outdated Package Versions');
    console.log('• Suspicious Package Names');
    console.log('• Insecure Package Sources (HTTP)');
    
    console.log(chalk.bold('\n🔄 CI/CD & Infrastructure:'));
    console.log('• GitHub Actions Security Issues');
    console.log('• GitLab CI Configuration Problems');
    console.log('• Jenkins Pipeline Vulnerabilities');
    console.log('• Docker Security Misconfigurations');
    console.log('• Secrets in CI/CD Files');
    console.log('• Excessive Permissions');
    
    console.log(chalk.bold('\n🏆 Security Assessment:'));
    console.log('• Overall Security Grade (A-F)');
    console.log('• Category-based Scoring');
    console.log('• Confidence Scoring (0-100%)');
    console.log('• CWE & OWASP Mapping');
    console.log('• Impact Assessment');
    console.log('• Effort Estimation');
    console.log('• Intelligent Recommendations');
    console.log('• Next Steps Planning');
  });

export { program };