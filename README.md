# 🤖 Bugnitor Security Scanner

**AI-Era Security Scanner: Intelligent automated security review agent specializing in AI-generated vulnerability patterns**

[![npm version](https://badge.fury.io/js/bugnitor-security-scanner.svg)](https://badge.fury.io/js/bugnitor-security-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js CI](https://github.com/ZunoBotics/bugnitor/workflows/Node.js%20CI/badge.svg)](https://github.com/ZunoBotics/bugnitor/actions)

## 🎯 Why Bugnitor?

In the AI-driven development era, traditional security scanners fall short. **Bugnitor** is the first security scanner specifically designed to detect vulnerabilities commonly introduced by AI coding assistants like GitHub Copilot, ChatGPT, Claude, and others.

### The AI Security Challenge

When developers use AI assistants, they often get functional code that works but contains security vulnerabilities:

- 🔓 **Missing Authorization Checks** - AI generates CRUD operations without access control
- 💉 **Injection Vulnerabilities** - AI uses string concatenation instead of parameterized queries  
- 🔐 **Hardcoded Secrets** - AI incorporates example credentials from training data
- ⚠️ **Missing Input Validation** - AI focuses on functionality, skips security validation
- 🔑 **Weak Cryptography** - AI suggests outdated algorithms from legacy examples

**Bugnitor solves this by understanding AI code generation patterns and detecting these specific vulnerability classes.**

## ✨ Key Features

### 🤖 AI-Specific Vulnerability Detection
- **Missing Authorization Checks** on DELETE/Admin operations
- **Direct Database Queries** with user input concatenation
- **Hardcoded Secrets** from AI examples and prompts
- **Unsanitized Input Processing** (CSV, JSON, file uploads)
- **Detailed Error Exposure** in catch blocks
- **Weak Cryptographic Algorithms** from outdated AI training data
- **Unvalidated Redirects** and missing input validation

### 🔐 Enhanced Secret Detection
- **Context-Aware Analysis** - Higher confidence for real secrets vs. test data
- **Advanced Pattern Matching** - Database URLs, JWT secrets, API keys
- **AI Training Data Detection** - Identifies secrets from AI examples
- **Binary File Exclusion** - Eliminates false positives in images/assets
- **Confidence Scoring** - Reduces noise with intelligent filtering

### 🛡️ Comprehensive Security Analysis
- **OWASP Top 10 Coverage** - All major vulnerability categories
- **CWE Mapping** - Industry-standard vulnerability classification
- **Dependency Analysis** - Vulnerable package detection
- **CI/CD Security** - GitHub Actions, GitLab CI, Docker analysis
- **Code Quality Scoring** - Maintainability and complexity analysis

### 📊 Intelligent Reporting
- **Security Grading** (A-F) with detailed breakdowns
- **File-by-file Analysis** with exact line numbers
- **Confidence Scoring** to prioritize real threats
- **Actionable Remediation** with code examples
- **Multiple Output Formats** (Text, JSON, SARIF)

## 🚀 Quick Start

### Installation

```bash
# Global installation (recommended)
npm install -g bugnitor-security-scanner

# Local installation
npm install --save-dev bugnitor-security-scanner
```

### Basic Usage

```bash
# Scan current directory
bugnitor scan

# Scan specific directory
bugnitor scan /path/to/project

# Focus on secrets only
bugnitor scan --secrets-only

# Focus on AI-generated vulnerabilities
bugnitor scan --ai-vulnerabilities

# High-severity issues only
bugnitor scan --min-severity high

# JSON output for CI/CD integration
bugnitor scan --format json --output security-report.json
```

## 📋 Command Reference

### Core Scanning Commands

```bash
# Basic project scan
bugnitor scan [path]

# Scan with specific focus
bugnitor scan --secrets-only              # Only secrets and credentials
bugnitor scan --vulnerabilities-only      # Only code vulnerabilities  
bugnitor scan --ai-vulnerabilities        # AI-specific patterns
bugnitor scan --dependencies-only         # Only dependency issues
bugnitor scan --cicd-only                 # Only CI/CD configurations

# Filtering and output
bugnitor scan --min-severity <level>       # critical, high, medium, low
bugnitor scan --format <format>            # text, json, sarif
bugnitor scan --output <file>              # Save to file
bugnitor scan --exclude <patterns...>      # Exclude file patterns
bugnitor scan --include <patterns...>      # Include file patterns

# Advanced options  
bugnitor scan --detailed                   # Detailed file analysis
bugnitor scan --show-grade                 # Display security grade
bugnitor scan --no-color                   # Disable colored output
```

### Information Commands

```bash
# List all detection capabilities
bugnitor patterns

# Show version information
bugnitor --version

# Show help
bugnitor --help
```

## 🎯 Specialized Scanning Modes

### 1. AI Vulnerability Focus
```bash
bugnitor scan --ai-vulnerabilities
```
Specifically targets vulnerabilities commonly introduced by AI coding assistants:
- Missing authorization on admin/delete routes
- SQL injection via string concatenation  
- Hardcoded credentials from AI examples
- Missing input validation on generated endpoints

### 2. Enhanced Secret Detection
```bash
bugnitor scan --secrets-only
```
Advanced secret detection with context analysis:
- AWS keys, GitHub tokens, API keys
- JWT signing secrets, database URLs
- Context-aware confidence scoring
- Reduced false positives

### 3. Comprehensive Security Audit
```bash
bugnitor scan --detailed --show-grade
```
Full security assessment including:
- All vulnerability categories
- Dependency analysis
- CI/CD security review
- Code quality metrics
- Security grading (A-F)

## 📊 Output Formats

### 1. Human-Readable Text (Default)
```bash
bugnitor scan
```
Colored, formatted output perfect for developers:
- Clear categorization by severity
- Exact file locations and line numbers
- Code context and remediation advice
- Security grade and next steps

### 2. JSON for Automation
```bash
bugnitor scan --format json --output results.json
```
Structured data for CI/CD integration:
```json
{
  "projectPath": "/path/to/project",
  "scanTime": "2024-01-15T10:30:00Z",
  "securityGrade": {
    "overall": "B",
    "score": 82
  },
  "findings": [
    {
      "type": "injection",
      "severity": "critical",
      "title": "Missing Authorization Check",
      "file": "routes/admin.js",
      "line": 15,
      "confidence": 0.95,
      "cwe": "CWE-862",
      "owasp": "A01:2021 – Broken Access Control"
    }
  ]
}
```

### 3. SARIF for Security Tools
```bash
bugnitor scan --format sarif --output results.sarif
```
Static Analysis Results Interchange Format for integration with:
- GitHub Security tab
- Azure DevOps
- SonarQube
- Other SARIF-compatible tools

## 🛠️ CI/CD Integration

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install Bugnitor
        run: npm install -g bugnitor-security-scanner
      
      - name: Run Security Scan
        run: |
          bugnitor scan --format json --output security-results.json
          bugnitor scan --min-severity high
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: security-results.json
```

### GitLab CI
```yaml
security_scan:
  stage: test
  image: node:18
  before_script:
    - npm install -g bugnitor-security-scanner
  script:
    - bugnitor scan --format json --output security-results.json
    - bugnitor scan --min-severity high
  artifacts:
    reports:
      junit: security-results.json
    expire_in: 1 week
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'npm install -g bugnitor-security-scanner'
                sh 'bugnitor scan --format json --output security-results.json'
                
                // Fail build on critical issues
                script {
                    def result = sh(
                        script: 'bugnitor scan --min-severity critical',
                        returnStatus: true
                    )
                    if (result != 0) {
                        error("Critical security vulnerabilities found!")
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-results.json'
                }
            }
        }
    }
}
```

## 🔍 Detection Capabilities

### 🤖 AI-Generated Vulnerability Patterns
- **Missing Authorization Checks** on DELETE/Admin Operations
- **Direct Database Queries** with User Input  
- **Unsanitized CSV/File Processing**
- **Hardcoded Secrets** from AI Examples
- **Detailed Error Information Exposure**
- **Weak Cryptographic Algorithms** from AI Suggestions
- **Unvalidated Redirects**
- **Missing Input Validation** on Endpoints

### 🔐 Enhanced Secret Detection
- **AWS Access Keys & Secret Keys** (Context-Aware)
- **GitHub Personal Access Tokens**
- **OpenAI API Keys**
- **Stripe API Keys**
- **Google API Keys**
- **Firebase Tokens**
- **JWT Signing Secrets**
- **SSH Private Keys**
- **Database Connection Strings** with Credentials
- **Slack & Discord Tokens**
- **Generic API Keys** with Context Analysis

### 💉 Injection & Syntax Attacks
- **SQL Injection** (concatenation & interpolation)
- **NoSQL Injection**
- **Cross-Site Scripting** (XSS) - DOM & Stored
- **Command Injection** / Shell Injection
- **Server-Side Template Injection**
- **Code Injection** via eval()

### 🔓 Broken Access & Authorization
- **Missing Authorization Checks**
- **Insecure Direct Object References**
- **Privilege Escalation Vulnerabilities**

### 📦 Deserialization & Remote Code Execution
- **Unsafe Deserialization** (pickle, yaml, JSON)
- **Log4Shell JNDI Lookup** Attacks
- **Object Injection Vulnerabilities**

### 📁 File, Path & Resource Manipulation
- **Directory Traversal** / Path Traversal
- **Unrestricted File Upload**
- **Zip-Slip** / Archive Traversal

### 🧠 Memory & Language-Specific
- **Buffer Overflow** (C/C++)
- **Format String Vulnerabilities**
- **Integer Overflow/Underflow**

### 🔑 Cryptography & Configuration
- **Weak Cryptographic Algorithms** (MD5, SHA1, DES)
- **Insecure Random Number Generation**
- **Improper SSL/TLS Configuration**
- **Missing Encryption** for Sensitive Data

### 📚 Dependency & Supply-Chain
- **Vulnerable Dependencies** (Log4j, Lodash, etc.)
- **Outdated Package Versions**
- **Suspicious Package Names**
- **Insecure Package Sources** (HTTP)

### 🔄 CI/CD & Infrastructure
- **GitHub Actions Security Issues**
- **GitLab CI Configuration Problems**
- **Jenkins Pipeline Vulnerabilities**
- **Docker Security Misconfigurations**
- **Secrets in CI/CD Files**
- **Excessive Permissions**

## 📈 Version History

### v3.1.0 (Latest) - AI-Era Security Scanner
**🤖 Major AI Vulnerability Detection Update**
- ✅ **NEW**: AI-specific vulnerability patterns for code generated by assistants
- ✅ **NEW**: Missing authorization detection on DELETE/Admin operations  
- ✅ **NEW**: Direct database query vulnerability detection
- ✅ **NEW**: Hardcoded secrets from AI examples detection
- ✅ **NEW**: Enhanced error exposure analysis
- ✅ **NEW**: AI context-aware confidence scoring
- ✅ **NEW**: `--ai-vulnerabilities` CLI flag
- ✅ **IMPROVED**: Pattern descriptions with AI context explanations
- ✅ **IMPROVED**: Detection accuracy for AI-generated code patterns

### v3.0.0 - Enhanced Security Analysis
**🔐 Major Security Enhancement Update**
- ✅ **NEW**: Enhanced secret detection with context analysis
- ✅ **NEW**: Dangerous API usage detection (eval, exec, etc.)
- ✅ **NEW**: Code quality and maintainability scoring
- ✅ **NEW**: AST-based analysis for deeper code understanding
- ✅ **NEW**: Binary file detection to reduce false positives
- ✅ **NEW**: Context-aware confidence scoring
- ✅ **IMPROVED**: Better cryptographic algorithm detection
- ✅ **IMPROVED**: Reduced false positives in test files

### v2.1.0 - Accuracy Improvements
**🎯 False Positive Reduction Update**
- ✅ **FIXED**: Binary file false positives (PNG, JPEG exclusion)
- ✅ **FIXED**: Cryptographic algorithm detection accuracy
- ✅ **FIXED**: AWS Secret Key pattern specificity
- ✅ **IMPROVED**: Context-aware confidence scoring
- ✅ **IMPROVED**: File size limits (10MB max) for performance

### v2.0.0 - Comprehensive Analysis
**🏆 Intelligent Security Review Update**
- ✅ **NEW**: Advanced vulnerability detection for OWASP Top 10
- ✅ **NEW**: Dependency analysis (npm, pip, maven, etc.)
- ✅ **NEW**: CI/CD security analysis (GitHub Actions, GitLab CI, Docker)
- ✅ **NEW**: Security grading system (A-F grades)
- ✅ **NEW**: Intelligence recommendations and next steps
- ✅ **NEW**: Multiple output formats (JSON, SARIF)

### v1.1.0 - Enhanced Reporting
**📊 Detailed Analysis Update**
- ✅ **NEW**: File-by-file and folder-by-folder analysis
- ✅ **NEW**: Exact file paths and line numbers
- ✅ **NEW**: Folder hierarchy breakdown
- ✅ **NEW**: Enhanced reporting with metadata

### v1.0.0 - Initial Release
**🚀 Core Security Scanner**
- ✅ Basic vulnerability detection patterns
- ✅ Secret detection for common API keys and tokens
- ✅ CLI interface with scan command
- ✅ Text output format
- ✅ File analysis with pattern matching

## 🏗️ Architecture

### Core Components

```
bugnitor-security-scanner/
├── src/
│   ├── scanner.ts              # Main scanning engine
│   ├── ai-vulnerability-detector.ts  # AI-specific patterns
│   ├── enhanced-secrets.ts     # Advanced secret detection
│   ├── dangerous-api-detector.ts # Unsafe API usage
│   ├── code-quality-analyzer.ts # Quality metrics
│   ├── advanced-vulnerabilities.ts # OWASP patterns
│   ├── dependency-analyzer.ts  # Package vulnerabilities
│   ├── cicd-analyzer.ts       # CI/CD security
│   ├── security-grader.ts     # Grading system
│   ├── reporter.ts            # Output formatting
│   ├── cli.ts                 # Command interface
│   └── types.ts               # Type definitions
├── bin/
│   └── bugnitor.js            # CLI entry point
└── dist/                      # Compiled JavaScript
```

### Detection Flow

1. **File Discovery** - Glob pattern matching with exclusion filters
2. **Binary Detection** - Skip binary files using file signatures
3. **Multi-Layer Analysis**:
   - AI-specific vulnerability patterns
   - Enhanced secret detection with context
   - Dangerous API usage analysis
   - Advanced vulnerability patterns (OWASP)
   - Code quality metrics
4. **Dependency Analysis** - Package vulnerability scanning
5. **CI/CD Analysis** - Configuration security review
6. **Confidence Scoring** - Context-aware accuracy calculation
7. **Security Grading** - A-F grade calculation
8. **Report Generation** - Multiple output formats

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Development Setup

```bash
# Clone the repository
git clone https://github.com/ZunoBotics/bugnitor.git
cd bugnitor

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test

# Run locally
node dist/index.js scan test-project
```

### Adding New Vulnerability Patterns

1. **Choose the appropriate detector file**:
   - `ai-vulnerability-detector.ts` - AI-specific patterns
   - `enhanced-secrets.ts` - Secret patterns
   - `dangerous-api-detector.ts` - API usage patterns
   - `advanced-vulnerabilities.ts` - General vulnerabilities

2. **Add your pattern**:
```typescript
{
  id: 'your-vulnerability-id',
  name: 'Descriptive Vulnerability Name',
  category: 'Vulnerability Category',
  description: 'What this vulnerability detects',
  patterns: [/your-regex-pattern/gi],
  severity: 'critical', // critical, high, medium, low
  confidence: 0.9,
  fileTypes: ['js', 'ts', 'py'],
  cwe: 'CWE-XXX',
  owasp: 'AXX:2021 – Category Name',
  impact: 'Description of impact',
  remediation: {
    description: 'How to fix this',
    effort: 'low', // low, medium, high
    codeExample: '// Example fix'
  }
}
```

3. **Test your pattern**:
```bash
# Create test file with vulnerability
echo 'your test code' > test-vuln.js

# Test detection
node dist/index.js scan test-vuln.js
```

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-detection`
3. Make your changes and add tests
4. Ensure all tests pass: `npm test`
5. Submit a pull request with detailed description

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- **NPM Package**: https://www.npmjs.com/package/bugnitor-security-scanner
- **GitHub Repository**: https://github.com/ZunoBotics/bugnitor
- **Issue Tracker**: https://github.com/ZunoBotics/bugnitor/issues
- **Documentation**: https://github.com/ZunoBotics/bugnitor/wiki

## 🙋 Support

### Getting Help

- 📖 **Documentation**: Check this README and the [Wiki](https://github.com/ZunoBotics/bugnitor/wiki)
- 🐛 **Bug Reports**: [Open an issue](https://github.com/ZunoBotics/bugnitor/issues/new?template=bug_report.md)
- 💡 **Feature Requests**: [Request a feature](https://github.com/ZunoBotics/bugnitor/issues/new?template=feature_request.md)
- 💬 **Discussions**: [Join the discussion](https://github.com/ZunoBotics/bugnitor/discussions)

### Common Issues

**Q: Too many false positives in my scan results?**
A: Use `--min-severity high` to focus on critical issues, or `--exclude test/**` to skip test files.

**Q: How do I integrate with my CI/CD pipeline?**
A: Use `--format json` for automation and check the exit code (0=success, 1=issues found, 2=critical issues).

**Q: The scanner is taking too long on large projects?**
A: Use `--include src/**` to focus on source code directories, or `--exclude node_modules/**` to skip dependencies.

**Q: How accurate are the vulnerability detections?**
A: Bugnitor uses confidence scoring. Focus on findings with >80% confidence for highest accuracy.

---

**⚡ Powered by Bugnitor - Secure your AI-generated code!**

*Made with ❤️ for the AI development era*