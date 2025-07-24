import * as fs from 'fs';
import * as path from 'path';
import { SecurityFinding } from './types';

export interface VulnerableDependency {
  name: string;
  version: string;
  vulnerability: {
    id: string;
    title: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    cwe: string;
    cvss: number;
    publishedDate: string;
  };
}

export interface DependencyAnalysisResult {
  findings: SecurityFinding[];
  vulnerableDependencies: VulnerableDependency[];
  outdatedDependencies: Array<{
    name: string;
    current: string;
    latest: string;
    age: number; // days
  }>;
}

// Known vulnerable packages (simplified - in production would use CVE database)
const knownVulnerabilities: Record<string, Array<{
  versionRange: string;
  vulnerability: VulnerableDependency['vulnerability'];
}>> = {
  'lodash': [
    {
      versionRange: '<4.17.12',
      vulnerability: {
        id: 'CVE-2019-10744',
        title: 'Prototype Pollution',
        description: 'Lodash versions prior to 4.17.12 are vulnerable to Prototype Pollution',
        severity: 'high',
        cwe: 'CWE-1321',
        cvss: 7.4,
        publishedDate: '2019-07-26'
      }
    }
  ],
  'log4j-core': [
    {
      versionRange: '>=2.0-beta9 <2.12.2',
      vulnerability: {
        id: 'CVE-2021-44228',
        title: 'Log4Shell Remote Code Execution',
        description: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP',
        severity: 'critical',
        cwe: 'CWE-917',
        cvss: 10.0,
        publishedDate: '2021-12-09'
      }
    }
  ],
  'serialize-javascript': [
    {
      versionRange: '<3.1.0',
      vulnerability: {
        id: 'CVE-2020-7660',
        title: 'Cross-site Scripting (XSS)',
        description: 'serialize-javascript prior to 3.1.0 allows remote attackers to inject XSS',
        severity: 'medium',
        cwe: 'CWE-79',
        cvss: 5.4,
        publishedDate: '2020-06-01'
      }
    }
  ],
  'axios': [
    {
      versionRange: '>=0.8.1 <0.21.1',
      vulnerability: {
        id: 'CVE-2020-28168',
        title: 'Server-Side Request Forgery (SSRF)',
        description: 'Axios NPM package contains a Server-Side Request Forgery (SSRF) vulnerability',
        severity: 'medium',
        cwe: 'CWE-918',
        cvss: 5.9,
        publishedDate: '2020-11-06'
      }
    }
  ],
  'express': [
    {
      versionRange: '<4.17.1',
      vulnerability: {
        id: 'CVE-2019-5413',
        title: 'Open Redirect',
        description: 'Express.js redirect() method vulnerable to open redirect',
        severity: 'medium',
        cwe: 'CWE-601',
        cvss: 4.3,
        publishedDate: '2019-04-26'
      }
    }
  ]
};

export class DependencyAnalyzer {
  async analyzeDependencies(projectPath: string): Promise<DependencyAnalysisResult> {
    const findings: SecurityFinding[] = [];
    const vulnerableDependencies: VulnerableDependency[] = [];
    const outdatedDependencies: DependencyAnalysisResult['outdatedDependencies'] = [];

    // Analyze package.json (Node.js)
    const packageJsonPath = path.join(projectPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      const result = await this.analyzePackageJson(packageJsonPath);
      findings.push(...result.findings);
      vulnerableDependencies.push(...result.vulnerableDependencies);
      outdatedDependencies.push(...result.outdatedDependencies);
    }

    // Analyze requirements.txt (Python)
    const requirementsPath = path.join(projectPath, 'requirements.txt');
    if (fs.existsSync(requirementsPath)) {
      const result = await this.analyzeRequirementsTxt(requirementsPath);
      findings.push(...result.findings);
    }

    // Analyze pom.xml (Java Maven)
    const pomXmlPath = path.join(projectPath, 'pom.xml');
    if (fs.existsSync(pomXmlPath)) {
      const result = await this.analyzePomXml(pomXmlPath);
      findings.push(...result.findings);
    }

    // Analyze Gemfile (Ruby)
    const gemfilePath = path.join(projectPath, 'Gemfile');
    if (fs.existsSync(gemfilePath)) {
      const result = await this.analyzeGemfile(gemfilePath);
      findings.push(...result.findings);
    }

    // Analyze go.mod (Go)
    const goModPath = path.join(projectPath, 'go.mod');
    if (fs.existsSync(goModPath)) {
      const result = await this.analyzeGoMod(goModPath);
      findings.push(...result.findings);
    }

    return {
      findings,
      vulnerableDependencies,
      outdatedDependencies
    };
  }

  private async analyzePackageJson(filePath: string): Promise<DependencyAnalysisResult> {
    const findings: SecurityFinding[] = [];
    const vulnerableDependencies: VulnerableDependency[] = [];
    const outdatedDependencies: DependencyAnalysisResult['outdatedDependencies'] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const packageJson = JSON.parse(content);

      // Check dependencies and devDependencies
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies
      };

      for (const [name, version] of Object.entries(allDeps)) {
        const versionStr = version as string;
        
        // Check for vulnerable versions
        if (knownVulnerabilities[name]) {
          for (const vuln of knownVulnerabilities[name]) {
            if (this.isVersionVulnerable(versionStr, vuln.versionRange)) {
              vulnerableDependencies.push({
                name,
                version: versionStr,
                vulnerability: vuln.vulnerability
              });

              findings.push({
                type: 'dependency',
                category: 'Vulnerable Dependency',
                severity: vuln.vulnerability.severity,
                title: `Vulnerable dependency: ${name}`,
                description: `${name}@${versionStr} has known vulnerability: ${vuln.vulnerability.title}`,
                file: path.basename(filePath),
                recommendation: `Update ${name} to a secure version to fix ${vuln.vulnerability.id}`,
                confidence: 0.95,
                cwe: vuln.vulnerability.cwe,
                impact: vuln.vulnerability.description,
                effort: 'low'
              });
            }
          }
        }

        // Check for potentially unsafe package patterns
        if (this.isSuspiciousPackage(name)) {
          findings.push({
            type: 'dependency',
            category: 'Suspicious Dependency',
            severity: 'medium',
            title: `Suspicious package name: ${name}`,
            description: `Package name "${name}" appears suspicious and may be a typosquatting attempt`,
            file: path.basename(filePath),
            recommendation: `Verify the package name and publisher. Consider using official packages.`,
            confidence: 0.6,
            impact: 'Potential malicious code execution',
            effort: 'low'
          });
        }
      }

      // Check for security-related configurations
      if (packageJson.scripts) {
        for (const [scriptName, scriptCommand] of Object.entries(packageJson.scripts)) {
          const command = scriptCommand as string;
          if (this.hasInsecureScriptCommand(command)) {
            findings.push({
              type: 'config',
              category: 'Insecure NPM Script',
              severity: 'medium',
              title: `Insecure script command: ${scriptName}`,
              description: `NPM script "${scriptName}" contains potentially insecure commands`,
              file: path.basename(filePath),
              code: `"${scriptName}": "${command}"`,
              recommendation: 'Review script commands for security implications. Avoid downloading and executing remote scripts.',
              confidence: 0.7,
              impact: 'Potential code execution during npm install',
              effort: 'low'
            });
          }
        }
      }

    } catch (error) {
      findings.push({
        type: 'config',
        category: 'Malformed Configuration',
        severity: 'low',
        title: 'Malformed package.json',
        description: `Cannot parse package.json: ${error}`,
        file: path.basename(filePath),
        recommendation: 'Fix JSON syntax errors in package.json',
        confidence: 0.9,
        impact: 'Build failures, dependency resolution issues',
        effort: 'low'
      });
    }

    return {
      findings,
      vulnerableDependencies,
      outdatedDependencies
    };
  }

  private async analyzeRequirementsTxt(filePath: string): Promise<DependencyAnalysisResult> {
    const findings: SecurityFinding[] = [];
    const vulnerableDependencies: VulnerableDependency[] = [];
    const outdatedDependencies: DependencyAnalysisResult['outdatedDependencies'] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));

      for (const line of lines) {
        // Check for insecure package sources
        if (line.includes('http://') && !line.includes('https://')) {
          findings.push({
            type: 'dependency',
            category: 'Insecure Package Source',
            severity: 'medium',
            title: 'HTTP package source',
            description: 'Package installed from insecure HTTP source',
            file: path.basename(filePath),
            code: line.trim(),
            recommendation: 'Use HTTPS sources for package installation',
            confidence: 0.8,
            impact: 'Man-in-the-middle attacks during package installation',
            effort: 'low'
          });
        }

        // Check for unpinned versions
        if (line.includes('>=') || line.includes('>') || line.includes('*')) {
          findings.push({
            type: 'dependency',
            category: 'Unpinned Dependency Version',
            severity: 'low',
            title: 'Unpinned dependency version',
            description: 'Dependency version not pinned, may lead to inconsistent builds',
            file: path.basename(filePath),
            code: line.trim(),
            recommendation: 'Pin dependency versions for reproducible builds',
            confidence: 0.6,
            impact: 'Build inconsistencies, potential breaking changes',
            effort: 'low'
          });
        }
      }

    } catch (error) {
      findings.push({
        type: 'config',
        category: 'File Access Error',
        severity: 'low',
        title: 'Cannot read requirements.txt',
        description: `Error reading requirements.txt: ${error}`,
        file: path.basename(filePath),
        recommendation: 'Ensure requirements.txt is accessible and properly formatted',
        confidence: 0.9,
        impact: 'Dependency analysis incomplete',
        effort: 'low'
      });
    }

    return {
      findings,
      vulnerableDependencies,
      outdatedDependencies
    };
  }

  private async analyzePomXml(filePath: string): Promise<DependencyAnalysisResult> {
    const findings: SecurityFinding[] = [];
    const vulnerableDependencies: VulnerableDependency[] = [];
    const outdatedDependencies: DependencyAnalysisResult['outdatedDependencies'] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');

      // Check for Log4j vulnerability
      if (content.includes('log4j-core') && !content.includes('2.17.0')) {
        findings.push({
          type: 'dependency',
          category: 'Critical Vulnerability',
          severity: 'critical',
          title: 'Log4Shell vulnerability (CVE-2021-44228)',
          description: 'Project uses vulnerable version of Log4j',
          file: path.basename(filePath),
          recommendation: 'Update Log4j to version 2.17.0 or later immediately',
          confidence: 0.9,
          cwe: 'CWE-917',
          impact: 'Remote code execution via JNDI injection',
          effort: 'low'
        });
      }

      // Check for insecure repositories
      if (content.includes('<repository>') && content.includes('http://')) {
        findings.push({
          type: 'config',
          category: 'Insecure Repository',
          severity: 'medium',
          title: 'Insecure Maven repository',
          description: 'Maven repository configured with HTTP instead of HTTPS',
          file: path.basename(filePath),
          recommendation: 'Use HTTPS for all Maven repositories',
          confidence: 0.8,
          impact: 'Man-in-the-middle attacks during dependency download',
          effort: 'low'
        });
      }

    } catch (error) {
      findings.push({
        type: 'config',
        category: 'File Access Error',
        severity: 'low',
        title: 'Cannot read pom.xml',
        description: `Error reading pom.xml: ${error}`,
        file: path.basename(filePath),
        recommendation: 'Ensure pom.xml is accessible and properly formatted',
        confidence: 0.9,
        impact: 'Dependency analysis incomplete',
        effort: 'low'
      });
    }

    return {
      findings,
      vulnerableDependencies,
      outdatedDependencies
    };
  }

  private async analyzeGemfile(filePath: string): Promise<DependencyAnalysisResult> {
    const findings: SecurityFinding[] = [];
    const vulnerableDependencies: VulnerableDependency[] = [];
    const outdatedDependencies: DependencyAnalysisResult['outdatedDependencies'] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');

      // Check for insecure gem sources
      if (content.includes('source \'http://')) {
        findings.push({
          type: 'dependency',
          category: 'Insecure Gem Source',
          severity: 'medium',
          title: 'Insecure gem source',
          description: 'Gem source configured with HTTP instead of HTTPS',
          file: path.basename(filePath),
          recommendation: 'Use HTTPS for gem sources',
          confidence: 0.8,
          impact: 'Man-in-the-middle attacks during gem installation',
          effort: 'low'
        });
      }

    } catch (error) {
      findings.push({
        type: 'config',
        category: 'File Access Error',
        severity: 'low',
        title: 'Cannot read Gemfile',
        description: `Error reading Gemfile: ${error}`,
        file: path.basename(filePath),
        recommendation: 'Ensure Gemfile is accessible and properly formatted',
        confidence: 0.9,
        impact: 'Dependency analysis incomplete',
        effort: 'low'
      });
    }

    return {
      findings,
      vulnerableDependencies,
      outdatedDependencies
    };
  }

  private async analyzeGoMod(filePath: string): Promise<DependencyAnalysisResult> {
    const findings: SecurityFinding[] = [];
    const vulnerableDependencies: VulnerableDependency[] = [];
    const outdatedDependencies: DependencyAnalysisResult['outdatedDependencies'] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');

      // Check for insecure module paths
      if (content.includes('replace ') && content.includes('=>') && content.includes('http://')) {
        findings.push({
          type: 'dependency',
          category: 'Insecure Module Source',
          severity: 'medium',
          title: 'Insecure Go module source',
          description: 'Go module replacement uses HTTP instead of HTTPS',
          file: path.basename(filePath),
          recommendation: 'Use HTTPS for Go module sources',
          confidence: 0.8,
          impact: 'Man-in-the-middle attacks during module download',
          effort: 'low'
        });
      }

    } catch (error) {
      findings.push({
        type: 'config',
        category: 'File Access Error',
        severity: 'low',
        title: 'Cannot read go.mod',
        description: `Error reading go.mod: ${error}`,
        file: path.basename(filePath),
        recommendation: 'Ensure go.mod is accessible and properly formatted',
        confidence: 0.9,
        impact: 'Dependency analysis incomplete',
        effort: 'low'
      });
    }

    return {
      findings,
      vulnerableDependencies,
      outdatedDependencies
    };
  }

  private isVersionVulnerable(version: string, versionRange: string): boolean {
    // Simplified version comparison - in production would use semver library
    const cleanVersion = version.replace(/[\^~]/g, '');
    
    if (versionRange.includes('<')) {
      const targetVersion = versionRange.replace('<', '').trim();
      return this.compareVersions(cleanVersion, targetVersion) < 0;
    }
    
    if (versionRange.includes('>=') && versionRange.includes('<')) {
      const [minVersion, maxVersion] = versionRange.split('<');
      const min = minVersion.replace('>=', '').trim();
      const max = maxVersion.trim();
      return this.compareVersions(cleanVersion, min) >= 0 && this.compareVersions(cleanVersion, max) < 0;
    }
    
    return false;
  }

  private compareVersions(v1: string, v2: string): number {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const part1 = parts1[i] || 0;
      const part2 = parts2[i] || 0;
      
      if (part1 < part2) return -1;
      if (part1 > part2) return 1;
    }
    
    return 0;
  }

  private isSuspiciousPackage(name: string): boolean {
    const suspiciousPatterns = [
      /^[a-z]{1,3}$/,  // Very short names
      /\d{10,}/,       // Long numeric sequences
      /^(test|temp|demo)-/,  // Test packages
      /-[a-z]{1,2}$/,  // Single letter suffixes
    ];

    return suspiciousPatterns.some(pattern => pattern.test(name));
  }

  private hasInsecureScriptCommand(command: string): boolean {
    const insecurePatterns = [
      /curl.*\|.*sh/,     // Pipe to shell
      /wget.*\|.*sh/,     // Pipe to shell
      /http:\/\/[^\/]*\//,  // HTTP downloads
      /sudo/,             // Sudo commands
      /rm\s+-rf\s+\//,    // Dangerous file operations
    ];

    return insecurePatterns.some(pattern => pattern.test(command));
  }
}