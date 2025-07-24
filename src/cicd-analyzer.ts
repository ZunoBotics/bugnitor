import * as fs from 'fs';
import * as path from 'path';
import { SecurityFinding } from './types';

export interface CICDAnalysisResult {
  findings: SecurityFinding[];
  workflows: Array<{
    file: string;
    type: 'github' | 'gitlab' | 'jenkins' | 'docker' | 'other';
    findings: SecurityFinding[];
  }>;
}

export class CICDAnalyzer {
  async analyzeCICD(projectPath: string): Promise<CICDAnalysisResult> {
    const findings: SecurityFinding[] = [];
    const workflows: CICDAnalysisResult['workflows'] = [];

    // Analyze GitHub Actions
    const githubWorkflowsPath = path.join(projectPath, '.github', 'workflows');
    if (fs.existsSync(githubWorkflowsPath)) {
      const result = await this.analyzeGitHubActions(githubWorkflowsPath);
      findings.push(...result.findings);
      workflows.push(...result.workflows);
    }

    // Analyze GitLab CI
    const gitlabCIPath = path.join(projectPath, '.gitlab-ci.yml');
    if (fs.existsSync(gitlabCIPath)) {
      const result = await this.analyzeGitLabCI(gitlabCIPath);
      findings.push(...result.findings);
      workflows.push(result.workflow);
    }

    // Analyze Jenkins
    const jenkinsfilePath = path.join(projectPath, 'Jenkinsfile');
    if (fs.existsSync(jenkinsfilePath)) {
      const result = await this.analyzeJenkinsfile(jenkinsfilePath);
      findings.push(...result.findings);
      workflows.push(result.workflow);
    }

    // Analyze Dockerfiles
    const dockerFiles = this.findDockerfiles(projectPath);
    for (const dockerFile of dockerFiles) {
      const result = await this.analyzeDockerfile(dockerFile);
      findings.push(...result.findings);
      workflows.push(result.workflow);
    }

    return {
      findings,
      workflows
    };
  }

  private async analyzeGitHubActions(workflowsPath: string): Promise<{
    findings: SecurityFinding[];
    workflows: CICDAnalysisResult['workflows'];
  }> {
    const findings: SecurityFinding[] = [];
    const workflows: CICDAnalysisResult['workflows'] = [];

    try {
      const files = fs.readdirSync(workflowsPath);
      
      for (const file of files) {
        if (file.endsWith('.yml') || file.endsWith('.yaml')) {
          const filePath = path.join(workflowsPath, file);
          const content = fs.readFileSync(filePath, 'utf-8');
          const workflowFindings = this.analyzeGitHubWorkflow(content, file);
          
          findings.push(...workflowFindings);
          workflows.push({
            file: path.relative(path.dirname(workflowsPath), filePath),
            type: 'github',
            findings: workflowFindings
          });
        }
      }
    } catch (error) {
      findings.push({
        type: 'cicd',
        category: 'File Access Error',
        severity: 'low',
        title: 'Cannot analyze GitHub Actions',
        description: `Error reading GitHub workflows: ${error}`,
        file: '.github/workflows/',
        recommendation: 'Ensure workflow files are accessible',
        confidence: 0.9,
        impact: 'CI/CD security analysis incomplete',
        effort: 'low'
      });
    }

    return { findings, workflows };
  }

  private analyzeGitHubWorkflow(content: string, filename: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Check for secrets in workflow files
    const secretPatterns = [
      /password\s*:\s*["'][^"']*["']/gi,
      /token\s*:\s*["'][^"']*["']/gi,
      /api_key\s*:\s*["'][^"']*["']/gi,
      /secret\s*:\s*["'][^"']*["']/gi
    ];

    for (const pattern of secretPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        findings.push({
          type: 'cicd',
          category: 'Hardcoded Secret in CI/CD',
          severity: 'critical',
          title: 'Secret exposed in GitHub workflow',
          description: 'Sensitive information hardcoded in workflow file',
          file: filename,
          line: this.getLineNumber(content, match.index || 0),
          code: match[0],
          recommendation: 'Use GitHub secrets instead of hardcoding sensitive values',
          confidence: 0.8,
          impact: 'Secret exposure in version control',
          effort: 'low'
        });
      }
    }

    // Check for pull request write permissions
    if (content.includes('pull-requests: write') && content.includes('on:') && content.includes('pull_request')) {
      findings.push({
        type: 'cicd',
        category: 'Excessive Permissions',
        severity: 'medium',
        title: 'Excessive pull request permissions',
        description: 'Workflow has write access to pull requests',
        file: filename,
        recommendation: 'Use minimal required permissions. Consider using read-only access.',
        confidence: 0.7,
        impact: 'Potential unauthorized modifications to pull requests',
        effort: 'low'
      });
    }

    // Check for dangerous shell commands
    const dangerousCommands = [
      /curl.*\|.*sh/gi,
      /wget.*\|.*bash/gi,
      /sudo\s+/gi,
      /rm\s+-rf\s+\//gi,
      /chmod\s+777/gi
    ];

    for (const pattern of dangerousCommands) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        findings.push({
          type: 'cicd',
          category: 'Dangerous Command',
          severity: 'high',
          title: 'Dangerous shell command in workflow',
          description: 'Potentially unsafe command execution in CI/CD pipeline',
          file: filename,
          line: this.getLineNumber(content, match.index || 0),
          code: match[0],
          recommendation: 'Avoid piping downloads to shell or using dangerous file operations',
          confidence: 0.8,
          impact: 'Code execution vulnerabilities in CI/CD environment',
          effort: 'medium'
        });
      }
    }

    // Check for third-party actions without version pinning
    const actionPattern = /uses:\s*([^@\s]+)@([^\s]+)/gi;
    let match;
    while ((match = actionPattern.exec(content)) !== null) {
      const actionRef = match[2];
      if (actionRef === 'main' || actionRef === 'master' || actionRef === 'latest') {
        findings.push({
          type: 'cicd',
          category: 'Unpinned Action Version',
          severity: 'medium',
          title: 'Unpinned third-party action',
          description: 'Third-party GitHub action not pinned to specific version',
          file: filename,
          line: this.getLineNumber(content, match.index || 0),
          code: match[0],
          recommendation: 'Pin actions to specific commit SHA or version tag',
          confidence: 0.7,
          impact: 'Supply chain attacks via action updates',
          effort: 'low'
        });
      }
    }

    // Check for missing security scanning
    const hasSecurityScan = content.includes('security') || 
                           content.includes('vulnerability') || 
                           content.includes('codeql') ||
                           content.includes('snyk');
    
    if (!hasSecurityScan && content.includes('on:') && (content.includes('push') || content.includes('pull_request'))) {
      findings.push({
        type: 'cicd',
        category: 'Missing Security Controls',
        severity: 'medium',
        title: 'No security scanning in CI/CD',
        description: 'Workflow lacks security vulnerability scanning',
        file: filename,
        recommendation: 'Add security scanning tools like CodeQL, Snyk, or similar',
        confidence: 0.6,
        impact: 'Vulnerabilities may go undetected',
        effort: 'medium'
      });
    }

    return findings;
  }

  private async analyzeGitLabCI(filePath: string): Promise<{
    findings: SecurityFinding[];
    workflow: CICDAnalysisResult['workflows'][0];
  }> {
    const findings: SecurityFinding[] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const filename = path.basename(filePath);

      // Check for secrets in variables
      const secretPattern = /variables:\s*\n([\s\S]*?)(?=\n\S|\n$)/gi;
      let match;
      while ((match = secretPattern.exec(content)) !== null) {
        const variables = match[1];
        if (variables.includes('password') || variables.includes('token') || variables.includes('key')) {
          findings.push({
            type: 'cicd',
            category: 'Hardcoded Secret in CI/CD',
            severity: 'high',
            title: 'Potential secret in GitLab CI variables',
            description: 'Sensitive variables may be exposed in CI configuration',
            file: filename,
            line: this.getLineNumber(content, match.index || 0),
            recommendation: 'Use GitLab CI/CD variables or secrets instead',
            confidence: 0.6,
            impact: 'Secret exposure in CI/CD configuration',
            effort: 'low'
          });
        }
      }

      // Check for image security
      const imagePattern = /image:\s*([^\s]+)/gi;
      while ((match = imagePattern.exec(content)) !== null) {
        const image = match[1];
        if (image.includes(':latest')) {
          findings.push({
            type: 'cicd',
            category: 'Unpinned Docker Image',
            severity: 'low',
            title: 'Unpinned Docker image version',
            description: 'CI/CD uses latest Docker image tag',
            file: filename,
            line: this.getLineNumber(content, match.index || 0),
            code: match[0],
            recommendation: 'Pin Docker images to specific versions',
            confidence: 0.7,
            impact: 'Build inconsistencies, potential supply chain attacks',
            effort: 'low'
          });
        }
      }

    } catch (error) {
      findings.push({
        type: 'cicd',
        category: 'File Access Error',
        severity: 'low',
        title: 'Cannot analyze GitLab CI',
        description: `Error reading .gitlab-ci.yml: ${error}`,
        file: path.basename(filePath),
        recommendation: 'Ensure GitLab CI file is accessible',
        confidence: 0.9,
        impact: 'CI/CD security analysis incomplete',
        effort: 'low'
      });
    }

    return {
      findings,
      workflow: {
        file: path.basename(filePath),
        type: 'gitlab',
        findings
      }
    };
  }

  private async analyzeJenkinsfile(filePath: string): Promise<{
    findings: SecurityFinding[];
    workflow: CICDAnalysisResult['workflows'][0];
  }> {
    const findings: SecurityFinding[] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const filename = path.basename(filePath);

      // Check for shell command injection
      const shellPattern = /sh\s+['"`]([^'"`]*)['"]/gi;
      let match;
      while ((match = shellPattern.exec(content)) !== null) {
        const command = match[1];
        if (command.includes('$') && (command.includes('env.') || command.includes('params.'))) {
          findings.push({
            type: 'cicd',
            category: 'Command Injection Risk',
            severity: 'high',
            title: 'Potential command injection in Jenkinsfile',
            description: 'Shell command uses environment variables without proper escaping',
            file: filename,
            line: this.getLineNumber(content, match.index || 0),
            code: match[0],
            recommendation: 'Properly escape or validate environment variables in shell commands',
            confidence: 0.7,
            impact: 'Command injection in CI/CD pipeline',
            effort: 'medium'
          });
        }
      }

      // Check for credentials usage
      if (content.includes('withCredentials') && content.includes('usernamePassword')) {
        const credPattern = /usernamePassword.*passwordVariable:\s*['"]([^'"]*)['"]/gi;
        while ((match = credPattern.exec(content)) !== null) {
          findings.push({
            type: 'cicd',
            category: 'Credential Exposure Risk',
            severity: 'medium',
            title: 'Credential usage in pipeline',
            description: 'Pipeline uses credentials that may be logged',
            file: filename,
            line: this.getLineNumber(content, match.index || 0),
            recommendation: 'Ensure credentials are not logged or exposed in pipeline output',
            confidence: 0.6,
            impact: 'Potential credential exposure in logs',
            effort: 'low'
          });
        }
      }

    } catch (error) {
      findings.push({
        type: 'cicd',
        category: 'File Access Error',
        severity: 'low',
        title: 'Cannot analyze Jenkinsfile',
        description: `Error reading Jenkinsfile: ${error}`,
        file: path.basename(filePath),
        recommendation: 'Ensure Jenkinsfile is accessible',
        confidence: 0.9,
        impact: 'CI/CD security analysis incomplete',
        effort: 'low'
      });
    }

    return {
      findings,
      workflow: {
        file: path.basename(filePath),
        type: 'jenkins',
        findings
      }
    };
  }

  private async analyzeDockerfile(filePath: string): Promise<{
    findings: SecurityFinding[];
    workflow: CICDAnalysisResult['workflows'][0];
  }> {
    const findings: SecurityFinding[] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const filename = path.basename(filePath);

      // Check for root user
      if (!content.includes('USER ') || content.includes('USER root')) {
        findings.push({
          type: 'config',
          category: 'Insecure Docker Configuration',
          severity: 'medium',
          title: 'Container runs as root',
          description: 'Dockerfile does not specify non-root user',
          file: filename,
          recommendation: 'Add USER directive to run container as non-root user',
          confidence: 0.8,
          impact: 'Privilege escalation if container is compromised',
          effort: 'low'
        });
      }

      // Check for latest tag usage
      const fromPattern = /FROM\s+([^:\s]+)(?::([^\s]+))?/gi;
      let match;
      while ((match = fromPattern.exec(content)) !== null) {
        const tag = match[2];
        if (!tag || tag === 'latest') {
          findings.push({
            type: 'config',
            category: 'Unpinned Docker Image',
            severity: 'low',
            title: 'Unpinned base image version',
            description: 'Dockerfile uses latest or no tag for base image',
            file: filename,
            line: this.getLineNumber(content, match.index || 0),
            code: match[0],
            recommendation: 'Pin base image to specific version',
            confidence: 0.8,
            impact: 'Build inconsistencies, potential supply chain attacks',
            effort: 'low'
          });
        }
      }

      // Check for ADD instead of COPY
      if (content.includes('ADD ')) {
        const addPattern = /ADD\s+/gi;
        while ((match = addPattern.exec(content)) !== null) {
          findings.push({
            type: 'config',
            category: 'Insecure Docker Practice',
            severity: 'low',
            title: 'Use of ADD instead of COPY',
            description: 'ADD has additional functionality that may be unsafe',
            file: filename,
            line: this.getLineNumber(content, match.index || 0),
            recommendation: 'Use COPY instead of ADD unless auto-extraction is needed',
            confidence: 0.6,
            impact: 'Potential unintended file extraction or URL downloads',
            effort: 'low'
          });
        }
      }

      // Check for secrets in build args
      const argPattern = /ARG\s+([^=\s]+)(?:=([^\s]+))?/gi;
      while ((match = argPattern.exec(content)) !== null) {
        const argName = match[1].toLowerCase();
        if (argName.includes('password') || argName.includes('token') || argName.includes('key')) {
          findings.push({
            type: 'config',
            category: 'Secret in Build Args',
            severity: 'medium',
            title: 'Potential secret in build argument',
            description: 'Build argument may contain sensitive information',
            file: filename,
            line: this.getLineNumber(content, match.index || 0),
            code: match[0],
            recommendation: 'Avoid passing secrets as build arguments. Use multi-stage builds or runtime secrets.',
            confidence: 0.7,
            impact: 'Secrets visible in image layers and build cache',
            effort: 'medium'
          });
        }
      }

      // Check for package manager cache
      if (content.includes('apt-get update') && !content.includes('rm -rf /var/lib/apt/lists/*')) {
        findings.push({
          type: 'config',
          category: 'Docker Image Bloat',
          severity: 'low',
          title: 'Package manager cache not cleaned',
          description: 'APT cache not removed, increasing image size',
          file: filename,
          recommendation: 'Add "rm -rf /var/lib/apt/lists/*" after apt-get commands',
          confidence: 0.8,
          impact: 'Larger image size, potential security metadata exposure',
          effort: 'low'
        });
      }

    } catch (error) {
      findings.push({
        type: 'config',
        category: 'File Access Error',
        severity: 'low',
        title: 'Cannot analyze Dockerfile',
        description: `Error reading Dockerfile: ${error}`,
        file: path.basename(filePath),
        recommendation: 'Ensure Dockerfile is accessible',
        confidence: 0.9,
        impact: 'Docker security analysis incomplete',
        effort: 'low'
      });
    }

    return {
      findings,
      workflow: {
        file: path.basename(filePath),
        type: 'docker',
        findings
      }
    };
  }

  private findDockerfiles(projectPath: string): string[] {
    const dockerfiles: string[] = [];
    
    try {
      const findDockerfilesRecursive = (dir: string) => {
        const items = fs.readdirSync(dir);
        
        for (const item of items) {
          const fullPath = path.join(dir, item);
          const stat = fs.statSync(fullPath);
          
          if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
            findDockerfilesRecursive(fullPath);
          } else if (stat.isFile() && (item === 'Dockerfile' || item.startsWith('Dockerfile.'))) {
            dockerfiles.push(fullPath);
          }
        }
      };
      
      findDockerfilesRecursive(projectPath);
    } catch (error) {
      // Silently handle errors in recursive search
    }
    
    return dockerfiles;
  }

  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }
}