import { SecurityFinding, SecurityGrade } from './types';

export class SecurityGrader {
  calculateSecurityGrade(findings: SecurityFinding[], totalFiles: number): SecurityGrade {
    const categoryFindings = this.categorizeFindingsByType(findings);
    const categoryGrades = this.calculateCategoryGrades(categoryFindings, totalFiles);
    const overallScore = this.calculateOverallScore(categoryGrades);
    const overallGrade = this.scoreToGrade(overallScore);
    const recommendations = this.generateRecommendations(findings, categoryGrades);

    return {
      overall: overallGrade,
      categories: {
        injection: categoryGrades.injection,
        access_control: categoryGrades.access_control,
        sensitive_data: categoryGrades.sensitive_data,
        cryptography: categoryGrades.cryptography,
        dependencies: categoryGrades.dependencies,
        configuration: categoryGrades.configuration
      },
      score: overallScore,
      recommendations
    };
  }

  private categorizeFindingsByType(findings: SecurityFinding[]): Record<string, SecurityFinding[]> {
    const categories: Record<string, SecurityFinding[]> = {
      injection: [],
      access_control: [],
      sensitive_data: [],
      cryptography: [],
      dependencies: [],
      configuration: []
    };

    for (const finding of findings) {
      switch (finding.type) {
        case 'injection':
        case 'deserialization':
          categories.injection.push(finding);
          break;
        case 'broken_access':
          categories.access_control.push(finding);
          break;
        case 'sensitive_data':
          categories.sensitive_data.push(finding);
          break;
        case 'cryptography':
          categories.cryptography.push(finding);
          break;
        case 'dependency':
          categories.dependencies.push(finding);
          break;
        case 'config':
        case 'cicd':
        case 'file_path':
        case 'memory':
          categories.configuration.push(finding);
          break;
      }
    }

    return categories;
  }

  private calculateCategoryGrades(
    categoryFindings: Record<string, SecurityFinding[]>,
    totalFiles: number
  ): Record<string, 'A' | 'B' | 'C' | 'D' | 'F'> {
    const grades: Record<string, 'A' | 'B' | 'C' | 'D' | 'F'> = {};

    for (const [category, findings] of Object.entries(categoryFindings)) {
      const score = this.calculateCategoryScore(findings, totalFiles);
      grades[category] = this.scoreToGrade(score);
    }

    return grades;
  }

  private calculateCategoryScore(findings: SecurityFinding[], totalFiles: number): number {
    if (findings.length === 0) return 100;

    // Weight findings by severity
    const severityWeights = {
      critical: 20,
      high: 10,
      medium: 5,
      low: 1
    };

    let totalWeight = 0;
    let maxPossibleWeight = 0;

    for (const finding of findings) {
      const weight = severityWeights[finding.severity];
      totalWeight += weight * finding.confidence;
    }

    // Calculate max possible weight based on file count
    // Assume each file could have at most 1 critical issue
    maxPossibleWeight = totalFiles * severityWeights.critical;

    // Calculate penalty percentage
    const penaltyPercentage = Math.min((totalWeight / maxPossibleWeight) * 100, 100);
    
    return Math.max(0, 100 - penaltyPercentage);
  }

  private calculateOverallScore(categoryGrades: Record<string, 'A' | 'B' | 'C' | 'D' | 'F'>): number {
    const gradeValues = { A: 90, B: 80, C: 70, D: 60, F: 50 };
    const categoryWeights = {
      injection: 0.25,        // 25% - Most critical
      access_control: 0.20,   // 20% - Very important
      sensitive_data: 0.20,   // 20% - Very important
      cryptography: 0.15,     // 15% - Important
      dependencies: 0.10,     // 10% - Moderate
      configuration: 0.10     // 10% - Moderate
    };

    let weightedSum = 0;
    let totalWeight = 0;

    for (const [category, grade] of Object.entries(categoryGrades)) {
      if (categoryWeights[category as keyof typeof categoryWeights]) {
        const weight = categoryWeights[category as keyof typeof categoryWeights];
        const value = gradeValues[grade];
        weightedSum += value * weight;
        totalWeight += weight;
      }
    }

    return Math.round(weightedSum / totalWeight);
  }

  private scoreToGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  private generateRecommendations(
    findings: SecurityFinding[],
    categoryGrades: Record<string, 'A' | 'B' | 'C' | 'D' | 'F'>
  ): string[] {
    const recommendations: string[] = [];

    // Priority recommendations based on critical and high severity issues
    const criticalFindings = findings.filter(f => f.severity === 'critical');
    const highFindings = findings.filter(f => f.severity === 'high');

    if (criticalFindings.length > 0) {
      recommendations.push(`🚨 URGENT: Address ${criticalFindings.length} critical security issues immediately`);
      
      // Group critical findings by category
      const criticalByCategory = this.groupByCategory(criticalFindings);
      for (const [category, count] of Object.entries(criticalByCategory)) {
        if (count > 0) {
          recommendations.push(`  • Fix ${count} critical ${this.getCategoryDisplayName(category)} issues`);
        }
      }
    }

    if (highFindings.length > 0) {
      recommendations.push(`⚠️  HIGH PRIORITY: Resolve ${highFindings.length} high-severity vulnerabilities`);
    }

    // Category-specific recommendations
    if (categoryGrades.injection === 'F') {
      recommendations.push('🛡️ Implement input validation and parameterized queries to prevent injection attacks');
    }

    if (categoryGrades.sensitive_data === 'F') {
      recommendations.push('🔐 Remove hardcoded secrets and implement proper secret management');
    }

    if (categoryGrades.access_control === 'F') {
      recommendations.push('🔒 Add authorization checks to all sensitive operations');
    }

    if (categoryGrades.cryptography === 'F') {
      recommendations.push('🔑 Update to strong cryptographic algorithms and secure configurations');
    }

    if (categoryGrades.dependencies === 'F') {
      recommendations.push('📦 Update vulnerable dependencies and implement dependency scanning');
    }

    if (categoryGrades.configuration === 'F') {
      recommendations.push('⚙️ Review and secure configuration files and CI/CD pipelines');
    }

    // General recommendations
    const totalIssues = findings.length;
    if (totalIssues > 50) {
      recommendations.push('🔧 Consider implementing automated security testing in CI/CD pipeline');
    }

    if (totalIssues > 20) {
      recommendations.push('📋 Conduct security code review process for all changes');
    }

    if (findings.some(f => f.confidence < 0.7)) {
      recommendations.push('🔍 Manual security review recommended for low-confidence findings');
    }

    // Best practices recommendations
    if (categoryGrades.overall !== 'A') {
      recommendations.push('📚 Implement security training for development team');
      recommendations.push('🔐 Set up regular security scanning and monitoring');
    }

    return recommendations.slice(0, 10); // Limit to top 10 recommendations
  }

  private groupByCategory(findings: SecurityFinding[]): Record<string, number> {
    const counts: Record<string, number> = {};
    
    for (const finding of findings) {
      const category = finding.type;
      counts[category] = (counts[category] || 0) + 1;
    }
    
    return counts;
  }

  private getCategoryDisplayName(category: string): string {
    const displayNames: Record<string, string> = {
      injection: 'injection',
      broken_access: 'access control',
      sensitive_data: 'sensitive data',
      deserialization: 'deserialization',
      file_path: 'file/path',
      memory: 'memory safety',
      cryptography: 'cryptography',
      dependency: 'dependency',
      cicd: 'CI/CD',
      config: 'configuration'
    };

    return displayNames[category] || category;
  }

  generateNextSteps(findings: SecurityFinding[], grade: SecurityGrade): string[] {
    const nextSteps: string[] = [];

    // Immediate actions for critical issues
    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;

    if (criticalCount > 0) {
      nextSteps.push('🚨 IMMEDIATE: Fix all critical vulnerabilities before deployment');
      nextSteps.push('🔒 Rotate any exposed secrets or credentials');
      nextSteps.push('🛡️ Implement emergency patches for critical security flaws');
    }

    if (highCount > 0) {
      nextSteps.push('⚠️ HIGH PRIORITY: Schedule remediation of high-severity issues within 1 week');
    }

    // Grade-based recommendations
    if (grade.overall === 'F') {
      nextSteps.push('📋 Conduct comprehensive security audit');
      nextSteps.push('🔧 Implement security-first development practices');
      nextSteps.push('👥 Consider hiring security consultant');
    } else if (grade.overall === 'D') {
      nextSteps.push('📈 Develop security improvement roadmap');
      nextSteps.push('🎯 Focus on top 3 vulnerability categories');
    }

    // Automation recommendations
    if (findings.length > 10) {
      nextSteps.push('🤖 Set up automated security testing in CI/CD pipeline');
      nextSteps.push('📊 Implement security metrics and monitoring');
    }

    // Process improvements
    nextSteps.push('📚 Train development team on secure coding practices');
    nextSteps.push('🔍 Establish regular security code review process');
    nextSteps.push('📅 Schedule follow-up security scan in 30 days');

    // Dependency management
    const depFindings = findings.filter(f => f.type === 'dependency');
    if (depFindings.length > 0) {
      nextSteps.push('📦 Set up automated dependency vulnerability scanning');
      nextSteps.push('🔄 Establish regular dependency update schedule');
    }

    return nextSteps.slice(0, 8); // Limit to top 8 next steps
  }
}