<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Security Copilot Agent - Development Guidelines

## Project Overview
This is a comprehensive Azure security automation tool that:
- Scans Azure Network Security Groups (NSGs) and firewall rules for misconfigurations
- Automatically creates GitHub issues with detailed remediation steps
- Generates pull requests with auto-remediation scripts
- Logs all findings to Azure SQL Database for audit trails
- Integrates with honeypot logs for real-time threat correlation
- Provides CLI tools for security operations teams

## Architecture Principles
- **Security First**: Always prioritize security in code design and implementation
- **Azure Native**: Leverage Azure services and best practices
- **Automation**: Minimize manual intervention while maintaining safety controls
- **Observability**: Comprehensive logging and monitoring for all operations
- **Extensibility**: Modular design to support additional security checks

## Code Style Guidelines
- Use Python 3.9+ features and type hints throughout
- Follow PEP 8 and use black for formatting
- Implement comprehensive error handling with structured logging
- Use Pydantic models for data validation and serialization
- Prefer async/await for I/O operations
- Write docstrings for all public functions and classes

## Security Guidelines
- Never log sensitive information (credentials, tokens, etc.)
- Use Azure Managed Identity when possible
- Validate all inputs and sanitize outputs
- Implement proper error handling to avoid information disclosure
- Use secure defaults and principle of least privilege
- Review all auto-remediation scripts for safety

## Testing Guidelines
- Write unit tests for all core functionality
- Include integration tests for Azure SDK interactions
- Mock external dependencies (Azure APIs, GitHub API, etc.)
- Test error conditions and edge cases
- Validate security rule parsing logic thoroughly

## Azure SDK Usage
- Use the latest Azure SDK for Python
- Implement proper credential handling with azure.identity
- Handle Azure throttling and rate limits gracefully
- Use async clients where available
- Implement retry logic with exponential backoff

## GitHub Integration
- Create meaningful issue titles and descriptions
- Use appropriate labels for categorization
- Generate safe auto-remediation scripts
- Create draft PRs for safety review
- Handle GitHub API rate limits

## Database Operations
- Use SQLAlchemy ORM for database operations
- Implement proper connection pooling
- Handle database connection failures gracefully
- Use migrations for schema changes
- Log all database operations for audit trails

## Configuration Management
- Use environment variables for all configuration
- Provide secure defaults
- Validate configuration on startup
- Support both development and production configs
- Never hardcode credentials or sensitive data

## Logging and Monitoring
- Use structured logging with contextual information
- Log security events with appropriate severity levels
- Include correlation IDs for request tracing
- Monitor performance metrics
- Alert on critical security findings

## Error Handling
- Use specific exception types for different error conditions
- Provide meaningful error messages for operators
- Log errors with sufficient context for debugging
- Gracefully degrade functionality when non-critical components fail
- Implement circuit breakers for external service calls

## Performance Considerations
- Use async programming for I/O bound operations
- Implement proper caching where appropriate
- Batch operations when possible
- Monitor resource usage (CPU, memory, network)
- Optimize database queries

## Security Scanning Rules
When adding new security rules:
- Document the security risk being detected
- Provide clear remediation steps
- Include risk scoring methodology
- Consider false positive scenarios
- Test against various Azure configurations

## Deployment Guidelines
- Support both Azure Container Instances and App Service
- Use Azure Key Vault for secrets management
- Implement health checks and readiness probes
- Support scaling and high availability
- Include monitoring and alerting configuration

## Common Patterns
- Use the SecurityFinding model for all security issues
- Leverage the Config class for all configuration access
- Use the database manager for all persistence operations
- Follow the async patterns established in the scanner module
- Use rich console for CLI output formatting
