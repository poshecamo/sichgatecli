# SichGate

**Advanced AI Security Auditing for Startups**

SichGate detects sophisticated AI security vulnerabilities that traditional tools miss. Built specifically for startups shipping AI features fast without dedicated security teams.

```bash
pip install sichgate
sichgate audit
```

## Quick Start

```bash
# Install
pip install sichgate

# Scan your AI project
cd your-ai-project
sichgate audit

# Get detailed security report in seconds
```

## What Makes SichGate Different

Most security scanners look for basic issues like hardcoded keys. SichGate understands **AI-specific attack vectors** that can compromise your LLM applications:

### Advanced Detection Capabilities

**Critical Vulnerabilities:**
- Hardcoded API keys (OpenAI, Anthropic, etc.)
- RAG injection attacks via poisoned documents
- Function calling without authorization checks
- LLM outputs used for security decisions

**High Severity Issues:**
- Prompt injection vulnerabilities
- Training data poisoning risks
- Multimodal injection via images
- Context window manipulation

**Medium Severity Issues:**
- PII logging and data leakage
- Missing input validation
- Unvalidated user feedback collection

## Example Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                         SICHGATE AI SECURITY                                 ║
║                              AUDIT REPORT                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Security Score: 0/100 [ CRITICAL ]
  [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░··················]

╔══════════════════════════════════════════════════════════════════════════════╗
║ THREAT MATRIX                                                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ [CRITICAL]    5 issues detected                                              ║
║ [HIGH]       23 issues detected                                              ║
║ [MEDIUM]      6 issues detected                                              ║
║ [LOW]         0 issues detected                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Why SichGate?

**For startups that:**
- Ship AI features without dedicated security teams
- Use RAG, function calling, or fine-tuning
- Can't afford enterprise security solutions
- Want to build responsibly from day one

**Key advantages:**
- Zero configuration required
- Detects AI-specific vulnerabilities fast
- Fast scanning (seconds, not minutes)

## Installation Options

```bash
# Standard install (recommended)
pip install sichgate

# With ML-based prompt injection detection
pip install sichgate[full]

# Development install
pip install sichgate[dev]
```

## Usage

```bash
# Audit current directory
sichgate audit

# Audit specific project
sichgate audit --target /path/to/project

# Lite mode (faster, regex-only)
sichgate audit --lite

# Check version
sichgate version
```

## What We Detect

### RAG Injection Attacks
Detects when untrusted documents can poison your vector database and inject malicious prompts into future conversations.

### Function Calling Authorization
Identifies missing authorization checks that let users invoke privileged functions through LLM tool calling.

### LLM Security Decisions
Flags dangerous patterns where LLM outputs determine security-critical actions (approvals, access control, code execution).

### Training Data Poisoning
Finds unvalidated user feedback collection that could compromise fine-tuned models.

### Multimodal Injection
Detects vision model vulnerabilities where images contain adversarial text prompts.

### Context Manipulation
Identifies risks where users can poison conversation history or system context.

## Roadmap

**Coming Soon:**
- `sichgate protect` - Runtime protection and auto-fix
- `sichgate monitor` - Real-time threat detection
- GitHub Action for CI/CD integration
- VS Code extension
- Slack/Discord alerting

## Contributing

We're actively developing and welcome contributions:

```bash
git clone https://github.com/yourusername/sichgate
cd sichgate
pip install -e .[dev]
pytest
```

**Areas we need help:**
- Additional AI vulnerability detectors
- False positive reduction
- Documentation and examples
- Integration with popular frameworks

## Security Philosophy

SichGate is built on the principle that AI security requires understanding AI-specific attack patterns. Traditional security tools scan for generic vulnerabilities but miss:

- Indirect prompt injection via RAG
- Authorization bypass through function calling
- Model behavior manipulation
- Supply chain attacks on training data

We focus on these AI-native threats that most tools overlook.

## License

MIT License

## Support

- Documentation: https://sichgate.dev/docs
- Report Issues: https://github.com/yourusername/sichgate/issues
- Security Contact: security@sichgate.dev

Made with ❤️ for the startup community.



