# Auton v3

Autonomous web application security testing platform powered by Claude.

## Quick Start

### Prerequisites
- Python 3.11+
- Claude Code CLI: `npm install -g @anthropic-ai/claude-code`
- Claude Pro subscription (for authentication)

### Installation

```bash
pip install -r requirements.txt
```

### Usage

```bash
# Start a new scan
python -m auton scan https://example.com

# Scan with specific instructions
python -m auton scan https://example.com --instruction "Focus on authentication bypass"

# Resume a previous scan
python -m auton resume <session_id>

# List saved sessions
python -m auton sessions
```

### How It Works

Auton uses Claude Code as its backend — Claude autonomously:
1. Visits the target in a browser
2. Identifies all input points and entry vectors
3. Tests each with payloads for XSS, SQLi, SSRF, and more
4. Verifies findings by observing actual exploitation
5. Generates a report with proof-of-concept exploits

**"No Exploit, No Report"** — Only confirmed vulnerabilities are reported.

## Architecture

```
auton/
├── cli.py           # Entry point
├── config.py        # Pydantic configuration
├── core/
│   ├── backend.py   # AgentBackend ABC + ClaudeCodeBackend
│   ├── controller.py # Lifecycle (pause/resume/stop)
│   └── session.py   # Session persistence
├── prompts/
│   └── pentesting.py # Web security system prompt
└── reporting/
    └── generator.py  # Markdown report generator
```

## License

MIT
