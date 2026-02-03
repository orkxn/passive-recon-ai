# AI Passive Recon

A web-based passive reconnaissance tool powered by AI for security professionals. Performs comprehensive OSINT gathering on target domains and uses Ollama LLMs for intelligent threat analysis.

## Features

### Reconnaissance Modules

| Module | Description |
|--------|-------------|
| **DNS Enumeration** | Queries A, AAAA, MX, TXT, NS, CNAME, and SOA records |
| **WHOIS Lookup** | Retrieves domain registration information |
| **Technology Fingerprinting** | Detects web servers, frameworks, and CMS |
| **Certificate Transparency** | Discovers subdomains via crt.sh |
| **Wayback Machine** | Checks historical snapshots on archive.org |
| **Infrastructure Scan** | GeoIP, security files (robots.txt, sitemap, security.txt), headers |
| **Shodan Integration** | Open ports, services, vulnerabilities, ISP/ASN data |
| **Email Enumeration** | Discovers emails from pages, mailto links, and common patterns |

### AI Analysis

Uses local Ollama models (Llama 3, Mistral, CodeLlama, Gemma) to:
- Summarize key findings
- Identify attack surface and misconfigurations
- Analyze Shodan data for vulnerable services
- Suggest social engineering vectors from discovered emails
- Rate passive risk score (Low/Medium/High)
- Generate relevant Google Dorks

## Requirements

- Node.js 18+
- Ollama running locally (for AI analysis)
- Shodan API key (optional, for Shodan module)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/passive-recon-ai.git
cd passive-recon-ai
```

2. Install dependencies:
```bash
npm install
```

3. Create environment file:
```bash
cp .env.example .env
```

4. Add your API keys to `.env`:
```
SHODAN_API_KEY=your_shodan_api_key_here
```

5. Start Ollama (in a separate terminal):
```bash
ollama serve
```

6. Run the application:
```bash
npm start
```

7. Open your browser to `http://localhost:3000`

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SHODAN_API_KEY` | No | Shodan API key for host intelligence |
| `PORT` | No | Server port (default: 3000) |

### Ollama Models

Make sure you have at least one model pulled:
```bash
ollama pull llama3
```

Supported models:
- llama3 (recommended)
- mistral
- codellama
- gemma

## Project Structure

```
passive-recon-ai/
├── server.js          # Express server and recon modules
├── public/
│   └── index.html     # Frontend UI
├── .env               # Environment variables (create from .env.example)
├── .env.example       # Environment template
├── package.json       # Dependencies
└── README.md          # This file
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/ollama-status` | GET | Check Ollama connection and available models |

## WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| `start-scan` | Client -> Server | Initiate scan with domain and model |
| `log` | Server -> Client | Log message for terminal |
| `result` | Server -> Client | Module result data |
| `ai-chunk` | Server -> Client | Streaming AI response |
| `done` | Server -> Client | Scan complete |

## Legal Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before scanning any domains. Unauthorized scanning may violate computer crime laws.

## Author

Made by Orkxn

## License

MIT License
