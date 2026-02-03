require('dotenv').config();
const express = require('express');
const http = require('http');
const https = require('https'); // EKLENDI: SSL ayarları için
const { Server } = require("socket.io");
const cors = require('cors');
const helmet = require('helmet');
const dns = require('dns').promises;
const whois = require('whois-json');
const axios = require('axios');
const cheerio = require('cheerio');
const geoip = require('geoip-lite');
const ollama = require('ollama').default;
const path = require('path');

// Environment variables
const SHODAN_API_KEY = process.env.SHODAN_API_KEY || '';

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({
    contentSecurityPolicy: false,
}));
app.use(cors());
app.use(express.static('public'));
app.use(express.json());

// --- CONSTANTS & HELPERS ---
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// SSL hatalarını yok sayan özel Axios instance'ı
const axiosInstance = axios.create({
    timeout: 10000,
    headers: { 'User-Agent': USER_AGENT },
    httpsAgent: new https.Agent({
        rejectUnauthorized: false // Self-signed sertifikaları kabul et
    }),
    validateStatus: false // 404/500 hatalarında patlama, veriyi oku
});

const cleanDomain = (input) => {
    if (!input) return "";
    let domain = input
        .replace(/^(?:https?:\/\/)?(?:www\.)?/i, "") // Remove protocol and www
        .split('/')[0]     // Remove path
        .split(':')[0]     // Remove port
        .replace(/\.$/, "") // Remove trailing dot
        .toLowerCase()
        .trim();
    return domain;
};

// --- RECON MODULES ---

// 1. DNS Enumeration (with timeout protection)
async function scanDNS(domain) {
    const records = {};
    const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];
    const DNS_TIMEOUT = 5000; // 5 second timeout per record type

    for (const type of types) {
        try {
            // Add timeout protection for each DNS query
            const timeout = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('DNS timeout')), DNS_TIMEOUT)
            );
            records[type] = await Promise.race([dns.resolve(domain, type), timeout]);
        } catch (e) {
            // Return empty array but log the reason for debugging
            records[type] = [];
            if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
                // Normal: record type doesn't exist for this domain
            } else if (e.message === 'DNS timeout') {
                console.log(`[DNS] Timeout on ${type} record for ${domain}`);
            } else {
                console.log(`[DNS] Error on ${type}: ${e.code || e.message}`);
            }
        }
    }
    return records;
}

// 2. WHOIS (with timeout and retry)
async function scanWhois(domain, retryCount = 0) {
    const WHOIS_TIMEOUT = 10000; // 10 second timeout (WHOIS servers are slow)
    const MAX_RETRIES = 1;

    const timeout = new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Whois timeout")), WHOIS_TIMEOUT)
    );

    try {
        const result = await Promise.race([whois(domain), timeout]);

        // Check if result is valid
        if (!result || typeof result !== 'object') {
            return { error: 'Invalid WHOIS response format.' };
        }

        if (Object.keys(result).length === 0) {
            return { error: 'No WHOIS data found for this domain.' };
        }

        return result;
    } catch (e) {
        // Retry once on timeout
        if ((e.message === 'Whois timeout' || e.code === 'ECONNRESET') && retryCount < MAX_RETRIES) {
            console.log(`[WHOIS] Retry ${retryCount + 1} for ${domain}`);
            return scanWhois(domain, retryCount + 1);
        }

        // Provide more specific error messages
        if (e.message === 'Whois timeout') {
            return { error: 'WHOIS server took too long to respond. Try again later.' };
        }
        if (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND') {
            return { error: 'Could not connect to WHOIS server.' };
        }

        return { error: 'WHOIS lookup failed: ' + e.message };
    }
}

// 3. HTTP Headers & Tech (Axios instance kullanıldı)
async function scanTech(domain) {
    const protocols = ['https', 'http'];
    let lastError = null;

    for (const proto of protocols) {
        try {
            const url = `${proto}://${domain}`;
            const res = await axiosInstance.get(url);

            const headers = res.headers;
            const $ = cheerio.load(res.data);

            const tech = {
                url: url,
                status: res.status,
                server: headers['server'] || 'Unknown',
                poweredBy: headers['x-powered-by'] || 'Unknown',
                cookies: headers['set-cookie'] ? headers['set-cookie'].length : 0,
                title: $('title').text().trim() || 'No Title',
                metaGenerator: $('meta[name="generator"]').attr('content') || null,
                scripts: []
            };

            $('script[src]').each((i, el) => {
                const src = $(el).attr('src');
                if (src && !src.startsWith('data:')) tech.scripts.push(src);
            });

            return tech;
        } catch (e) {
            lastError = e.message;
        }
    }
    return { error: 'Could not fetch HTTP/HTTPS data: ' + lastError };
}

// 4. Cert Transparency (with rate limit detection and retry)
async function scanCerts(domain, retryCount = 0) {
    const MAX_RETRIES = 1;
    const RETRY_DELAY = 2000; // 2 seconds

    try {
        const url = `https://crt.sh/?q=%.${domain}&output=json`;
        const res = await axiosInstance.get(url, { timeout: 15000 }); // Longer timeout for crt.sh
        const subdomains = new Set();

        // Check if response is HTML (rate limited or error page)
        if (typeof res.data === 'string' && res.data.includes('<!DOCTYPE') || res.data.includes('<html')) {
            if (retryCount < MAX_RETRIES) {
                console.log(`[CRT.sh] Rate limited, retrying in ${RETRY_DELAY}ms...`);
                await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
                return scanCerts(domain, retryCount + 1);
            }
            return { error: 'CRT.sh is rate limiting. Try again in a few minutes.' };
        }

        // Check if response is valid JSON array
        if (!Array.isArray(res.data)) {
            if (res.data === null || res.data === '') {
                return []; // No certificates found
            }
            return { error: 'Unexpected response from CRT.sh' };
        }

        res.data.forEach(entry => {
            if (entry && entry.name_value) {
                const nameValues = entry.name_value.split('\n');
                nameValues.forEach(nv => {
                    const sub = nv.toLowerCase().trim();
                    if (!sub.includes('*') && sub.length > 0) {
                        subdomains.add(sub);
                    }
                });
            }
        });

        return Array.from(subdomains).sort().slice(0, 100);
    } catch (e) {
        console.error("CRT.sh Error:", e.message);
        if (e.code === 'ECONNABORTED' || e.message.includes('timeout')) {
            return { error: 'CRT.sh request timed out. The service may be slow.' };
        }
        return { error: 'CRT.sh lookup failed: ' + (e.message || 'Unknown error') };
    }
}

// 5. Wayback Machine
async function scanWayback(domain) {
    try {
        const url = `http://archive.org/wayback/available?url=${domain}`;
        const res = await axiosInstance.get(url);
        if (res.data && res.data.archived_snapshots && res.data.archived_snapshots.closest) {
            return res.data.archived_snapshots.closest;
        }
        return { message: 'No snapshots found' };
    } catch (e) {
        return { message: 'Wayback API unreachable' };
    }
}

// 7. Shodan Host Intelligence
async function scanShodan(domain) {
    if (!SHODAN_API_KEY) {
        return { error: 'Shodan API key not configured. Add SHODAN_API_KEY to .env file.' };
    }

    try {
        // First, resolve the domain to an IP
        let ip;
        try {
            const ips = await dns.resolve4(domain);
            ip = ips[0];
        } catch (e) {
            return { error: 'Could not resolve domain to IP for Shodan lookup.' };
        }

        const url = `https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}`;
        const res = await axiosInstance.get(url, { timeout: 15000 });

        if (res.status === 401) {
            return { error: 'Invalid Shodan API key.' };
        }

        if (res.status === 404) {
            return { message: 'No Shodan data found for this IP.', ip: ip };
        }

        if (res.status !== 200) {
            return { error: `Shodan API error: ${res.status}` };
        }

        const data = res.data;

        // Extract relevant information
        const result = {
            ip: ip,
            hostnames: data.hostnames || [],
            country: data.country_name || 'Unknown',
            city: data.city || 'Unknown',
            org: data.org || 'Unknown',
            isp: data.isp || 'Unknown',
            asn: data.asn || 'Unknown',
            ports: data.ports || [],
            vulns: data.vulns || [],
            lastUpdate: data.last_update || 'Unknown',
            services: []
        };

        // Extract service details
        if (data.data && Array.isArray(data.data)) {
            result.services = data.data.slice(0, 10).map(service => ({
                port: service.port,
                protocol: service.transport || 'tcp',
                product: service.product || 'Unknown',
                version: service.version || '',
                banner: service.data ? service.data.substring(0, 200) : ''
            }));
        }

        return result;
    } catch (e) {
        console.error('Shodan Error:', e.message);
        if (e.code === 'ECONNABORTED' || e.message.includes('timeout')) {
            return { error: 'Shodan API request timed out.' };
        }
        return { error: 'Shodan lookup failed: ' + e.message };
    }
}

// 8. Enhanced Email Enumeration
async function scanEmails(domain) {
    const emails = new Set();
    const sources = [];

    // Common email patterns to generate
    const commonPrefixes = [
        'info', 'contact', 'admin', 'support', 'sales', 'hello', 'help',
        'webmaster', 'mail', 'office', 'hr', 'jobs', 'careers', 'press',
        'media', 'marketing', 'team', 'feedback', 'abuse', 'security',
        'privacy', 'legal', 'billing', 'accounts', 'noreply', 'newsletter'
    ];

    // Generate common email pattern suggestions
    const suggestedEmails = commonPrefixes.map(prefix => `${prefix}@${domain}`);

    // 1. Scrape homepage for emails
    try {
        for (const proto of ['https', 'http']) {
            try {
                const res = await axiosInstance.get(`${proto}://${domain}`, { timeout: 8000 });
                if (res.status === 200 && typeof res.data === 'string') {
                    const $ = cheerio.load(res.data);
                    const text = $.text();
                    const html = $.html();

                    // Email regex
                    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
                    const foundEmails = text.match(emailRegex) || [];
                    foundEmails.forEach(e => emails.add(e.toLowerCase()));

                    // Check mailto links
                    $('a[href^="mailto:"]').each((i, el) => {
                        const href = $(el).attr('href');
                        if (href) {
                            const email = href.replace('mailto:', '').split('?')[0].toLowerCase();
                            if (email.includes('@')) emails.add(email);
                        }
                    });

                    sources.push('homepage');
                    break;
                }
            } catch (e) { }
        }
    } catch (e) { }

    // 2. Check contact page
    const contactPaths = ['/contact', '/contact-us', '/about', '/about-us', '/team', '/support'];
    for (const contactPath of contactPaths) {
        try {
            for (const proto of ['https', 'http']) {
                try {
                    const res = await axiosInstance.get(`${proto}://${domain}${contactPath}`, { timeout: 5000 });
                    if (res.status === 200 && typeof res.data === 'string') {
                        const $ = cheerio.load(res.data);
                        const text = $.text();

                        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
                        const foundEmails = text.match(emailRegex) || [];
                        foundEmails.forEach(e => emails.add(e.toLowerCase()));

                        $('a[href^="mailto:"]').each((i, el) => {
                            const href = $(el).attr('href');
                            if (href) {
                                const email = href.replace('mailto:', '').split('?')[0].toLowerCase();
                                if (email.includes('@')) emails.add(email);
                            }
                        });

                        if (!sources.includes('contact pages')) sources.push('contact pages');
                        break;
                    }
                } catch (e) { }
            }
        } catch (e) { }
    }

    // 3. Check Google (via HTML scrape - limited but works)
    try {
        const googleUrl = `https://www.google.com/search?q="@${domain}"+email`;
        const res = await axiosInstance.get(googleUrl, {
            timeout: 5000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });
        if (res.status === 200 && typeof res.data === 'string') {
            const emailRegex = new RegExp(`[a-zA-Z0-9._%+-]+@${domain.replace('.', '\\.')}`, 'gi');
            const foundEmails = res.data.match(emailRegex) || [];
            foundEmails.forEach(e => emails.add(e.toLowerCase()));
            if (foundEmails.length > 0) sources.push('google search');
        }
    } catch (e) { }

    // Filter out invalid emails and those from other domains
    const validEmails = Array.from(emails).filter(email => {
        const emailDomain = email.split('@')[1];
        return emailDomain && (emailDomain === domain || emailDomain.endsWith('.' + domain));
    });

    return {
        found: validEmails.slice(0, 20),
        suggested: suggestedEmails.slice(0, 15),
        sources: sources,
        total: validEmails.length
    };
}

// 6. Security & Infrastructure
async function scanSecurity(domain) {
    const results = {
        robots: 'Not found',
        sitemap: 'Not found',
        securityTxt: 'Not found',
        geo: null,
        ip: null,
        emails: [],
        comments: [],
        headers: {}
    };

    // GeoIP - with better error handling
    try {
        const ips = await dns.resolve4(domain);
        if (ips && ips.length > 0) {
            results.ip = ips[0];
            const geoData = geoip.lookup(results.ip);
            if (geoData) {
                results.geo = {
                    country: geoData.country || 'Unknown',
                    region: geoData.region || 'Unknown',
                    city: geoData.city || 'Unknown',
                    timezone: geoData.timezone || 'Unknown'
                };
            }
        }
    } catch (e) {
        console.log(`[Infrastructure] GeoIP lookup failed for ${domain}: ${e.message}`);
        results.geo = { error: 'Could not resolve IP address' };
    }

    // Helper function with longer timeout and better error handling
    const tryFetch = async (path, timeout = 8000) => {
        for (const proto of ['https', 'http']) {
            try {
                const res = await axiosInstance.get(`${proto}://${domain}${path}`, {
                    timeout: timeout,
                    maxRedirects: 3
                });
                // Accept various success codes
                if (res.status >= 200 && res.status < 400) {
                    return { data: res.data, status: res.status, headers: res.headers };
                }
            } catch (e) {
                // Continue to next protocol
            }
        }
        return null;
    };

    // Fetch resources with individual error handling
    try {
        const robotsResult = await tryFetch('/robots.txt', 5000);
        if (robotsResult && robotsResult.data && typeof robotsResult.data === 'string' && robotsResult.data.length > 0) {
            results.robots = 'Found';
        }
    } catch (e) { }

    try {
        const sitemapResult = await tryFetch('/sitemap.xml', 5000);
        if (sitemapResult && sitemapResult.data) {
            results.sitemap = 'Found';
        }
    } catch (e) { }

    try {
        const securityResult = await tryFetch('/.well-known/security.txt', 5000);
        if (securityResult && securityResult.data && typeof securityResult.data === 'string' && securityResult.data.length > 0) {
            results.securityTxt = 'Found';
        }
    } catch (e) { }

    // Fetch main page for emails and comments
    try {
        const pageResult = await tryFetch('/', 10000);
        if (pageResult && pageResult.data && typeof pageResult.data === 'string') {
            const $ = cheerio.load(pageResult.data);
            const text = $('body').text();
            const html = $.html();

            // Extract emails
            const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
            const foundEmails = text.match(emailRegex) || [];
            results.emails = [...new Set(foundEmails)].slice(0, 10);

            // Extract HTML comments
            const commentRegex = /<!--([\s\S]*?)-->/g;
            let match;
            while ((match = commentRegex.exec(html)) !== null) {
                const comment = match[1].trim();
                if (comment.length > 5 && comment.length < 200 && !comment.includes('[if')) {
                    results.comments.push(comment);
                }
            }
            results.comments = [...new Set(results.comments)].slice(0, 8);

            // Extract some security headers
            if (pageResult.headers) {
                const securityHeaders = ['x-frame-options', 'x-content-type-options', 'x-xss-protection', 'strict-transport-security', 'content-security-policy'];
                securityHeaders.forEach(header => {
                    if (pageResult.headers[header]) {
                        results.headers[header] = pageResult.headers[header];
                    }
                });
            }
        }
    } catch (e) {
        console.log(`[Infrastructure] Page fetch failed for ${domain}: ${e.message}`);
    }

    return results;
}

// --- CONTROLLER ---

io.on('connection', (socket) => {
    console.log('Client connected');

    socket.on('start-scan', async (data) => {
        const domain = cleanDomain(data.domain);
        if (!domain) {
            socket.emit('log', 'Invalid domain provided.');
            socket.emit('done');
            return;
        }

        const model = data.model || 'llama3';

        socket.emit('log', `Starting passive recon on: ${domain}`);

        const results = {};

        // 1. DNS
        socket.emit('log', 'Running DNS enumeration...');
        results.dns = await scanDNS(domain);
        socket.emit('result', { module: 'DNS', data: results.dns });

        // 2. GeoIP & Security
        socket.emit('log', 'Checking infrastructure & security files...');
        results.security = await scanSecurity(domain);
        socket.emit('result', { module: 'Infrastructure', data: results.security });

        // 3. Tech Stack
        socket.emit('log', 'Fingerprinting technology stack...');
        results.tech = await scanTech(domain);
        socket.emit('result', { module: 'Technology', data: results.tech });

        // 4. Whois
        socket.emit('log', 'Querying WHOIS database...');
        results.whois = await scanWhois(domain);
        socket.emit('result', { module: 'Whois', data: results.whois });

        // 5. Cert Logs
        socket.emit('log', 'Searching Certificate Transparency logs (crt.sh)...');
        results.certs = await scanCerts(domain);
        socket.emit('result', { module: 'Subdomains', data: results.certs });

        // 6. Wayback
        socket.emit('log', 'Checking Wayback Machine availability...');
        results.wayback = await scanWayback(domain);
        socket.emit('result', { module: 'Wayback', data: results.wayback });

        // 7. Shodan
        socket.emit('log', 'Querying Shodan for host intelligence...');
        results.shodan = await scanShodan(domain);
        socket.emit('result', { module: 'Shodan', data: results.shodan });

        // 8. Email Enumeration
        socket.emit('log', 'Enumerating email addresses...');
        results.emails = await scanEmails(domain);
        socket.emit('result', { module: 'Emails', data: results.emails });

        // 7. AI Analysis
        socket.emit('log', 'Sending data to Ollama for analysis...');

        const prompt = `
        You are an expert Red Team Reconnaissance Assistant. Analyze the following passive reconnaissance data for the domain ${domain}.
        
        DATA:
        ${JSON.stringify(results, null, 2)}
        
        TASK:
        1. Summarize the key findings (Tech stack, hosting location, open ports/services, potential emails).
        2. Analyze Shodan data for exposed services, vulnerable versions, and security misconfigurations.
        3. Review discovered emails and suggest social engineering vectors.
        4. Identify potential attack surface (e.g., exposed admin panels, old software, sensitive files, open ports).
        5. Rate the \"Passive Risk Score\" (Low/Medium/High) based on overall exposure.
        6. Suggest 3 specific Google Dorks relevant to this domain to find more info.
        
        Keep it concise, professional, and actionable. Format with Markdown.
        `;

        try {
            const response = await ollama.generate({
                model: model,
                prompt: prompt,
                stream: true
            });

            for await (const part of response) {
                socket.emit('ai-chunk', part.response);
            }
            socket.emit('log', 'Analysis complete.');
        } catch (e) {
            console.error('Ollama Error:', e);
            socket.emit('log', `AI Error: ${e.message}`);

            let errorMessage = `**Error**: Could not connect to Ollama.\n`;
            if (e.message.includes('fetch failed')) {
                errorMessage += `Ensure Ollama is running (run \`ollama serve\` in terminal).`;
            }
            socket.emit('ai-chunk', errorMessage);
        }

        socket.emit('done');
    });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.get('/api/ollama-status', async (req, res) => {
    try {
        const response = await axios.get('http://127.0.0.1:11434/api/tags', { timeout: 2000 });
        res.json({ status: 'online', models: response.data.models });
    } catch (e) {
        res.status(503).json({ status: 'offline', error: e.message });
    }
});

server.listen(PORT, () => {
    console.log(`Passive Recon AI running on http://localhost:${PORT}`);
});