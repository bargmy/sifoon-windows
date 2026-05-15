#!/usr/bin/env node
/**
 * mhrcfw.js - Node.js port of mhr-cfw
 * DomainFront Tunnel — Bypass DPI censorship via GAS (Google Apps Script).
 * 
 * Features:
 * - HTTP & SOCKS5 Proxy
 * - MITM Interception (HTTPS Decryption)
 * - Domain Fronting Relay (Apps Script)
 * - Parallel Range Downloads
 * - Google IP Scanner
 * - Zero external dependencies (uses built-in modules)
 */

const http = require('http');
const https = require('https');
const http2 = require('http2');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const zlib = require('zlib');
const { URL } = require('url');
const { execSync } = require('child_process');

// --- Constants & Configuration ---

const VERSION = '1.0.0-node';
const DEFAULT_CONFIG = {
    listen_host: '127.0.0.1',
    listen_port: 8085,
    socks5_enabled: true,
    socks5_port: 1085,
    auth_key: '',
    script_id: '',
    front_domain: 'www.google.com',
    google_ip: '', // Optional: force a specific IP
    log_level: 'INFO',
    verify_ssl: true,
    cache_enabled: true,
    cache_max_mb: 50,
    chunked_download_min_size: 5 * 1024 * 1024,
    chunked_download_max_parallel: 8,
    chunked_download_chunk_size: 512 * 1024
};

const CA_ARG_INDEX = process.argv.indexOf('--ca-dir');
const CA_DIR = CA_ARG_INDEX !== -1 ? process.argv[CA_ARG_INDEX + 1] : path.join(process.cwd(), 'ca');
const NO_MITM = process.argv.includes('--no-mitm');
const PROXY_GOOGLE_IPS = process.argv.includes('--proxy-google-ips');

const CA_KEY_FILE = path.join(CA_DIR, 'ca.key');
const CA_CERT_FILE = path.join(CA_DIR, 'ca.crt');

// --- Logger ---

const COLORS = {
    reset: '\x1b[0m',
    dim: '\x1b[2m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    cyan: '\x1b[36m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m'
};

const LOG_LEVELS = { DEBUG: 0, INFO: 1, WARNING: 2, ERROR: 3 };
let CURRENT_LOG_LEVEL = LOG_LEVELS.INFO;

function log(level, component, message) {
    if (LOG_LEVELS[level] < CURRENT_LOG_LEVEL) return;
    const timestamp = new Date().toISOString().split('T')[1].split('Z')[0];
    const color = level === 'ERROR' ? COLORS.red : (level === 'WARNING' ? COLORS.yellow : COLORS.reset);
    const compColor = COLORS.cyan;
    console.log(`${COLORS.dim}[${timestamp}]${COLORS.reset} ${color}${level.padEnd(5)}${COLORS.reset} ${compColor}[${component}]${COLORS.reset} ${message}`);
}

// --- Utility Functions ---

function encodeBase64(data) {
    return Buffer.from(data).toString('base64');
}

function decodeBase64(data) {
    return Buffer.from(data, 'base64');
}

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// --- Certificate Manager (MITM) ---

class CertManager {
    constructor() {
        this.ctxCache = new Map();
        this.certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mhrcfw_certs_'));
        if (!NO_MITM) {
            this.initCA();
        }
    }

    initCA() {
        if (fs.existsSync(CA_KEY_FILE) && fs.existsSync(CA_CERT_FILE)) {
            log('INFO', 'Cert', `Loaded CA from ${CA_DIR}`);
            return;
        }

        if (!fs.existsSync(CA_DIR)) fs.mkdirSync(CA_DIR, { recursive: true });

        log('WARNING', 'Cert', 'Generating new CA certificate. This requires "openssl" in your PATH.');
        try {
            // Generate CA key and cert using openssl CLI
            execSync(`openssl genrsa -out "${CA_KEY_FILE}" 2048`);
            execSync(`openssl req -x509 -new -nodes -key "${CA_KEY_FILE}" -sha256 -days 3650 -out "${CA_CERT_FILE}" -subj "/CN=MHR-CFW/O=MHR-CFW"`);
            log('INFO', 'Cert', `CA generated: ${CA_CERT_FILE}`);
            log('WARNING', 'Cert', '>>> Install this CA certificate in your browser! <<<');
        } catch (e) {
            log('ERROR', 'Cert', 'Failed to generate CA. MITM will be disabled. Error: ' + e.message);
        }
    }

    getSSLContext(domain) {
        if (this.ctxCache.has(domain)) return this.ctxCache.get(domain);

        const safe = domain.replace(/[^a-z0-9.-]/g, '_');
        const keyFile = path.join(this.certDir, `${safe}.key`);
        const certFile = path.join(this.certDir, `${safe}.crt`);

        try {
            // Generate domain certificate signed by our CA
            const cnfFile = path.join(this.certDir, `${safe}.cnf`);
            const cnf = `[req]\ndistinguished_name=dn\n[dn]\n[ext]\nsubjectAltName=DNS:${domain}`;
            fs.writeFileSync(cnfFile, cnf);

            execSync(`openssl genrsa -out "${keyFile}" 2048`);
            execSync(`openssl req -new -key "${keyFile}" -out "${certFile}.csr" -subj "/CN=${domain}"`);
            execSync(`openssl x509 -req -in "${certFile}.csr" -CA "${CA_CERT_FILE}" -CAkey "${CA_KEY_FILE}" -CAcreateserial -out "${certFile}" -days 365 -sha256 -extfile "${cnfFile}" -extensions ext`);

            const ctx = tls.createSecureContext({
                key: fs.readFileSync(keyFile),
                cert: fs.readFileSync(certFile)
            });

            this.ctxCache.set(domain, ctx);
            return ctx;
        } catch (e) {
            log('ERROR', 'Cert', `Failed to generate cert for ${domain}: ${e.message}`);
            return null;
        }
    }
}

// --- Domain Fronter (Relay Logic) ---

class DomainFronter {
    constructor(config) {
        this.config = config;
        this.authKey = config.auth_key;
        this.scriptId = config.script_id;
        this.frontDomain = config.front_domain;
        this.googleIp = config.google_ip || config.front_domain;
    }

    isGoogleDomain(host) {
        if (!host) return false;
        const h = host.toLowerCase();
        
        // EXCLUSIONS
        if (h.endsWith('.googlevideo.com')) return false;
        if (h.endsWith('.gvt1.com') || h.endsWith('.gvt2.com') || h.endsWith('.gvt3.com') || h.endsWith('.gvt5.com')) return false;
        if (h.includes('play.googleapis.com') && h.includes('download')) return false;
        if (h.endsWith('.googleplay.com')) return false;

        // INCLUSIONS
        const exactDomains = [
            'google.com', 'youtube.com', 'android.com', 'blogger.com', 'chrome.com', 
            'tensorflow.org', 'gmail.com', 'google.cn', 'google.hk', 'appspot.com',
            'chromium.org', 'google-analytics.com', 'googletagmanager.com',
            'doubleclick.net', 'googlesyndication.com', 'gstatic.com', 'googleapis.com'
        ];
        const suffixDomains = [
            'google.com', 'youtube.com', 'android.com', 'blogger.com', 'blogspot.com',
            'gstatic.com', 'googleapis.com', 'googleusercontent.com', 'ggpht.com',
            'ytimg.com', 'doubleclick.net', 'appspot.com', 'chromium.org',
            'google.co.uk', 'google.co.jp', 'google.co.in', 'google.com.br'
        ];
        
        if (exactDomains.includes(h)) return true;
        return suffixDomains.some(d => h === d || h.endsWith('.' + d));
    }

    isGoogleIp(host) {
        return host.startsWith('142.250.') || host.startsWith('172.217.') || host.startsWith('216.58.') || host.startsWith('216.239.');
    }

    async relay(method, url, headers, body) {
        const hostKey = this._hostKey(url);
        const sid = this.scriptId; // Simplification: use the first one

        const payload = {
            m: method,
            u: url,
            k: this.authKey
        };

        if (headers) {
            // Strip proxy-specific headers
            const stripHeaders = ['proxy-connection', 'proxy-authorization', 'connection', 'keep-alive'];
            const filteredHeaders = {};
            for (const [k, v] of Object.entries(headers)) {
                if (!stripHeaders.includes(k.toLowerCase())) {
                    filteredHeaders[k] = v;
                }
            }
            payload.h = filteredHeaders;
        }

        if (body && body.length > 0) {
            payload.b = encodeBase64(body);
            const ct = headers['content-type'] || headers['Content-Type'];
            if (ct) payload.ct = ct;
        }

        const jsonPayload = JSON.stringify(payload);
        
        const makeRequest = (targetIp, targetPath, targetHost, isRedirect = false) => {
            const options = {
                hostname: targetIp,
                port: 443,
                path: targetPath,
                method: isRedirect ? 'GET' : 'POST',
                headers: {
                    'Host': targetHost,
                    'Accept-Encoding': 'gzip',
                    'Connection': 'keep-alive'
                },
                servername: this.frontDomain,
                rejectUnauthorized: this.config.verify_ssl
            };
            
            if (!isRedirect) {
                options.headers['Content-Type'] = 'application/json';
                options.headers['Content-Length'] = Buffer.byteLength(jsonPayload);
            }

            return new Promise((resolve, reject) => {
                const req = https.request(options, (res) => {
                    if (res.statusCode === 302 || res.statusCode === 301) {
                        const redirectUrl = new URL(res.headers.location);
                        resolve(makeRequest(this.googleIp, redirectUrl.pathname + redirectUrl.search, redirectUrl.hostname, true));
                        return;
                    }

                    let chunks = [];
                    res.on('data', (chunk) => chunks.push(chunk));
                    res.on('end', () => {
                        let bodyBuffer = Buffer.concat(chunks);
                        const contentEncoding = res.headers['content-encoding'];
                        if (contentEncoding === 'gzip') {
                            try {
                                bodyBuffer = zlib.gunzipSync(bodyBuffer);
                            } catch (e) {
                                log('ERROR', 'Fronter', 'Gzip decompression failed');
                            }
                        }

                        const text = bodyBuffer.toString();
                        try {
                            const data = JSON.parse(text);
                            if (data.e) {
                                reject(new Error(`Relay error: ${data.e}`));
                                return;
                            }
                            resolve({
                                status: data.s || 200,
                                headers: data.h || {},
                                body: data.b ? decodeBase64(data.b) : Buffer.alloc(0)
                            });
                        } catch (e) {
                            // Try to find JSON in potential HTML error response
                            const match = text.match(/\{.*\}/s);
                            if (match) {
                                try {
                                    const data = JSON.parse(match[0]);
                                    resolve({
                                        status: data.s || 200,
                                        headers: data.h || {},
                                        body: data.b ? decodeBase64(data.b) : Buffer.alloc(0)
                                    });
                                    return;
                                } catch (inner) {}
                            }
                            reject(new Error(`Invalid response from relay: ${text.substring(0, 100)}`));
                        }
                    });
                });

                req.on('error', (e) => reject(e));
                if (!isRedirect) req.write(jsonPayload);
                req.end();
            });
        };

        return makeRequest(this.googleIp, `/macros/s/${this.scriptId}/exec`, 'script.google.com');
    }

    _hostKey(url) {
        try {
            return new URL(url).hostname;
        } catch (e) {
            return 'unknown';
        }
    }

    // Parallel Range Download Implementation
    async relayParallel(method, url, headers, body, writer) {
        log('INFO', 'Fronter', `Parallel download start: ${url}`);
        
        // 1. Get total size with a HEAD or Range: bytes=0-0 request
        const rangeHeaders = { ...headers, 'Range': 'bytes=0-0' };
        try {
            const firstChunk = await this.relay(method, url, rangeHeaders, body);
            if (firstChunk.status !== 206 || !firstChunk.headers['content-range']) {
                log('INFO', 'Fronter', 'Server does not support Range, falling back to single relay');
                const fullRes = await this.relay(method, url, headers, body);
                this.writeHttpResponse(writer, fullRes.status, fullRes.headers, fullRes.body);
                return;
            }

            const match = firstChunk.headers['content-range'].match(/\/(\d+)$/);
            const totalSize = match ? parseInt(match[1]) : 0;
            log('INFO', 'Fronter', `Total size: ${totalSize} bytes`);

            if (totalSize < this.config.chunked_download_min_size) {
                const fullRes = await this.relay(method, url, headers, body);
                this.writeHttpResponse(writer, fullRes.status, fullRes.headers, fullRes.body);
                return;
            }

            // 2. Start streaming chunks
            const chunkSize = this.config.chunked_download_chunk_size;
            const maxParallel = this.config.chunked_download_max_parallel;
            
            // Write initial headers
            const responseHeaders = { ...firstChunk.headers };
            delete responseHeaders['content-range'];
            responseHeaders['content-length'] = totalSize;
            responseHeaders['accept-ranges'] = 'bytes';
            
            this.writeHttpResponse(writer, 200, responseHeaders, null);

            let currentPos = 0;
            while (currentPos < totalSize) {
                const tasks = [];
                for (let i = 0; i < maxParallel && currentPos < totalSize; i++) {
                    const start = currentPos;
                    const end = Math.min(start + chunkSize - 1, totalSize - 1);
                    tasks.push(this.relay('GET', url, { ...headers, 'Range': `bytes=${start}-${end}` }, null));
                    currentPos = end + 1;
                }

                const results = await Promise.all(tasks);
                for (const res of results) {
                    if (res.body) writer.write(res.body);
                }
            }
        } catch (e) {
            log('ERROR', 'Fronter', `Parallel download failed: ${e.message}`);
            // Attempt fallback or close
            writer.destroy();
        }
    }

    _splitSetCookie(blob) {
        if (!blob) return [];
        if (Array.isArray(blob)) return blob;
        // Split on commas followed by a cookie name (token=)
        return blob.split(/,\s*(?=[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)/);
    }

    writeHttpResponse(writer, status, headers, body) {
        const statusText = http.STATUS_CODES[status] || 'OK';
        writer.write(`HTTP/1.1 ${status} ${statusText}\r\n`);
        
        for (let [k, v] of Object.entries(headers)) {
            const lowerK = k.toLowerCase();
            if (['transfer-encoding', 'connection', 'content-length', 'content-encoding'].includes(lowerK)) continue;
            
            if (lowerK === 'set-cookie') {
                const cookies = this._splitSetCookie(v);
                for (const cookie of cookies) {
                    writer.write(`${k}: ${cookie}\r\n`);
                }
            } else {
                writer.write(`${k}: ${v}\r\n`);
            }
        }
        
        if (body) {
            writer.write(`Content-Length: ${body.length}\r\n`);
            writer.write('\r\n');
            writer.write(body);
        } else {
            writer.write('\r\n');
        }
    }
}

// --- Proxy Servers ---

class ProxyServer {
    constructor(config, certManager) {
        this.config = config;
        this.fronter = new DomainFronter(config);
        this.certManager = certManager;
    }

    start() {
        // HTTP Proxy Server
        this.httpServer = http.createServer();
        this.httpServer.on('connect', (req, socket, head) => this.handleConnect(req, socket, head));
        this.httpServer.on('request', (req, res) => this.handleHttpRequest(req, res));
        
        this.httpServer.listen(this.config.listen_port, this.config.listen_host, () => {
            log('INFO', 'Proxy', `HTTP Proxy listening on ${this.config.listen_host}:${this.config.listen_port}`);
        });

        // SOCKS5 Proxy Server
        if (this.config.socks5_enabled) {
            this.socksServer = net.createServer((socket) => this.handleSocks(socket));
            this.socksServer.listen(this.config.socks5_port, this.config.listen_host, () => {
                log('INFO', 'Socks', `SOCKS5 Proxy listening on ${this.config.listen_host}:${this.config.socks5_port}`);
            });
        }
    }

    async handleHttpRequest(req, res) {
        log('INFO', 'Proxy', `HTTP ${req.method} ${req.url}`);
        try {
            if (req.method === 'GET') {
                await this.fronter.relayParallel(req.method, req.url, req.headers, null, res);
            } else {
                const body = await this.readBody(req);
                const relayRes = await this.fronter.relay(req.method, req.url, req.headers, body);
                res.writeHead(relayRes.status, relayRes.headers);
                res.end(relayRes.body);
            }
        } catch (e) {
            log('ERROR', 'Proxy', `HTTP Request Error: ${e.message}`);
            res.writeHead(502);
            res.end('Bad Gateway');
        }
    }

    async handleConnect(req, socket, head) {
        const [host, port] = req.url.split(':');
        log('INFO', 'Proxy', `CONNECT ${host}:${port}`);

        // Google Domain Redirection
        if (this.fronter.isGoogleDomain(host)) {
            socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            this.handleDirectForward(socket, this.fronter.googleIp, port, this.fronter.frontDomain);
            return;
        }

        // Proxy Google IPs
        if (PROXY_GOOGLE_IPS && this.fronter.isGoogleIp(host)) {
            socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            // Continue to handleMitmStream or relay
        } else {
            socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        }

        if (port === '443' && !NO_MITM) {
            // MITM: Decrypt HTTPS
            const ctx = this.certManager.getSSLContext(host);
            if (ctx) {
                const tlsSocket = new tls.TLSSocket(socket, {
                    isServer: true,
                    secureContext: ctx
                });

                tlsSocket.on('secure', () => {
                    this.handleMitmStream(host, tlsSocket);
                });
                return;
            }
        }

        // Fallback or Direct Tunnel if MITM fails or is disabled
        socket.destroy();
    }

    handleDirectForward(socket, targetIp, targetPort, sni) {
        const target = tls.connect({
            host: targetIp,
            port: targetPort || 443,
            servername: sni,
            rejectUnauthorized: false
        }, () => {
            socket.pipe(target);
            target.pipe(socket);
        });
        target.on('error', () => socket.destroy());
        socket.on('error', () => target.destroy());
    }

    async handleMitmStream(host, tlsSocket) {
        // We now have a decrypted stream. Read HTTP requests from it.
        // For simplicity in this single-file port, we'll use a basic parser.
        let buffer = Buffer.alloc(0);
        
        tlsSocket.on('data', async (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            
            // Check for full request header
            const headerEnd = buffer.indexOf('\r\n\r\n');
            if (headerEnd !== -1) {
                const headerStr = buffer.slice(0, headerEnd).toString();
                const lines = headerStr.split('\r\n');
                const [method, path] = lines[0].split(' ');
                
                const headers = {};
                for (let i = 1; i < lines.length; i++) {
                    const [k, v] = lines[i].split(': ');
                    if (k && v) headers[k.toLowerCase()] = v;
                }

                const contentLength = parseInt(headers['content-length'] || '0');
                const bodyStart = headerEnd + 4;
                
                if (buffer.length >= bodyStart + contentLength) {
                    const body = buffer.slice(bodyStart, bodyStart + contentLength);
                    buffer = buffer.slice(bodyStart + contentLength);

                    const url = `https://${host}${path}`;
                    log('INFO', 'MITM', `${method} ${url}`);

                    try {
                        if (method === 'GET') {
                            // Create a custom writer that mimics an http.Response for writeHttpResponse
                            const customWriter = {
                                write: (data) => tlsSocket.write(data),
                                destroy: () => tlsSocket.destroy(),
                                writeHead: (status, headers) => {
                                    tlsSocket.write(`HTTP/1.1 ${status} OK\r\n`);
                                    for (const [k, v] of Object.entries(headers)) tlsSocket.write(`${k}: ${v}\r\n`);
                                    tlsSocket.write('\r\n');
                                }
                            };
                            await this.fronter.relayParallel(method, url, headers, null, customWriter);
                        } else {
                            const relayRes = await this.fronter.relay(method, url, headers, body);
                            
                            // Send response back to tlsSocket
                            tlsSocket.write(`HTTP/1.1 ${relayRes.status} ${http.STATUS_CODES[relayRes.status]}\r\n`);
                            for (const [k, v] of Object.entries(relayRes.headers)) {
                                tlsSocket.write(`${k}: ${v}\r\n`);
                            }
                            tlsSocket.write('\r\n');
                            tlsSocket.write(relayRes.body);
                        }
                    } catch (e) {
                        log('ERROR', 'MITM', `Relay Error: ${e.message}`);
                        tlsSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
                    }
                }
            }
        });
    }

    handleSocks(socket) {
        socket.once('data', (data) => {
            if (data[0] !== 0x05) return socket.destroy(); // Only SOCKS5
            const nmethods = data[1];
            socket.write(Buffer.from([0x05, 0x00])); // No authentication

            socket.once('data', (data) => {
                if (data[1] !== 0x01) return socket.destroy(); // Only CONNECT
                
                let host = '';
                let port = 0;
                let offset = 4;

                if (data[3] === 0x01) { // IPv4
                    host = data.slice(4, 8).join('.');
                    offset = 8;
                } else if (data[3] === 0x03) { // Domain
                    const len = data[4];
                    host = data.slice(5, 5 + len).toString();
                    offset = 5 + len;
                }

                port = data.readUInt16BE(offset);
                log('INFO', 'Socks', `CONNECT ${host}:${port}`);

                // Google Domain Redirection
                if (this.fronter.isGoogleDomain(host)) {
                    socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
                    this.handleDirectForward(socket, this.fronter.googleIp, port, this.fronter.frontDomain);
                    return;
                }

                // Proxy Google IPs
                if (PROXY_GOOGLE_IPS && this.fronter.isGoogleIp(host)) {
                    // Continue to MITM or relay
                }

                socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));

                // For SOCKS5, if it's port 443, we try MITM
                if (port === 443 && !NO_MITM) {
                    const ctx = this.certManager.getSSLContext(host);
                    if (ctx) {
                        const tlsSocket = new tls.TLSSocket(socket, {
                            isServer: true,
                            secureContext: ctx
                        });
                        tlsSocket.on('secure', () => this.handleMitmStream(host, tlsSocket));
                        return;
                    }
                }
                
                socket.destroy();
            });
        });
    }

    readBody(req) {
        return new Promise((resolve) => {
            let body = [];
            req.on('data', (chunk) => body.push(chunk));
            req.on('end', () => resolve(Buffer.concat(body)));
        });
    }
}

// --- IP Scanner ---

async function scanGoogleIPs(frontDomain) {
    log('INFO', 'Scanner', `Scanning Google IPs for ${frontDomain}...`);
    // This would contain a list of Google IP ranges to probe
    const testIPs = ['142.250.181.228', '142.250.185.100', '142.250.185.132']; 
    for (const ip of testIPs) {
        const start = Date.now();
        try {
            await new Promise((resolve, reject) => {
                const req = https.request({
                    hostname: ip, port: 443, method: 'HEAD', timeout: 2000,
                    servername: frontDomain, rejectUnauthorized: false
                }, (res) => resolve());
                req.on('error', reject);
                req.end();
            });
            log('INFO', 'Scanner', `${ip}: ${Date.now() - start}ms - OK`);
        } catch (e) {
            log('INFO', 'Scanner', `${ip}: Failed`);
        }
    }
}

// --- Main ---

async function main() {
    console.log(`${COLORS.cyan}${COLORS.bold}`);
    console.log(`  __  __ _    _ _____      _____ ______ _      `);
    console.log(` |  \\/  | |  | |  __ \\    / ____|  ____| |     `);
    console.log(` | \\  / | |__| | |__) |  | |    | |__  | |     `);
    console.log(` | |\\/| |  __  |  _  /   | |    |  __| | |     `);
    console.log(` | |  | | |  | | | \\ \\   | |____| |    | |____ `);
    console.log(` |_|  |_|_|  |_|_|  \\_\\   \\_____|_|    |______|`);
    console.log(`${COLORS.reset}`);
    log('INFO', 'Main', `mhr-cfw Node.js Port v${VERSION}`);

    let config = { ...DEFAULT_CONFIG };
    const configPath = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : 'config.json';
    if (fs.existsSync(configPath)) {
        try {
            const userConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            config = { ...config, ...userConfig };
            log('INFO', 'Main', `Loaded config from ${configPath}`);
        } catch (e) {
            log('ERROR', 'Main', `Failed to parse ${configPath}, using defaults.`);
        }
    }

    CURRENT_LOG_LEVEL = LOG_LEVELS[config.log_level] || LOG_LEVELS.INFO;

    const certManager = new CertManager();

    if (process.argv.includes('--generate-only')) {
        log('INFO', 'Main', 'CA generation complete.');
        process.exit(0);
    }

    if (!config.auth_key || !config.script_id) {
        log('ERROR', 'Main', 'Missing auth_key or script_id in config!');
        log('INFO', 'Main', 'Please create a config.json with your Apps Script details.');
        process.exit(1);
    }

    if (process.argv.includes('--scan')) {
        await scanGoogleIPs(config.front_domain);
        process.exit(0);
    }

    const proxy = new ProxyServer(config, certManager);
    proxy.start();
}

main().catch(e => log('ERROR', 'Main', e.stack));
