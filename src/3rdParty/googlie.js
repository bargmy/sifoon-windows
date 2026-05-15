const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const crypto = require('crypto');
const zlib = require('zlib');
const { URL } = require('url');

/**
 * googlie.js - Mixed Protocol (HTTP + SOCKS4/5) Google Apps Script Relay Proxy
 */

// --- Core Relay Logic ---
class GoogleRelay {
    constructor(config) {
        this.googleIp = config.google_ip || '216.239.38.120';
        this.frontDomain = config.front_domain || 'www.google.com';
        this.scriptId = config.script_id;
        this.authKey = config.auth_key || '';
        this.upstreamProxyUrl = config.UpstreamProxyURL || null;
        this.maxRedirects = 5;
    }

    _createProxyConnection(options) {
        return new Promise((resolve, reject) => {
            const proxyUrl = new URL(this.upstreamProxyUrl);
            const proxySocket = net.connect({
                host: proxyUrl.hostname,
                port: proxyUrl.port || 80
            });
            
            let authHeader = '';
            if (proxyUrl.username || proxyUrl.password) {
                const auth = Buffer.from(decodeURIComponent(proxyUrl.username) + ':' + decodeURIComponent(proxyUrl.password)).toString('base64');
                authHeader = `Proxy-Authorization: Basic ${auth}\r\n`;
            }

            proxySocket.on('connect', () => {
                proxySocket.write(`CONNECT ${options.hostname}:${options.port} HTTP/1.1\r\nHost: ${options.hostname}:${options.port}\r\n${authHeader}\r\n`);
            });

            let connected = false;
            proxySocket.on('data', (chunk) => {
                if (!connected) {
                    const response = chunk.toString();
                    if (response.match(/^HTTP\/1\.[01] 200/)) {
                        connected = true;
                        resolve(proxySocket);
                    } else {
                        proxySocket.destroy();
                        reject(new Error("Proxy connection failed: " + response.split('\r\n')[0]));
                    }
                }
            });

            proxySocket.on('error', reject);
        });
    }

    _addProxyToOptions(options) {
        if (this.upstreamProxyUrl) {
            options.createConnection = (opts, callback) => {
                this._createProxyConnection(opts).then(socket => {
                    const tlsSocket = tls.connect({
                        socket: socket,
                        servername: opts.servername || opts.hostname
                    }, () => callback(null, tlsSocket));
                    tlsSocket.on('error', err => callback(err, null));
                }).catch(err => callback(err, null));
            };
        }
        return options;
    }

    async fetch(method, targetUrl, headers = {}, body = null) {
        const payload = {
            m: method,
            u: targetUrl,
            h: this._filterHeaders(headers),
            k: this.authKey,
            r: false
        };

        if (body && body.length > 0) {
            payload.b = Buffer.isBuffer(body) ? body.toString('base64') : Buffer.from(body).toString('base64');
        }

        return this._relayRequest(payload);
    }

    _filterHeaders(headers) {
        const filtered = {};
        const skip = ['host', 'connection', 'proxy-connection', 'content-length', 'accept-encoding'];
        for (const key in headers) {
            if (!skip.includes(key.toLowerCase())) {
                filtered[key] = headers[key];
            }
        }
        return filtered;
    }

    async _relayRequest(payload, redirectCount = 0) {
        if (redirectCount > this.maxRedirects) throw new Error("Too many redirects");

        const jsonPayload = JSON.stringify(payload);
        const options = this._addProxyToOptions({
            hostname: this.googleIp,
            port: 443,
            path: `/macros/s/${this.scriptId}/exec`,
            method: 'POST',
            headers: {
                'Host': 'script.google.com',
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(jsonPayload),
                'Accept-Encoding': 'gzip, deflate'
            },
            servername: this.frontDomain,
            rejectUnauthorized: false
        });

        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                if (res.statusCode === 302 || res.statusCode === 301) {
                    const location = res.headers.location;
                    if (location) {
                        this._followRedirect(new URL(location), jsonPayload, redirectCount + 1).then(resolve).catch(reject);
                        return;
                    }
                }

                this._handleResponse(res, (err, responseText) => {
                    if (err) return reject(err);
                    try {
                        const parsed = JSON.parse(responseText);
                        if (parsed.s) {
                            resolve({
                                status: parsed.s,
                                headers: parsed.h,
                                body: parsed.b ? Buffer.from(parsed.b, 'base64') : Buffer.alloc(0)
                            });
                        } else if (parsed.e) {
                            reject(new Error(`Relay Error: ${parsed.e}`));
                        } else {
                            reject(new Error(`Relay JSON missing status`));
                        }
                    } catch (e) {
                        reject(new Error(`Relay returned non-JSON (Status ${res.statusCode})`));
                    }
                });
            });

            req.on('error', reject);
            req.write(jsonPayload);
            req.end();
        });
    }

    async _followRedirect(url, originalPayload, redirectCount) {
        const options = this._addProxyToOptions({
            hostname: this.googleIp,
            port: 443,
            path: url.pathname + url.search,
            method: 'GET',
            headers: { 'Host': url.hostname, 'Accept-Encoding': 'gzip, deflate' },
            servername: this.frontDomain,
            rejectUnauthorized: false
        });
        
        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                if (res.statusCode === 302 || res.statusCode === 301) {
                    const location = res.headers.location;
                    if (location) {
                        this._followRedirect(new URL(location), originalPayload, redirectCount + 1).then(resolve).catch(reject);
                        return;
                    }
                }

                this._handleResponse(res, (err, responseText) => {
                    if (err) return reject(err);
                    try {
                        const parsed = JSON.parse(responseText);
                        if (parsed.s) {
                            resolve({
                                status: parsed.s,
                                headers: parsed.h,
                                body: parsed.b ? Buffer.from(parsed.b, 'base64') : Buffer.alloc(0)
                            });
                        } else {
                            resolve({ status: res.statusCode, headers: res.headers, body: Buffer.from(responseText) });
                        }
                    } catch (e) {
                        reject(new Error(`Redirected Relay returned non-JSON`));
                    }
                });
            });
            req.on('error', reject);
            req.end();
        });
    }

    _handleResponse(res, callback) {
        let stream = res;
        const encoding = res.headers['content-encoding'];
        if (encoding === 'gzip') stream = res.pipe(zlib.createGunzip());
        else if (encoding === 'deflate') stream = res.pipe(zlib.createInflate());

        let chunks = [];
        stream.on('data', (chunk) => chunks.push(chunk));
        stream.on('end', () => callback(null, Buffer.concat(chunks).toString('utf8')));
        stream.on('error', (err) => callback(err));
    }
}

// --- UI / Animation Logic ---
const UI = {
    uploaded: 0,
    downloaded: 0,
    upFrame: -1,
    downFrame: -1,
    upErr: false,
    downErr: false,
    arrowLen: 15,
    
    colors: {
        green: '\x1b[92m',
        red: '\x1b[91m',
        reset: '\x1b[0m',
        dim: '\x1b[2m'
    },

    getArrow(frame, isError, reverse = false) {
        let s = "";
        let color = isError ? this.colors.red : this.colors.green;
        for (let i = 0; i < this.arrowLen; i++) {
            let pos = reverse ? (this.arrowLen - 1 - i) : i;
            let isActive = (pos === frame % this.arrowLen) || (pos === (frame - 1) % this.arrowLen) || (pos === (frame - 2) % this.arrowLen);
            if (frame >= 0 && isActive) {
                s += color + (reverse ? '<' : '>') + this.colors.reset;
            } else {
                s += this.colors.dim + "-" + this.colors.reset;
            }
        }
        return s;
    },

    render(config) {
        process.stdout.write('\x1b[H\x1b[J'); 

        // Upload Row
        let upArrow1 = this.getArrow(this.upFrame, this.upErr);
        let upArrow2 = this.getArrow(this.upFrame >= 0 ? this.upFrame + 3 : -1, this.upErr);
        console.log(`User    ${upArrow1} Google ${upArrow2} Target    ( ${this.colors.green}${(this.uploaded / 1024).toFixed(2)} KB${this.colors.reset} uploaded )`);

        // Download Row
        let downArrow1 = this.getArrow(this.downFrame >= 0 ? this.downFrame + 3 : -1, this.downErr, true);
        let downArrow2 = this.getArrow(this.downFrame, this.downErr, true);
        console.log(`User    ${downArrow1} Google ${downArrow2} Target    ( ${this.colors.green}${(this.downloaded / 1024).toFixed(2)} KB${this.colors.reset} downloaded )`);
        
        console.log(`\n${this.colors.dim}Status: Listening on ${config.listen_port} | HTTP Proxy Only | Front Domain: ${config.front_domain}${this.colors.reset}`);
        
        if (this.upFrame >= 0) this.upFrame++;
        if (this.upFrame > this.arrowLen + 10) { this.upFrame = -1; this.upErr = false; }

        if (this.downFrame >= 0) this.downFrame++;
        if (this.downFrame > this.arrowLen + 10) { this.downFrame = -1; this.downErr = false; }
    },

    triggerUp(err = false) { this.upFrame = 0; this.upErr = err; },
    triggerDown(err = false) { this.downFrame = 0; this.downErr = err; }
};

// --- Configuration & Setup ---
const CONFIG_FILE = process.argv[2] || 'google_config.json';

let config;
try {
    config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
} catch (e) {
    console.log(JSON.stringify({"noticeType": "FatalError", "data": {"message": "Failed to read config file"}}));
    process.exit(1);
}
startServer();

// --- Master HTTP Server ---
function startServer() {
    const relay = new GoogleRelay(config);
    const PORT = config.listen_port || 8087;
    const httpServer = http.createServer();

    httpServer.on('request', (req, res) => handleHttpRequest(req, res, relay));
    httpServer.on('connect', (req, socket) => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        handleGenericRelay(socket, req.url, null, relay);
    });

    httpServer.listen(PORT, '127.0.0.1', () => {
        // Output JSON notices for Sifoon C++ client
        console.log(JSON.stringify({"noticeType": "ListeningHttpProxyPort", "data": {"port": PORT}}));
        
        // Perform an HTTP check through the proxy to ensure the relay is working
        const req = http.request({
            host: '127.0.0.1',
            port: PORT,
            method: 'GET',
            path: 'http://www.google.com/generate_204',
            headers: {
                'Host': 'www.google.com'
            }
        }, (res) => {
            if (res.statusCode === 204 || res.statusCode === 200) {
                console.log(JSON.stringify({"noticeType": "Tunnels", "data": {"count": 1}}));
            } else {
                console.log(JSON.stringify({"noticeType": "FatalError", "data": {"message": "HTTP check failed with status " + res.statusCode}}));
                process.exit(1);
            }
        });
        
        req.on('error', (err) => {
            console.log(JSON.stringify({"noticeType": "FatalError", "data": {"message": "HTTP check error: " + err.message}}));
            process.exit(1);
        });
        
        req.end();
    });
}

// --- Server Implementation Helpers ---

async function handleHttpRequest(req, res, relay) {
    let bodyChunks = [];
    req.on('data', (chunk) => bodyChunks.push(chunk));
    req.on('end', async () => {
        const bodyBuffer = Buffer.concat(bodyChunks);
        UI.uploaded += bodyBuffer.length;
        UI.triggerUp();

        try {
            const relayResponse = await relay.fetch(req.method, req.url, req.headers, bodyBuffer.length > 0 ? bodyBuffer : null);
            UI.downloaded += relayResponse.body.length;
            UI.triggerDown();
            res.writeHead(relayResponse.status, relayResponse.headers);
            res.end(relayResponse.body);
        } catch (e) {
            UI.triggerUp(true);
            UI.triggerDown(true);
            res.writeHead(502);
            res.end();
        }
    });
}

function handleGenericRelay(socket, targetHost, initialData, relay) {
    const isTelegram = targetHost.includes('149.154.') || targetHost.includes('91.108.');
    let buffer = initialData || Buffer.alloc(0);

    const onData = async (chunk) => {
        if (chunk) buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length === 0) return;

        UI.uploaded += chunk ? chunk.length : 0;
        UI.triggerUp();

        const s = buffer.toString('utf8', 0, 1024);
        const httpMatch = s.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.*) HTTP\/1\.[01]/i);

        if (httpMatch && !targetHost.includes(':443')) {
            const headEnd = buffer.indexOf('\r\n\r\n');
            if (headEnd !== -1) {
                const head = buffer.slice(0, headEnd).toString();
                const body = buffer.slice(headEnd + 4);
                const lines = head.split('\r\n');
                const [method, urlPath] = lines[0].split(' ');
                
                const headers = {};
                for (let i = 1; i < lines.length; i++) {
                    const parts = lines[i].split(': ');
                    if (parts.length === 2) headers[parts[0].toLowerCase()] = parts[1];
                }

                let targetUrl = urlPath.startsWith('/') ? `http://${targetHost}${urlPath}` : urlPath;
                
                try {
                    const res = await relay.fetch(method, targetUrl, headers, body);
                    UI.downloaded += res.body.length;
                    UI.triggerDown();
                    
                    socket.write(`HTTP/1.1 ${res.status} OK\r\n`);
                    for (const h in res.headers) socket.write(`${h}: ${res.headers[h]}\r\n`);
                    socket.write('\r\n');
                    socket.write(res.body);
                    buffer = Buffer.alloc(0);
                    return;
                } catch (e) { }
            } else if (buffer.length < 4096) return;
        }

        const targetUrl = isTelegram ? `http://${targetHost}/api` : `http://${targetHost}/`;
        try {
            const res = await relay.fetch('POST', targetUrl, { 'Content-Type': 'application/octet-stream' }, buffer);
            UI.downloaded += res.body.length;
            UI.triggerDown();
            socket.write(res.body);
            buffer = Buffer.alloc(0);
        } catch (e) {
            UI.triggerDown(true);
            socket.destroy();
        }
    };

    if (buffer.length > 0) onData();
    socket.on('data', onData);
    socket.on('error', () => socket.destroy());
    socket.on('close', () => socket.destroy());
}