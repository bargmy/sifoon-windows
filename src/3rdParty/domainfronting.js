#!/usr/bin/env node
/**
 * domainfronting.js - SNI Repack Relay Proxy
 * Decrypts HTTPS (MITM) and re-encrypts with a "safe" SNI.
 */

const http = require('http');
const tls = require('tls');
const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

// --- Logger ---
function log(level, component, message) {
    const timestamp = new Date().toISOString();
    console.log(JSON.stringify({
        "noticeType": "Info",
        "data": {
            "message": `[${timestamp}] [${level}] [${component}] ${message}`
        }
    }));
}

const CA_ARG_INDEX = process.argv.indexOf('--ca-dir');
const CA_DIR = CA_ARG_INDEX !== -1 ? process.argv[CA_ARG_INDEX + 1] : path.join(process.cwd(), 'ca');
const CA_KEY_FILE = path.join(CA_DIR, 'ca.key');
const CA_CERT_FILE = path.join(CA_DIR, 'ca.crt');

const RULES = [
  { domains: ['google', 'gstatic', 'googleapis', 'youtube', 'googlevideo', 'ggpht', 'ytimg'], sni: 'www.google.com' },
  { domains: ['vercel', 'nextjs'], sni: 'nextjs.org' },
  { domains: ['python', 'pypi', 'fastly', 'reddit', 'githubassets', 'adobe'], sni: 'www.python.org' },
  { domains: ['kubernetes', 'letsencrypt', 'aws', 'amazon'], sni: 'kubernetes.io' },
  { domains: ['github', 'githubusercontent'], sni: 'github.com' },
  { domains: ['pubmed', 'ncbi'], sni: 'pubmed.ncbi.nlm.nih.gov' }
];

function getSafeSNI(host) {
  if (!host) return 'www.google.com';
  const h = host.toLowerCase();
  for (const rule of RULES) {
    if (rule.domains.some(d => h.includes(d))) return rule.sni;
  }
  return 'www.google.com'; // Default fallback
}

// --- Certificate Manager ---
class CertManager {
  constructor() {
    this.ctxCache = new Map();
    this.certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'df_certs_'));
    this.initCA();
  }

  initCA() {
    if (fs.existsSync(CA_KEY_FILE) && fs.existsSync(CA_CERT_FILE)) return;
    if (!fs.existsSync(CA_DIR)) fs.mkdirSync(CA_DIR, { recursive: true });
    try {
      execSync(`openssl genrsa -out "${CA_KEY_FILE}" 2048`, { stdio: 'ignore' });
      execSync(`openssl req -x509 -new -nodes -key "${CA_KEY_FILE}" -sha256 -days 3650 -out "${CA_CERT_FILE}" -subj "/CN=DF-CA/O=Sifoon"`, { stdio: 'ignore' });
    } catch (e) { log('ERROR', 'Cert', e.message); }
  }

  getSSLContext(domain) {
    if (this.ctxCache.has(domain)) return this.ctxCache.get(domain);
    const safe = domain.replace(/[^a-z0-9.-]/g, '_');
    const keyFile = path.join(this.certDir, `${safe}.key`);
    const certFile = path.join(this.certDir, `${safe}.crt`);
    const cnfFile = path.join(this.certDir, `${safe}.cnf`);
    try {
      fs.writeFileSync(cnfFile, `[req]\ndistinguished_name=dn\n[dn]\n[ext]\nsubjectAltName=DNS:${domain}`);
      execSync(`openssl genrsa -out "${keyFile}" 2048`, { stdio: 'ignore' });
      execSync(`openssl req -new -key "${keyFile}" -out "${certFile}.csr" -subj "/CN=${domain}"`, { stdio: 'ignore' });
      execSync(`openssl x509 -req -in "${certFile}.csr" -CA "${CA_CERT_FILE}" -CAkey "${CA_KEY_FILE}" -CAcreateserial -out "${certFile}" -days 365 -sha256 -extfile "${cnfFile}" -extensions ext`, { stdio: 'ignore' });
      const ctx = tls.createSecureContext({ key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) });
      this.ctxCache.set(domain, ctx);
      return ctx;
    } catch (e) { return null; }
  }
}

const certManager = new CertManager();

const server = http.createServer();
server.on('connect', (req, socket) => {
  const [host, port] = req.url.split(':');
  socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  
  const ctx = certManager.getSSLContext(host);
  if (ctx && port === '443') {
    const tlsSocket = new tls.TLSSocket(socket, { isServer: true, secureContext: ctx });
    tlsSocket.on('secure', () => {
      // For SNI Repack, we don't necessarily need to parse HTTP.
      // We just need to re-encrypt with the safe SNI.
      // But we must know WHERE we are connecting to.
      const safeSNI = getSafeSNI(host);
      
      const upstream = tls.connect({
        host: host,
        port: 443,
        servername: safeSNI,
        rejectUnauthorized: false
      }, () => {
        tlsSocket.pipe(upstream);
        upstream.pipe(tlsSocket);
      });
      upstream.on('error', () => tlsSocket.destroy());
      tlsSocket.on('error', () => upstream.destroy());
    });
  } else {
    const upstream = net.connect({ host, port }, () => {
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
  }
});

const PORT = 8088;
server.listen(PORT, '127.0.0.1', () => {
  console.log(JSON.stringify({ noticeType: "ListeningHttpProxyPort", data: { port: PORT } }));
});
