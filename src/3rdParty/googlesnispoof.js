#!/usr/bin/env node
/**
 * googlesnispoof.js - Google SNI Spoof Proxy
 * Forwards most Google domains to a specific fronting IP using raw TCP.
 * Blocks *.googlevideo.com and Google Play downloads.
 */

const http = require('http');
const net = require('net');
const fs = require('fs');

const PROXY_GOOGLE_IPS = process.argv.includes('--proxy-google-ips');

function isGoogleDomain(host) {
    if (!host) return false;
    const h = host.toLowerCase();

    // EXCLUSIONS (These should be blocked or handled otherwise)
    if (h.endsWith('.googlevideo.com')) return false;
    // 2. Google Play / System Update Downloads
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


function handleDirectForward(socket, targetIp, targetPort) {
    const target = net.connect({
        host: targetIp,
        port: targetPort || 443
    }, () => {
        socket.pipe(target);
        target.pipe(socket);
    });
    target.on('error', () => socket.destroy());
    socket.on('error', () => target.destroy());
}

// --- Configuration ---
const CONFIG_FILE = process.argv[2] || 'google_config.json';
let config = {};
try {
    config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
} catch (e) {
    process.exit(1);
}

const googleIp = config.google_ip || '216.239.38.120';
const PORT = config.listen_port || 8089;

const server = http.createServer();
server.on('connect', (req, socket) => {
    const [host, port] = req.url.split(':');
    
    if (isGoogleDomain(host)) {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        handleDirectForward(socket, googleIp, port);
    } else {
        // Just block or close for everything else in this specific mode
        socket.destroy();
    }
});

// For plain HTTP requests
server.on('request', (req, res) => {
    res.writeHead(403);
    res.end('SNI Spoof mode only supports CONNECT');
});

server.listen(PORT, '127.0.0.1', () => {
    console.log(JSON.stringify({"noticeType": "ListeningHttpProxyPort", "data": {"port": PORT}}));
    console.log(JSON.stringify({"noticeType": "Tunnels", "data": {"count": 1}}));
});
