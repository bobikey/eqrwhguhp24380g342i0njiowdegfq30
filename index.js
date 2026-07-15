import fs from 'fs/promises';
import net from 'net';
import { decryptLink } from './src/decrypt.js';

// ── Домены, которые игнорируем (гит-хостинги с чужими конфигами) ──
const IGNORED_DOMAINS = [
    'github.com',
    'githubusercontent.com',
    'gitverse.ru',
    'gist.github.com',
    'gitea.com',
    'gitlab.com',
    'hub.mos.ru',
    'gitverse.com',
];

function isIgnoredLink(url) {
    try {
        const hostname = new URL(url).hostname;
        return IGNORED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
    } catch { return true; }
}

function decodeBase64ToLines(b64) {
    try {
        const decoded = Buffer.from(b64.trim(), 'base64').toString('utf-8');
        return decoded.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    } catch { return []; }
}

function linesToBase64(lines) {
    return Buffer.from(lines.join('\n'), 'utf-8').toString('base64');
}

// ── Конвертация sing-box JSON → VPN URI ──
function singboxOutboundToUri(ob, remarks) {
    if (!ob || !ob.protocol || !ob.settings) return null;
    const proto = ob.protocol;
    const label = encodeURIComponent(remarks || ob.tag || proto);

    if (proto === 'vless') {
        const vnext = (ob.settings.vnext || [])[0];
        if (!vnext) return null;
        const user = (vnext.users || [])[0];
        if (!user) return null;
        const addr = vnext.address;
        const port = vnext.port;
        const id = user.id;
        if (addr === '0.0.0.0' || id === '00000000-0000-0000-0000-000000000000') return null;
        const flow = user.flow || '';
        const st = ob.streamSettings || {};
        const network = st.network || 'tcp';
        const sec = st.security || 'none';
        let params = `encryption=none&type=${network}&security=${sec}`;
        if (flow) params += `&flow=${flow}`;
        if (st.realitySettings) {
            const rs = st.realitySettings;
            if (rs.serverName) params += `&sni=${rs.serverName}`;
            if (rs.publicKey)  params += `&pbk=${rs.publicKey}`;
            if (rs.shortId)    params += `&sid=${rs.shortId}`;
            if (rs.fingerprint)params += `&fp=${rs.fingerprint}`;
        }
        if (st.tlsSettings?.serverName) params += `&sni=${st.tlsSettings.serverName}`;
        return `vless://${id}@${addr}:${port}?${params}#${label}`;
    }
    if (proto === 'trojan') {
        const servers = (ob.settings.servers || [])[0];
        if (!servers || servers.address === '0.0.0.0') return null;
        const st = ob.streamSettings || {};
        let params = `type=${st.network || 'tcp'}&security=${st.security || 'tls'}`;
        if (st.tlsSettings?.serverName)    params += `&sni=${st.tlsSettings.serverName}`;
        if (st.realitySettings?.serverName)params += `&sni=${st.realitySettings.serverName}`;
        return `trojan://${servers.password}@${servers.address}:${servers.port}?${params}#${label}`;
    }
    if (proto === 'shadowsocks') {
        const servers = (ob.settings.servers || [])[0];
        if (!servers || servers.address === '0.0.0.0') return null;
        const userinfo = Buffer.from(`${servers.method}:${servers.password}`).toString('base64');
        return `ss://${userinfo}@${servers.address}:${servers.port}#${label}`;
    }
    return null;
}

// ── Скачиватель с авто-определением формата ──
async function fetchKeys(url) {
    const r = await fetch(url, { signal: AbortSignal.timeout(12000) });
    if (!r.ok) { console.warn(`  ⚠ HTTP ${r.status}`); return []; }

    const ct = r.headers.get('content-type') || '';

    if (ct.includes('application/json')) {
        try {
            const json = await r.json();
            const configs = Array.isArray(json) ? json : [json];
            const keys = [];
            for (const config of configs) {
                const remarks = config.remarks || '';
                for (const ob of (config.outbounds || [])) {
                    if (!ob.protocol) continue;
                    if (['direct', 'block', 'dns', 'dns-out'].includes(ob.tag)) continue;
                    const uri = singboxOutboundToUri(ob, remarks);
                    if (uri) keys.push(uri);
                }
            }
            if (keys.length > 0) { console.log(`  ✓ Sing-box JSON: ${keys.length} ключей`); return keys; }
            console.warn(`  ⚠ JSON но ключей не нашли`); return [];
        } catch (e) { console.warn(`  ⚠ JSON error:`, e.message); return []; }
    }

    const text = await r.text();
    const vpnPrefixes = ['vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://', 'hysteria://', 'wireguard://'];
    const rawKeys = text.split('\n').map(l => l.trim()).filter(l => vpnPrefixes.some(p => l.startsWith(p)));
    if (rawKeys.length > 0) { console.log(`  ✓ Сырые ключи: ${rawKeys.length} ключей`); return rawKeys; }

    const b64Keys = decodeBase64ToLines(text).filter(l => vpnPrefixes.some(p => l.startsWith(p)));
    if (b64Keys.length > 0) { console.log(`  ✓ Base64: ${b64Keys.length} ключей`); return b64Keys; }

    console.warn(`  ⚠ Формат не распознан (длина: ${text.length})`); return [];
}

// ── Парсинг happvpn ──
async function fetchHappvpnSubscription() {
    const tgUrl = process.env.TG_CHANNEL_URL;
    if (!tgUrl) throw new Error("TG_CHANNEL_URL is not set!");

    console.log("[happvpn] Fetching Telegram channel...");
    const html = await (await fetch(tgUrl)).text();

    const messageBlocks = html.split('<div class="tgme_widget_message_text');
    let russiaLink = null;
    for (let i = messageBlocks.length - 1; i >= 1; i--) {
        const block = messageBlocks[i];
        if (block.includes('Для России')) {
            const match = block.match(/happ:\/\/crypt5\/[A-Za-z0-9+/=]+/);
            if (match) { russiaLink = match[0]; break; }
        }
    }
    if (!russiaLink) throw new Error("No happ:// Russia link found.");

    console.log("[happvpn] Found happ link:", russiaLink.substring(0, 50) + "...");
    console.log("[happvpn] Decrypting...");
    const decryptedUrl = await decryptLink(russiaLink);
    console.log("[happvpn] Decrypted URL: ***");

    console.log("[happvpn] Fetching subscription...");
    const sub = await fetch(decryptedUrl);
    if (!sub.ok) throw new Error(`Failed: ${sub.statusText}`);
    const base64Data = await sub.text();
    console.log(`[happvpn] Done. Length: ${base64Data.length}`);
    return base64Data.trim();
}

// ── Парсинг halyava_vpnz ──
async function fetchHalyavaVpnKeys() {
    const halyavaUrl = process.env.TG_HALYAVA_URL;
    if (!halyavaUrl) throw new Error("TG_HALYAVA_URL is not set!");

    console.log("[halyava] Fetching Telegram channel...");
    const html = await (await fetch(halyavaUrl)).text();
    const messageBlocks = html.split('<div class="tgme_widget_message_text');

    const vpnPosts = [];
    for (let i = messageBlocks.length - 1; i >= 1; i--) {
        const block = messageBlocks[i];
        if (block.includes('Поддержка: Happ') || block.includes('VPN-ключ')) {
            vpnPosts.push(block);
            if (vpnPosts.length >= 3) break;
        }
    }
    console.log(`[halyava] Found ${vpnPosts.length} relevant posts.`);

    const allKeys = [];
    for (const [idx, post] of vpnPosts.entries()) {
        const decoded = post
            .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(code))
            .replace(/&amp;/g, '&')
            .replace(/<[^>]+>/g, ' ');
        const linkMatches = [...decoded.matchAll(/https?:\/\/[^\s"<>)]+/g)].map(m => m[0]);
        const filteredLinks = linkMatches.filter(link => !isIgnoredLink(link));
        console.log(`[halyava] Post ${idx + 1}: ${linkMatches.length} links → ${filteredLinks.length} after filter`);
        for (const link of filteredLinks) {
            console.log(`[halyava] Fetching: ${link.substring(0, 60)}...`);
            try { allKeys.push(...await fetchKeys(link)); }
            catch (e) { console.warn(`[halyava] Error:`, e.message); }
        }
    }
    return allKeys;
}

// ── TCP-проверка и сортировка ──
function tcpPing(host, port, timeoutMs = 4000) {
    return new Promise((resolve) => {
        const start = Date.now();
        const socket = new net.Socket();
        let done = false;
        const finish = (lat) => { if (done) return; done = true; socket.destroy(); resolve(lat); };
        socket.setTimeout(timeoutMs);
        socket.connect(port, host, () => finish(Date.now() - start));
        socket.on('error', () => finish(Infinity));
        socket.on('timeout', () => finish(Infinity));
    });
}

function parseHostPort(uri) {
    try {
        const noproto = uri.replace(/^[a-z0-9]+:\/\//, '');
        const ai = noproto.lastIndexOf('@');
        if (ai === -1) return null;
        const hp = noproto.slice(ai + 1).split('?')[0].split('#')[0];
        const lc = hp.lastIndexOf(':');
        const host = hp.slice(0, lc);
        const port = parseInt(hp.slice(lc + 1));
        if (!host || isNaN(port)) return null;
        return { host, port };
    } catch { return null; }
}

async function checkAndSortKeys(keys, batchSize = 30) {
    console.log(`[check] Проверяем ${keys.length} ключей (TCP, параллельность: ${batchSize})...`);
    const results = [];
    for (let i = 0; i < keys.length; i += batchSize) {
        const batchResults = await Promise.all(
            keys.slice(i, i + batchSize).map(async (key) => {
                const hp = parseHostPort(key);
                const latency = hp ? await tcpPing(hp.host, hp.port) : Infinity;
                return { key, latency };
            })
        );
        results.push(...batchResults);
        const alive = results.filter(r => r.latency < Infinity).length;
        console.log(`[check] ${Math.min(i + batchSize, keys.length)}/${keys.length} | живых: ${alive}`);
    }
    const alive = results.filter(r => r.latency < Infinity).sort((a, b) => a.latency - b.latency);
    console.log(`[check] ✓ Живых: ${alive.length}/${keys.length} | Лучший: ${alive[0]?.latency ?? '-'}ms`);
    return alive.map(r => r.key);
}

// ── Сортировка по странам ──
const COUNTRY_PRIORITY = { RU: 0, FI: 1, DE: 2, NL: 3 };

function extractCountryCode(key) {
    try {
        const name = decodeURIComponent(key.split('#')[1] || '');
        const REGIONAL_BASE = 0x1F1E6;
        const chars = [...name];
        for (let i = 0; i < chars.length - 1; i++) {
            const cp1 = chars[i].codePointAt(0);
            const cp2 = chars[i + 1].codePointAt(0);
            if (cp1 >= REGIONAL_BASE && cp1 <= 0x1F1FF && cp2 >= REGIONAL_BASE && cp2 <= 0x1F1FF) {
                return String.fromCharCode(cp1 - REGIONAL_BASE + 65) + String.fromCharCode(cp2 - REGIONAL_BASE + 65);
            }
        }
        return '';
    } catch { return ''; }
}

function sortByCountryGroups(keys) {
    const groups = new Map();
    for (const key of keys) {
        const cc = extractCountryCode(key) || '??';
        if (!groups.has(cc)) groups.set(cc, []);
        groups.get(cc).push(key);
    }
    const sorted = [...groups.keys()].sort((a, b) => {
        const pa = COUNTRY_PRIORITY[a] ?? 999;
        const pb = COUNTRY_PRIORITY[b] ?? 999;
        if (pa !== pb) return pa - pb;
        return a.localeCompare(b);
    });
    const result = [];
    for (const cc of sorted) {
        const groupKeys = groups.get(cc);
        console.log(`[sort] ${cc === '??' ? '🌐 Без флага' : cc}: ${groupKeys.length} ключей`);
        result.push(...groupKeys);
    }
    return result;
}

// ── MAIN ──
async function main() {
    try {
        const happvpnBase64 = await fetchHappvpnSubscription();
        await fs.writeFile('base64_player_id_game.txt', happvpnBase64, 'utf-8');
        console.log("✅ Saved → base64_player_id_game.txt\n");

        console.log("--- Building combined subscription ---");
        const happvpnKeys = decodeBase64ToLines(happvpnBase64);
        console.log(`[combined] happvpn keys: ${happvpnKeys.length}`);

        let halyavaKeys = [];
        try {
            const rawHalyavaKeys = await fetchHalyavaVpnKeys();
            console.log(`\n[combined] Запускаем проверку halyava ключей...`);
            const checkedKeys = await checkAndSortKeys(rawHalyavaKeys);
            console.log(`\n[sort] Группируем по странам...`);
            halyavaKeys = sortByCountryGroups(checkedKeys);
        } catch (e) {
            console.warn("[combined] halyava failed, skipping:", e.message);
        }
        console.log(`\n[combined] halyava живых ключей: ${halyavaKeys.length}`);

        const happvpnUniq = [...new Set(happvpnKeys)];
        const halyavaUniq = halyavaKeys.filter(k => !happvpnUniq.includes(k));
        const allKeys = [...happvpnUniq, ...halyavaUniq];
        console.log(`[combined] Total unique keys: ${allKeys.length}`);

        await fs.writeFile('base64_player_id_game2.txt', linesToBase64(allKeys), 'utf-8');
        console.log("✅ Saved → base64_player_id_game2.txt");

    } catch (err) {
        console.error("Fatal error:", err);
        process.exit(1);
    }
}

main();
