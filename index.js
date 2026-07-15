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
    'hub.mos.ru',    // тоже гит-хостинг
    'gitverse.com',
];

function isIgnoredLink(url) {
    try {
        const hostname = new URL(url).hostname;
        return IGNORED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
    } catch {
        return true;
    }
}

// ── Декодирование/кодирование ──
function decodeBase64ToLines(b64) {
    try {
        const decoded = Buffer.from(b64.trim(), 'base64').toString('utf-8');
        return decoded.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    } catch {
        return [];
    }
}

function linesToBase64(lines) {
    return Buffer.from(lines.join('\n'), 'utf-8').toString('base64');
}

/**
 * Конвертирует sing-box outbound в строку vless:// / trojan:// / ss://
 * happ.dska.su возвращает JSON-массив sing-box конфигов где каждый конфиг = один сервер.
 * Поле `remarks` в конфиге содержит красивое название (🇳🇱 Нидерланды и т.д.)
 */
function singboxOutboundToUri(ob, remarks) {
    if (!ob || !ob.protocol || !ob.settings) return null;
    const proto = ob.protocol;

    // Красивое название: берём remarks конфига, иначе tag outbound-а
    const label = encodeURIComponent(remarks || ob.tag || proto);

    if (proto === 'vless') {
        const vnext = (ob.settings.vnext || [])[0];
        if (!vnext) return null;
        const user = (vnext.users || [])[0];
        if (!user) return null;
        const addr = vnext.address;
        const port = vnext.port;
        const id = user.id;

        // Пропускаем плейсхолдеры
        if (addr === '0.0.0.0' || id === '00000000-0000-0000-0000-000000000000') return null;

        const flow = user.flow || '';
        const st = ob.streamSettings || {};
        const net = st.network || 'tcp';
        const sec = st.security || 'none';
        let params = `encryption=none&type=${net}&security=${sec}`;
        if (flow) params += `&flow=${flow}`;
        if (st.realitySettings) {
            const rs = st.realitySettings;
            if (rs.serverName) params += `&sni=${rs.serverName}`;
            if (rs.publicKey) params += `&pbk=${rs.publicKey}`;
            if (rs.shortId) params += `&sid=${rs.shortId}`;
            if (rs.fingerprint) params += `&fp=${rs.fingerprint}`;
        }
        if (st.tlsSettings) {
            const ts = st.tlsSettings;
            if (ts.serverName) params += `&sni=${ts.serverName}`;
        }
        return `vless://${id}@${addr}:${port}?${params}#${label}`;
    }

    if (proto === 'trojan') {
        const servers = (ob.settings.servers || [])[0];
        if (!servers) return null;
        if (servers.address === '0.0.0.0') return null;
        const st = ob.streamSettings || {};
        const net = st.network || 'tcp';
        const sec = st.security || 'tls';
        let params = `type=${net}&security=${sec}`;
        if (st.tlsSettings?.serverName) params += `&sni=${st.tlsSettings.serverName}`;
        if (st.realitySettings?.serverName) params += `&sni=${st.realitySettings.serverName}`;
        return `trojan://${servers.password}@${servers.address}:${servers.port}?${params}#${label}`;
    }

    if (proto === 'shadowsocks') {
        const servers = (ob.settings.servers || [])[0];
        if (!servers) return null;
        if (servers.address === '0.0.0.0') return null;
        const userinfo = Buffer.from(`${servers.method}:${servers.password}`).toString('base64');
        return `ss://${userinfo}@${servers.address}:${servers.port}#${label}`;
    }

    return null;
}

/**
 * Умный скачиватель — определяет формат ответа и возвращает массив ключей
 */
async function fetchKeys(url) {
    const r = await fetch(url, { signal: AbortSignal.timeout(12000) });
    if (!r.ok) {
        console.warn(`  ⚠ HTTP ${r.status} for ***`);
        return [];
    }

    const contentType = r.headers.get('content-type') || '';

    // ── Формат 1: Sing-box JSON (happ.dska.su и подобные) ──
    if (contentType.includes('application/json')) {
        try {
            const json = await r.json();
            const configs = Array.isArray(json) ? json : [json];
            const keys = [];
            for (const config of configs) {
                const remarks = config.remarks || '';  // например "🇳🇱 Нидерланды"
                const outbounds = config.outbounds || [];
                for (const ob of outbounds) {
                    if (!ob.type && !ob.protocol) continue;
                    if (['direct', 'block', 'dns', 'dns-out'].includes(ob.tag)) continue;
                    const uri = singboxOutboundToUri(ob, remarks);
                    if (uri) keys.push(uri);
                }
            }
            if (keys.length > 0) {
                console.log(`  ✓ Sing-box JSON: ${keys.length} ключей`);
                return keys;
            }
            // Если ключей нет — пробуем как текст
            console.warn(`  ⚠ JSON но ключей не нашли`);
            return [];
        } catch (e) {
            console.warn(`  ⚠ JSON parse error:`, e.message);
            return [];
        }
    }

    // ── Формат 2 и 3: text/plain (сырые ключи или base64) ──
    const text = await r.text();

    // Пробуем сырые ключи (строки начинаются с vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, hy2://)
    const rawLines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    const vpnPrefixes = ['vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'hy2://', 'tuic://', 'hysteria://', 'wireguard://'];
    const rawKeys = rawLines.filter(l => vpnPrefixes.some(p => l.startsWith(p)));

    if (rawKeys.length > 0) {
        console.log(`  ✓ Сырые ключи: ${rawKeys.length} ключей`);
        return rawKeys;
    }

    // Пробуем base64
    const b64Lines = decodeBase64ToLines(text);
    const b64Keys = b64Lines.filter(l => vpnPrefixes.some(p => l.startsWith(p)));
    if (b64Keys.length > 0) {
        console.log(`  ✓ Base64: ${b64Keys.length} ключей`);
        return b64Keys;
    }

    console.warn(`  ⚠ Формат не распознан (длина: ${text.length})`);
    return [];
}

// ──────────────────────────────────────────────

async function fetchHappvpnSubscription() {
    const tgUrl = process.env.TG_CHANNEL_URL;
    if (!tgUrl) throw new Error("TG_CHANNEL_URL is not set!");

    console.log("[happvpn] Fetching Telegram channel...");
    const response = await fetch(tgUrl);
    const html = await response.text();

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
    const subResponse = await fetch(decryptedUrl);
    if (!subResponse.ok) throw new Error(`Failed: ${subResponse.statusText}`);

    const base64Data = await subResponse.text();
    console.log(`[happvpn] Done. Length: ${base64Data.length}`);
    return base64Data.trim();
}

async function fetchHalyavaVpnKeys() {
    const halyavaUrl = process.env.TG_HALYAVA_URL;
    if (!halyavaUrl) throw new Error("TG_HALYAVA_URL is not set!");

    console.log("[halyava] Fetching Telegram channel...");
    const response = await fetch(halyavaUrl);
    const html = await response.text();

    const messageBlocks = html.split('<div class="tgme_widget_message_text');

    // Берём последние 3 поста с маркером VPN-ключей
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
        // Декодируем HTML-entities
        const decoded = post
            .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(code))
            .replace(/&amp;/g, '&')
            .replace(/<[^>]+>/g, ' '); // убираем HTML теги

        // Ищем все http(s) ссылки
        const linkMatches = [...decoded.matchAll(/https?:\/\/[^\s"<>)]+/g)].map(m => m[0]);
        const filteredLinks = linkMatches.filter(link => !isIgnoredLink(link));

        console.log(`[halyava] Post ${idx + 1}: ${linkMatches.length} links → ${filteredLinks.length} after filter`);

        for (const link of filteredLinks) {
            console.log(`[halyava] Fetching: ${link.substring(0, 60)}...`);
            try {
                const keys = await fetchKeys(link);
                allKeys.push(...keys);
            } catch (e) {
                console.warn(`[halyava] Error:`, e.message);
            }
        }
    }

    return allKeys;
}

// ──────────────────────────────────────────────
// Проверка через xray (via Proxy GET) + TCP fallback
// ──────────────────────────────────────────────

import { spawn, execFile } from 'child_process';
import os from 'os';
import path from 'path';

const XRAY_PATH = process.env.XRAY_PATH || null;
let _portCounter = 21000; // стартовый порт для xray HTTP-in

function nextPort() { return _portCounter++; }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/**
 * Парсит VPN URI → xray outbound-объект.
 * Поддерживает vless, vmess, trojan, ss.
 * hysteria2/tuic — возвращает null (xray их не поддерживает).
 */
function uriToXrayOutbound(uri) {
    try {
        const noHash = uri.split('#')[0];
        const colonSlash = noHash.indexOf('://');
        const proto = noHash.slice(0, colonSlash);
        const rest = noHash.slice(colonSlash + 3);

        const atIdx = rest.lastIndexOf('@');
        if (atIdx === -1) return null;
        const userinfo = rest.slice(0, atIdx);
        const hostAndQuery = rest.slice(atIdx + 1);
        const [hostPort, queryStr] = hostAndQuery.split('?');

        let host, port;
        const ipv6 = hostPort.match(/^\[(.+)\]:(\d+)$/);
        if (ipv6) { host = ipv6[1]; port = parseInt(ipv6[2]); }
        else {
            const lc = hostPort.lastIndexOf(':');
            host = hostPort.slice(0, lc);
            port = parseInt(hostPort.slice(lc + 1));
        }
        if (!host || isNaN(port)) return null;

        const p = new URLSearchParams(queryStr || '');
        const network  = p.get('type') || 'tcp';
        const security = p.get('security') || 'none';
        const sni      = p.get('sni') || host;
        const fp       = p.get('fp') || 'chrome';

        // streamSettings
        const ss = { network };
        if (network === 'ws') {
            ss.wsSettings = { path: p.get('path') || '/', headers: { Host: p.get('host') || sni } };
        } else if (network === 'grpc') {
            ss.grpcSettings = { serviceName: p.get('serviceName') || p.get('path') || '' };
        } else if (network === 'h2') {
            ss.httpSettings = { path: p.get('path') || '/', host: [p.get('host') || sni] };
        }
        if (security === 'tls') {
            ss.security = 'tls';
            ss.tlsSettings = { serverName: sni, fingerprint: fp, allowInsecure: false };
        } else if (security === 'reality') {
            ss.security = 'reality';
            ss.realitySettings = { serverName: sni, publicKey: p.get('pbk') || '', shortId: p.get('sid') || '', fingerprint: fp };
        }

        if (proto === 'vless') {
            return { protocol: 'vless', settings: { vnext: [{ address: host, port, users: [{ id: userinfo, encryption: 'none', flow: p.get('flow') || '' }] }] }, streamSettings: ss };
        }
        if (proto === 'trojan') {
            return { protocol: 'trojan', settings: { servers: [{ address: host, port, password: decodeURIComponent(userinfo) }] }, streamSettings: ss };
        }
        if (proto === 'vmess') {
            const v = JSON.parse(Buffer.from(userinfo, 'base64').toString());
            const vNet = v.net || 'tcp';
            const vss = { network: vNet };
            if (vNet === 'ws') vss.wsSettings = { path: v.path || '/', headers: { Host: v.host || v.add } };
            if (v.tls === 'tls') { vss.security = 'tls'; vss.tlsSettings = { serverName: v.sni || v.host || v.add }; }
            return { protocol: 'vmess', settings: { vnext: [{ address: v.add, port: parseInt(v.port), users: [{ id: v.id, alterId: parseInt(v.aid) || 0, security: v.scy || 'auto' }] }] }, streamSettings: vss };
        }
        if (proto === 'ss') {
            let method, password;
            try { [method, ...rest2] = Buffer.from(userinfo, 'base64').toString().split(':'); password = rest2.join(':'); }
            catch { const ci = userinfo.indexOf(':'); method = userinfo.slice(0, ci); password = userinfo.slice(ci + 1); }
            return { protocol: 'shadowsocks', settings: { servers: [{ address: host, port, method, password }] }, streamSettings: { network: 'tcp' } };
        }
        return null; // hysteria2, tuic и пр.
    } catch { return null; }
}

/**
 * Тестирует один ключ через xray:
 * 1. Пишет xray-конфиг (HTTP inbound → VPN outbound)
 * 2. Запускает xray на уникальном порту
 * 3. Делает curl через этот прокси к gstatic.com/generate_204
 * 4. Возвращает задержку в мс, или Infinity если не прошло
 */
async function testViaXray(xrayPath, key, proxyPort) {
    const outbound = uriToXrayOutbound(key);
    if (!outbound) return Infinity; // протокол не поддерживается xray

    const config = {
        log: { loglevel: 'none' },
        inbounds: [{ port: proxyPort, listen: '127.0.0.1', protocol: 'http', settings: {} }],
        outbounds: [{ ...outbound, tag: 'proxy' }, { protocol: 'freedom', tag: 'direct' }]
    };

    const cfgPath = path.join(os.tmpdir(), `xray_${proxyPort}.json`);
    await fs.writeFile(cfgPath, JSON.stringify(config));

    const xray = spawn(xrayPath, ['-config', cfgPath], { stdio: 'ignore' });
    await sleep(700); // даём xray подняться

    const start = Date.now();
    let latency = Infinity;

    try {
        await new Promise((resolve) => {
            execFile('curl', [
                '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '--proxy', `http://127.0.0.1:${proxyPort}`,
                '--max-time', '7',
                '--connect-timeout', '5',
                'http://www.gstatic.com/generate_204'
            ], { timeout: 9000 }, (err, stdout) => {
                const code = parseInt(stdout?.trim());
                if (!err && (code === 204 || code === 200)) {
                    latency = Date.now() - start - 700; // вычитаем время старта
                }
                resolve();
            });
        });
    } catch { /* игнорируем */ }

    xray.kill('SIGKILL');
    await fs.unlink(cfgPath).catch(() => {});
    return latency;
}

/**
 * TCP fallback: просто проверяет открытость порта.
 */
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

/**
 * Основная функция проверки и сортировки.
 * Если XRAY_PATH задан — использует реальный "via Proxy GET".
 * Иначе — TCP-fallback.
 */
async function checkAndSortKeys(keys, batchSize = 10) {
    const useXray = XRAY_PATH && await fs.access(XRAY_PATH).then(() => true).catch(() => false);
    const mode = useXray ? `xray via Proxy GET (параллельность: ${batchSize})` : `TCP connect (параллельность: 30)`;
    const effectiveBatch = useXray ? batchSize : 30;

    console.log(`[check] Проверяем ${keys.length} ключей | режим: ${mode}`);
    const results = [];

    for (let i = 0; i < keys.length; i += effectiveBatch) {
        const batch = keys.slice(i, i + effectiveBatch);
        const batchResults = await Promise.all(
            batch.map(async (key) => {
                let latency;
                if (useXray) {
                    const port = nextPort();
                    latency = await testViaXray(XRAY_PATH, key, port);
                } else {
                    const hp = (() => {
                        try {
                            const noproto = key.replace(/^[a-z0-9]+:\/\//, '');
                            const ai = noproto.lastIndexOf('@');
                            if (ai === -1) return null;
                            const hp2 = noproto.slice(ai + 1).split('?')[0].split('#')[0];
                            const lc = hp2.lastIndexOf(':');
                            return { host: hp2.slice(0, lc), port: parseInt(hp2.slice(lc + 1)) };
                        } catch { return null; }
                    })();
                    latency = hp ? await tcpPing(hp.host, hp.port) : Infinity;
                }
                return { key, latency };
            })
        );
        results.push(...batchResults);
        const done = Math.min(i + effectiveBatch, keys.length);
        const alive = results.filter(r => r.latency < Infinity).length;
        console.log(`[check] ${done}/${keys.length} проверено | живых: ${alive}`);
    }

    const alive = results.filter(r => r.latency < Infinity).sort((a, b) => a.latency - b.latency);
    console.log(`[check] ✓ Живых: ${alive.length}/${keys.length} | мёртвых: ${keys.length - alive.length}`);
    if (alive.length > 0) console.log(`[check] Лучший: ${alive[0].latency}ms | Худший: ${alive[alive.length-1].latency}ms`);
    return alive.map(r => r.key);
}

// ── MAIN ──

// Приоритет стран (индекс = место в списке, меньше = выше)
const COUNTRY_PRIORITY = { RU: 0, FI: 1, DE: 2, NL: 3 };

/**
 * Извлекает ISO-код страны из флага-эмодзи в имени ключа (часть после #).
 * Флаги состоят из двух Unicode Regional Indicator символов (U+1F1E6–U+1F1FF).
 * Пример: 🇷🇺 → "RU", 🇳🇱 → "NL", нет флага → ""
 */
function extractCountryCode(key) {
    try {
        const name = decodeURIComponent(key.split('#')[1] || '');
        // Regional Indicator буквы: каждый символ = 0x1F1E6 + (буква - 'A')
        const REGIONAL_BASE = 0x1F1E6;
        const chars = [...name]; // split по code points (важно для emoji)
        for (let i = 0; i < chars.length - 1; i++) {
            const cp1 = chars[i].codePointAt(0);
            const cp2 = chars[i + 1].codePointAt(0);
            if (cp1 >= REGIONAL_BASE && cp1 <= 0x1F1FF &&
                cp2 >= REGIONAL_BASE && cp2 <= 0x1F1FF) {
                const letter1 = String.fromCharCode(cp1 - REGIONAL_BASE + 65); // A=65
                const letter2 = String.fromCharCode(cp2 - REGIONAL_BASE + 65);
                return letter1 + letter2;
            }
        }
        return '';
    } catch { return ''; }
}

/**
 * Принимает массив ключей (уже отсортированных по пингу),
 * группирует их по стране и возвращает в нужном порядке:
 *   🇷🇺 РФ (быстрый→медленный) → 🇫🇮 FI → 🇩🇪 DE → 🇳🇱 NL → остальные А-Я
 * Внутри каждой страны пинг-порядок сохраняется.
 */
function sortByCountryGroups(keys) {
    // Группируем, сохраняя порядок внутри (ключи уже по пингу)
    const groups = new Map(); // countryCode → [keys]
    for (const key of keys) {
        const cc = extractCountryCode(key) || '??';
        if (!groups.has(cc)) groups.set(cc, []);
        groups.get(cc).push(key);
    }

    // Сортируем страны: приоритетные вперёд, остальные по алфавиту
    const sortedCountries = [...groups.keys()].sort((a, b) => {
        const pa = COUNTRY_PRIORITY[a] ?? 999;
        const pb = COUNTRY_PRIORITY[b] ?? 999;
        if (pa !== pb) return pa - pb;
        return a.localeCompare(b); // алфавит для остальных
    });

    const result = [];
    for (const cc of sortedCountries) {
        const groupKeys = groups.get(cc);
        console.log(`[sort] ${cc === '??' ? '🌐 Без флага' : cc}: ${groupKeys.length} ключей`);
        result.push(...groupKeys);
    }
    return result;
}

async function main() {
    try {
        // Файл 1: только happvpn (оригинал — base64 как есть, без проверки)
        const happvpnBase64 = await fetchHappvpnSubscription();
        await fs.writeFile('base64_player_id_game.txt', happvpnBase64, 'utf-8');
        console.log("✅ Saved → base64_player_id_game.txt\n");

        // Файл 2: happvpn + halyava_vpnz с проверкой и сортировкой halyava-ключей
        console.log("--- Building combined subscription ---");

        const happvpnKeys = decodeBase64ToLines(happvpnBase64);
        console.log(`[combined] happvpn keys: ${happvpnKeys.length}`);

        let halyavaKeys = [];
        try {
            const rawHalyavaKeys = await fetchHalyavaVpnKeys();
            console.log(`\n[combined] Запускаем проверку halyava ключей...`);
            const checkedKeys = await checkAndSortKeys(rawHalyavaKeys);

            // Сортируем по группам стран (пинг-порядок внутри группы сохраняется)
            console.log(`\n[sort] Группируем по странам...`);
            halyavaKeys = sortByCountryGroups(checkedKeys);
        } catch (e) {
            console.warn("[combined] halyava failed, skipping:", e.message);
        }
        console.log(`\n[combined] halyava живых ключей: ${halyavaKeys.length}`);

        // Объединяем: сначала happvpn (без изменений), потом отсортированные halyava
        const happvpnUniq = [...new Set(happvpnKeys)];
        const halyavaUniq = halyavaKeys.filter(k => !happvpnUniq.includes(k));
        const allKeys = [...happvpnUniq, ...halyavaUniq];
        console.log(`[combined] Total unique keys: ${allKeys.length}`);

        const combinedBase64 = linesToBase64(allKeys);
        await fs.writeFile('base64_player_id_game2.txt', combinedBase64, 'utf-8');
        console.log("✅ Saved → base64_player_id_game2.txt");

    } catch (err) {
        console.error("Fatal error:", err);
        process.exit(1);
    }
}

main();
