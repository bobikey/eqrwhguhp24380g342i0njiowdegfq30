import fs from 'fs/promises';
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
 * happ.dska.su возвращает JSON-массив sing-box конфигов
 */
function singboxOutboundToUri(ob) {
    if (!ob || !ob.protocol || !ob.settings) return null;
    const proto = ob.protocol;

    if (proto === 'vless') {
        const vnext = (ob.settings.vnext || [])[0];
        if (!vnext) return null;
        const user = (vnext.users || [])[0];
        if (!user) return null;
        const addr = vnext.address;
        const port = vnext.port;
        const id = user.id;
        const flow = user.flow || '';
        const st = ob.streamSettings || {};
        const net = st.network || 'tcp';
        const sec = st.security || 'none';
        const tag = encodeURIComponent(ob.tag || 'vless');
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
        return `vless://${id}@${addr}:${port}?${params}#${tag}`;
    }

    if (proto === 'trojan') {
        const servers = (ob.settings.servers || [])[0];
        if (!servers) return null;
        const st = ob.streamSettings || {};
        const net = st.network || 'tcp';
        const sec = st.security || 'tls';
        const tag = encodeURIComponent(ob.tag || 'trojan');
        let params = `type=${net}&security=${sec}`;
        if (st.tlsSettings?.serverName) params += `&sni=${st.tlsSettings.serverName}`;
        if (st.realitySettings?.serverName) params += `&sni=${st.realitySettings.serverName}`;
        return `trojan://${servers.password}@${servers.address}:${servers.port}?${params}#${tag}`;
    }

    if (proto === 'shadowsocks') {
        const servers = (ob.settings.servers || [])[0];
        if (!servers) return null;
        const userinfo = Buffer.from(`${servers.method}:${servers.password}`).toString('base64');
        const tag = encodeURIComponent(ob.tag || 'ss');
        return `ss://${userinfo}@${servers.address}:${servers.port}#${tag}`;
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
                const outbounds = config.outbounds || [];
                for (const ob of outbounds) {
                    if (!ob.type && !ob.protocol) continue;
                    if (['direct', 'block', 'dns'].includes(ob.tag)) continue;
                    const uri = singboxOutboundToUri(ob);
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

// ── MAIN ──
async function main() {
    try {
        // Файл 1: только happvpn (оригинал — base64 как есть)
        const happvpnBase64 = await fetchHappvpnSubscription();
        await fs.writeFile('base64_player_id_game.txt', happvpnBase64, 'utf-8');
        console.log("✅ Saved → base64_player_id_game.txt\n");

        // Файл 2: happvpn + halyava_vpnz (объединённый, дедуп)
        console.log("--- Building combined subscription ---");

        const happvpnKeys = decodeBase64ToLines(happvpnBase64);
        console.log(`[combined] happvpn keys: ${happvpnKeys.length}`);

        let halyavaKeys = [];
        try {
            halyavaKeys = await fetchHalyavaVpnKeys();
        } catch (e) {
            console.warn("[combined] halyava failed, skipping:", e.message);
        }
        console.log(`[combined] halyava keys: ${halyavaKeys.length}`);

        const allKeys = [...new Set([...happvpnKeys, ...halyavaKeys])];
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
