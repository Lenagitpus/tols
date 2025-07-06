import 'dotenv/config';
import { Telegraf, Markup } from 'telegraf';
import fetch from 'node-fetch';
import dns from 'dns/promises';
import net from 'net';
import tls from 'tls';

const BOT_TOKEN = process.env.BOT_TOKEN;
const SECURITYTRAILS_API_KEY = process.env.SECURITYTRAILS_API_KEY;

if (!BOT_TOKEN || !SECURITYTRAILS_API_KEY) {
  console.error('Set BOT_TOKEN dan SECURITYTRAILS_API_KEY di file .env!');
  process.exit(1);
}

const bot = new Telegraf(BOT_TOKEN);
const userState = {};

// --- Utility: Get parent domain (last 3 parts, e.g. ioh.co.id) ---
function getParentDomain(domain) {
  const parts = domain.toLowerCase().split('.');
  if (parts.length < 2) return domain;
  return parts.slice(-3).join('.');
}

// --- SecurityTrails: get subdomains (return array of FQDN) ---
async function getSubdomainsSecurityTrails(domain) {
  const parent = getParentDomain(domain);
  const url = `https://api.securitytrails.com/v1/domain/${parent}/subdomains`;
  const res = await fetch(url, {
    headers: { 'APIKEY': SECURITYTRAILS_API_KEY }
  });
  if (!res.ok) return [];
  const data = await res.json();
  if (!data.subdomains) return [];
  const all = data.subdomains.map(sub => `${sub}.${parent}`.toLowerCase());
  if (!all.includes(parent)) all.unshift(parent);
  return [...new Set(all)];
}

// --- SecurityTrails: get detail domain ---
async function getDomainDetailSecurityTrails(domain) {
  const parent = getParentDomain(domain);
  const url = `https://api.securitytrails.com/v1/domain/${domain}`;
  const res = await fetch(url, {
    headers: { 'APIKEY': SECURITYTRAILS_API_KEY }
  });
  if (!res.ok) return 'Data tidak ditemukan di SecurityTrails.';
  const data = await res.json();
  let ip = '-';
  if (data.current_dns && data.current_dns.a && data.current_dns.a.values?.length)
    ip = data.current_dns.a.values[0];
  let asn = data.current_dns?.a?.record_details?.asn || '-';
  let registrar = data.registrar || '-';
  let created = data.created || '-';
  let updated = data.updated || '-';
  let status = (data.current_dns && data.current_dns.a && data.current_dns.a.values?.length) ? 'Aktif' : 'Tidak aktif';
  return `- Status: ${status}
- IP: ${ip}
- ASN: ${asn}
- Registrar: ${registrar}
- Dibuat: ${created}
- Update: ${updated}
- Parent: ${parent}`;
}

// --- Real HTTP test ---
async function checkHTTP(domain) {
  try {
    const res = await fetch(`http://${domain}`, { method: 'GET', timeout: 5000 });
    return res.status === 200
      ? '✅ HTTP: Bisa digunakan (200 OK)'
      : `❌ HTTP: Status ${res.status}`;
  } catch {
    return '❌ HTTP: Tidak bisa';
  }
}

// --- Real SSL/SNI test ---
async function checkSSL(domain) {
  return new Promise((resolve) => {
    const options = {
      host: domain,
      servername: domain,
      port: 443,
      timeout: 5000,
      rejectUnauthorized: false,
    };
    const socket = tls.connect(options, () => {
      if (socket.authorized || !socket.authorizationError) {
        resolve('✅ SSL/SNI: Bisa digunakan');
      } else {
        resolve('❌ SSL/SNI: Tidak bisa');
      }
      socket.end();
    });
    socket.on('error', () => resolve('❌ SSL/SNI: Tidak bisa'));
    socket.setTimeout(5000, () => {
      resolve('❌ SSL/SNI: Timeout');
      socket.destroy();
    });
  });
}

// --- Real CONNECT test (TCP 443) ---
async function checkConnect(domain) {
  return new Promise((resolve) => {
    const socket = net.connect(443, domain, () => {
      resolve('✅ CONNECT: Bisa digunakan');
      socket.end();
    });
    socket.on('error', () => resolve('❌ CONNECT: Tidak bisa'));
    setTimeout(() => {
      resolve('❌ CONNECT: Timeout');
      socket.destroy();
    }, 5000);
  });
}

// --- Real WebSocket test ---
async function checkWebSocket(domain) {
  // Only checks if TCP port 80 or 443 open (real WS handshake needs client)
  return new Promise((resolve) => {
    const socket = net.connect(80, domain, () => {
      resolve('✅ WebSocket (tcp:80): Bisa dibuka');
      socket.end();
    });
    socket.on('error', () => resolve('❌ WebSocket (tcp:80): Tidak bisa'));
    setTimeout(() => {
      resolve('❌ WebSocket (tcp:80): Timeout');
      socket.destroy();
    }, 5000);
  });
}

// --- Real X-Online-Host test ---
async function checkXOnlineHost(domain) {
  try {
    const res = await fetch(`http://${domain}`, {
      method: 'GET',
      headers: { 'X-Online-Host': domain },
      timeout: 5000,
    });
    return res.status === 200
      ? '✅ X-Online-Host: Bisa digunakan (200 OK)'
      : `❌ X-Online-Host: Status ${res.status}`;
  } catch {
    return '❌ X-Online-Host: Tidak bisa';
  }
}

// --- Real Payload test ---
async function checkPayloads(domain) {
  const results = [];
  // HTTP Host payload
  try {
    const res = await fetch(`http://${domain}`, { method: 'GET', timeout: 5000 });
    results.push(`1. GET / HTTP/1.1 Host: ${domain} ➡️ Status: ${res.status}`);
  } catch {
    results.push('1. GET / HTTP/1.1 Host: ... ➡️ Gagal koneksi');
  }
  // X-Online-Host
  try {
    const res = await fetch(`http://${domain}`, {
      method: 'GET',
      headers: { 'X-Online-Host': domain },
      timeout: 5000,
    });
    results.push(`2. X-Online-Host: ${domain} ➡️ Status: ${res.status}`);
  } catch {
    results.push('2. X-Online-Host: ... ➡️ Gagal koneksi');
  }
  // CONNECT
  try {
    await new Promise((resolve, reject) => {
      const socket = net.connect(443, domain, () => {
        results.push('3. CONNECT ke 443 ➡️ Success');
        socket.end();
        resolve();
      });
      socket.on('error', () => {
        results.push('3. CONNECT ke 443 ➡️ Gagal');
        resolve();
      });
      setTimeout(() => {
        results.push('3. CONNECT ke 443 ➡️ Timeout');
        socket.destroy();
        resolve();
      }, 5000);
    });
  } catch {
    results.push('3. CONNECT ke 443 ➡️ Gagal');
  }
  return results.join('\n');
}

// --- Main Menu ---
function getMainMenu() {
  return Markup.inlineKeyboard([
    [Markup.button.callback('🔎 Cek Metode Host/Domain', 'menu_method')],
    [Markup.button.callback('🟢 Cek Host/Domain Aktif', 'menu_active')],
    [Markup.button.callback('🧩 Cek Payload yang Cocok', 'menu_payload')],
    [Markup.button.callback('📱 Cek Domain Operator/Bug Lain', 'menu_operator')],
    [Markup.button.callback('ℹ️ Bantuan', 'menu_help')]
  ]);
}

// --- Start/Help Handler ---
bot.start((ctx) => {
  userState[ctx.from.id] = {};
  ctx.reply(
    '👋 Selamat datang di Bot Tester Bug (Real)! Silakan pilih menu di bawah ini:',
    getMainMenu()
  );
});

bot.action('menu_method', (ctx) => {
  userState[ctx.from.id] = { mode: 'method' };
  ctx.editMessageText('🔎 Kirim domain/host yang ingin dicek metodenya (satu per baris).');
});
bot.action('menu_active', (ctx) => {
  userState[ctx.from.id] = { mode: 'active' };
  ctx.editMessageText('🟢 Kirim domain/host yang ingin dicek status aktifnya.');
});
bot.action('menu_payload', (ctx) => {
  userState[ctx.from.id] = { mode: 'payload' };
  ctx.editMessageText('🧩 Kirim domain/host yang ingin dicek payload yang cocok.');
});
bot.action('menu_operator', (ctx) => {
  userState[ctx.from.id] = { mode: 'operator' };
  ctx.editMessageText('📱 Kirim bug/domain yang ingin dicari bug/domain lain yang berhubungan (subdomain/operator).');
});
bot.action('menu_help', (ctx) => {
  userState[ctx.from.id] = {};
  ctx.editMessageText(
    `ℹ️ Panduan Bot Tester Bug (Real)

1. Pilih menu sesuai kebutuhan:
   - 🔎 Cek Metode Host/Domain (Real)
   - 🟢 Cek Host/Domain Aktif (Real)
   - 🧩 Cek Payload yang Cocok (Real)
   - 📱 Cek Domain Operator/Bug Lain (Real, subdomain live SecurityTrails)

2. Ikuti instruksi berikutnya.
3. Hasil akan tampil rapi & interaktif.

Tips: Klik domain pada hasil pencarian untuk melihat detailnya!`
  );
});

// --- Main Message Handler ---
bot.on('text', async (ctx) => {
  const state = userState[ctx.from.id] || {};
  const mode = state.mode;
  const text = ctx.message.text.trim();

  if (!mode) {
    return ctx.reply('Silakan pilih menu dari /start terlebih dahulu.');
  }

  if (mode === 'method') {
    // Cek metode host/domain (real logic)
    const domain = text.split(/\s+/)[0];
    ctx.reply('🔎 Mengecek metode, mohon tunggu...');
    const [http, ssl, connect, ws, xOnlineHost] = await Promise.all([
      checkHTTP(domain),
      checkSSL(domain),
      checkConnect(domain),
      checkWebSocket(domain),
      checkXOnlineHost(domain),
    ]);
    ctx.reply(
      `🔎 Hasil Cek Metode untuk: ${domain}\n\n` +
      [http, ssl, ws, connect, xOnlineHost].join('\n')
    );
  } else if (mode === 'active') {
    const domain = text.split(/\s+/)[0];
    let ip = '-';
    try {
      const result = await dns.lookup(domain);
      ip = result.address;
      ctx.reply(`🟢 Status Host/Domain: ${domain}\n\n- Status: Aktif ✅\n- IP: ${ip}`);
    } catch (e) {
      ctx.reply(`🟢 Status Host/Domain: ${domain}\n\n❌ Tidak dapat di-resolve (kemungkinan mati/null route).`);
    }
  } else if (mode === 'payload') {
    const domain = text.split(/\s+/)[0];
    ctx.reply('🧩 Mengecek payload, mohon tunggu...');
    const result = await checkPayloads(domain);
    ctx.reply(`🧩 Payload result untuk: ${domain}\n\n${result}`);
  } else if (mode === 'operator') {
    ctx.reply('🔎 Mencari bug/domain yang berhubungan, mohon tunggu...');
    const related = await getSubdomainsSecurityTrails(text);
    if (!related.length) {
      ctx.reply('Tidak ada domain/bug terkait ditemukan.');
    } else {
      // Batas maksimal 40 tombol agar tidak error Telegram
      const rows = related.slice(0, 40).map(d =>
        [Markup.button.callback(d, `detail:${d}`)]
      );
      ctx.reply(
        `📱 Bug/Domain yang berhubungan dengan: ${text}\n\nKlik salah satu untuk detail:`,
        Markup.inlineKeyboard(rows)
      );
    }
  }
});

// --- Handler tombol domain detail ---
bot.action(/detail:(.+)/, async (ctx) => {
  const domain = ctx.match[1];
  ctx.answerCbQuery('Mengambil detail...');
  const info = await getDomainDetailSecurityTrails(domain);
  ctx.reply(`ℹ️ Detail domain: ${domain}\n${info}`);
});

// --- Jalankan bot ---
bot.launch();
console.log('Bot Telegram tester bug REAL aktif!');

process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
