// ===================================================================
// بخش اول: واردات و تنظیمات اولیه
// ===================================================================
import { connect } from '@cloudflare/puppeteer';

// ===================================================================
// بخش دوم: توابع کمکی (امنیت، توکن، اعتبارسنجی)
// ===================================================================
const encoder = new TextEncoder();

async function generateToken(length = 32) {
  const buffer = new Uint8Array(length);
  crypto.getRandomValues(buffer);
  return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateHMAC(secret, payload) {
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashToken(token) {
  const buffer = await crypto.subtle.digest('SHA-256', encoder.encode(token));
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===================================================================
// بخش سوم: Durable Object برای مدیریت Session بلو بانک
// ===================================================================
export class BrowserSession {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === '/otp') {
      const { otp } = await request.json();
      await this.state.storage.put('pending_otp', otp);
      return new Response('OTP received');
    }

    if (url.pathname === '/login') {
      return await this.login();
    }

    const transactions = await this.fetchTransactions();
    return new Response(JSON.stringify(transactions), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async login() {
    const { puppeteer } = this.env;
    const browser = await puppeteer.launch(this.env.MY_BROWSER);
    const page = await browser.newPage();

    try {
      await page.goto('https://blubank.example/login', {
        waitUntil: 'domcontentloaded', timeout: 20000
      });

      await page.type('#username', this.env.BLU_USERNAME);
      await page.type('#password', this.env.BLU_PASSWORD);
      await page.click('#login-button');

      const otp = await this.waitForOTP();
      await page.type('#otp-input', otp);
      await page.click('#verify-button');
      await page.waitForNavigation({ timeout: 30000 });

      const cookies = await page.cookies();
      const cookieString = cookies.map(c => `${c.name}=${c.value}`).join('; ');
      await this.state.storage.put('cookie', cookieString);
      await this.state.storage.put('cookie_time', Date.now());

      await browser.disconnect();
      return new Response('Logged in');
    } catch (err) {
      await browser.disconnect().catch(() => {});
      return new Response('Login failed: ' + err.message, { status: 500 });
    }
  }

  async fetchTransactions() {
    const cookie = await this.state.storage.get('cookie');

    if (cookie) {
      try {
        const res = await fetch('https://blubank.example/api/transactions', {
          headers: {
            'Cookie': cookie,
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/json'
          }
        });

        if (res.ok) {
          const data = await res.json();
          return data.map(tx => ({
            id: tx.id,
            amount: tx.amount,
            cardLast4: tx.cardNumber?.slice(-4) || '????',
            timestamp: tx.date
          }));
        }
      } catch (e) {
        // Cookie منقضی شده است
      }
    }

    await this.login();
    return [];
  }

  async waitForOTP() {
    return new Promise((resolve) => {
      const check = async () => {
        const otp = await this.state.storage.get('pending_otp');
        if (otp) {
          await this.state.storage.delete('pending_otp');
          resolve(otp);
        } else {
          setTimeout(check, 3000);
        }
      };
      check();
    });
  }
}

// ===================================================================
// بخش چهارم: Worker اصلی (روتر و منطق اصلی)
// ===================================================================
export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(checkTransactions(env));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith('/admin') && path !== '/admin/login' && path !== '/admin/auth') {
      const cookie = request.headers.get('Cookie') || '';
      const sessionToken = cookie.split('; ').find(row => row.startsWith('admin_session='))?.split('=')[1];

      if (!sessionToken || !(await env.PAYMENT_TOKENS.get(`session:${sessionToken}`))) {
        return Response.redirect(`${url.origin}/admin/login`, 302);
      }
    }

    if (path === '/') {
      return new Response('open-pay is running', { status: 200 });
    }

    if (path === '/admin/login') {
      return new Response(renderLoginPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/admin/auth' && request.method === 'POST') {
      const formData = await request.formData();
      const password = formData.get('password');

      if (password === env.ADMIN_PASSWORD) {
        const sessionToken = await generateToken(16);
        await env.PAYMENT_TOKENS.put(`session:${sessionToken}`, 'valid', { expirationTtl: 3600 });

        const headers = new Headers();
        headers.set('Set-Cookie', `admin_session=${sessionToken}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`);
        headers.set('Location', '/admin/dashboard');
        return new Response(null, { status: 302, headers });
      }

      return new Response(renderLoginPage('رمز عبور اشتباه است'), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/admin/dashboard') {
      const cards = await env.DB.prepare('SELECT * FROM cards ORDER BY created_at DESC').all();
      const gateways = await env.DB.prepare('SELECT g.*, c.card_number FROM payment_gateways g JOIN cards c ON g.card_id = c.id ORDER BY g.created_at DESC').all();

      return new Response(renderDashboard(cards.results, gateways.results), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/admin/cards' && request.method === 'POST') {
      const { card_number, holder_name } = await request.json();
      try {
        await env.DB.prepare(
          'INSERT INTO cards (card_number, holder_name) VALUES (?, ?)'
        ).bind(card_number, holder_name).run();

        return new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return new Response(JSON.stringify({ success: false, error: 'این کارت قبلاً ثبت شده است.' }), {
            status: 409,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        return new Response(JSON.stringify({ success: false, error: 'خطای داخلی سرور' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    if (path === '/admin/gateways' && request.method === 'POST') {
      const { card_id, title, amount, expires_in_minutes, redirect_url } = await request.json();

      const expiresAt = new Date(Date.now() + expires_in_minutes * 60 * 1000).toISOString();
      const gatewayId = await generateToken(16);

      await env.DB.prepare(
        'INSERT INTO payment_gateways (id, card_id, title, amount, expires_at, redirect_url) VALUES (?, ?, ?, ?, ?, ?)'
      ).bind(gatewayId, card_id, title, amount, expiresAt, redirect_url).run();

      return new Response(JSON.stringify({ success: true, gatewayId }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (path.startsWith('/p/')) {
      const gatewayId = path.split('/p/')[1];
      if (!gatewayId) return new Response('لینک نامعتبر است', { status: 400 });

      const gateway = await env.DB.prepare(
        'SELECT g.*, c.card_number, c.holder_name FROM payment_gateways g JOIN cards c ON g.card_id = c.id WHERE g.id = ?'
      ).bind(gatewayId).first();

      if (!gateway) {
        return new Response('لینک پرداخت یافت نشد', { status: 404 });
      }

      if (gateway.status !== 'active' || new Date(gateway.expires_at) < new Date()) {
        return new Response('این لینک پرداخت منقضی شده یا قبلاً استفاده شده است.', { status: 410 });
      }

      return new Response(renderPaymentPage(gateway), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/api/confirm-payment' && request.method === 'POST') {
      const { gateway_id, amount, card_last4 } = await request.json();
      if (!gateway_id) return new Response('شناسه درگاه ارسال نشده', { status: 400 });

      const gateway = await env.DB.prepare(
        'SELECT * FROM payment_gateways WHERE id = ?'
      ).bind(gateway_id).first();

      if (!gateway || gateway.status !== 'active') {
        return new Response('درگاه نامعتبر یا غیرفعال است', { status: 410 });
      }

      if (gateway.amount !== amount) {
        return new Response('مبلغ پرداخت شده با مبلغ درگاه مطابقت ندارد', { status: 400 });
      }

      await env.DB.prepare(
        'UPDATE payment_gateways SET status = ?, paid_at = ? WHERE id = ?'
      ).bind('paid', new Date().toISOString(), gateway_id).run();

      if (gateway.redirect_url) {
        const webhookPayload = {
          event: 'payment.confirmed',
          gateway_id: gateway.id,
          amount: gateway.amount,
          title: gateway.title,
          paid_at: new Date().toISOString(),
        };
        const signature = await generateHMAC(env.HMAC_SECRET, JSON.stringify(webhookPayload));

        ctx.waitUntil(
          fetch(gateway.redirect_url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Signature': signature
            },
            body: JSON.stringify(webhookPayload)
          })
        );
      }

      return new Response('پرداخت با موفقیت تأیید شد.');
    }

    return new Response('Not Found', { status: 404 });
  }
};

// ===================================================================
// بخش پنجم: توابع بررسی تراکنش‌های بلو بانک (Cron Job)
// ===================================================================
async function checkTransactions(env) {
  const session = env.BROWSER_SESSION.get(env.BROWSER_SESSION.idFromName('main'));
  const response = await session.fetch('https://internal/check');
  const transactions = await response.json();

  for (const tx of transactions) {
    const exists = await env.DB.prepare(
      'SELECT 1 FROM seen_transactions WHERE id = ?'
    ).bind(tx.id).first();

    if (exists) continue;

    await env.DB.prepare(
      'INSERT INTO seen_transactions (id, amount, card_last4) VALUES (?, ?, ?)'
    ).bind(tx.id, tx.amount, tx.cardLast4).run();

    await sendTelegram(env, tx);
  }
}

async function sendTelegram(env, tx) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;

  const message = `پرداخت جدید!\n\nمبلغ: ${Number(tx.amount).toLocaleString('fa-IR')} تومان\nکارت: ****${tx.cardLast4}\nزمان: ${new Date().toLocaleString('fa-IR')}`;

  await fetch(
    `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text: message })
    }
  );
}

// ===================================================================
// بخش ششم: توابع رندر HTML (صفحات UI)
// ===================================================================
function renderLoginPage(error = '') {
  return `<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود به پنل مدیریت | open-pay</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
    <style>
        :root { --primary: #2563eb; --primary-hover: #1d4ed8; --bg: #f8fafc; --card-bg: #ffffff; --text: #1e293b; --text-light: #64748b; --border: #e2e8f0; --danger: #ef4444; --radius: 12px; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Vazirmatn', sans-serif; background: var(--bg); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1rem; }
        .login-container { background: var(--card-bg); border-radius: var(--radius); box-shadow: 0 10px 25px rgba(0, 0, 0, 0.05); padding: 3rem; width: 100%; max-width: 420px; }
        .logo { text-align: center; margin-bottom: 2rem; }
        .logo h1 { color: var(--primary); font-size: 1.8rem; font-weight: 700; }
        .logo p { color: var(--text-light); font-size: 0.9rem; margin-top: 0.5rem; }
        .form-group { margin-bottom: 1.5rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: var(--text); font-weight: 500; font-size: 0.9rem; }
        .form-group input { width: 100%; padding: 0.75rem 1rem; border: 2px solid var(--border); border-radius: 8px; font-family: 'Vazirmatn', sans-serif; font-size: 1rem; transition: border-color 0.2s; }
        .form-group input:focus { outline: none; border-color: var(--primary); }
        .btn { width: 100%; padding: 0.85rem; background: var(--primary); color: #fff; border: none; border-radius: 8px; font-family: 'Vazirmatn', sans-serif; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; }
        .btn:hover { background: var(--primary-hover); }
        .error { background: #fef2f2; color: var(--danger); padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.9rem; text-align: center; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>open-pay</h1>
            <p>پنل مدیریت درگاه‌های پرداخت</p>
        </div>
        ${error ? `<div class="error">${error}</div>` : ''}
        <form method="POST" action="/admin/auth">
            <div class="form-group">
                <label for="password">رمز عبور</label>
                <input type="password" id="password" name="password" placeholder="رمز عبور خود را وارد کنید" required autofocus>
            </div>
            <button type="submit" class="btn">ورود به پنل</button>
        </form>
    </div>
</body>
</html>`;
}

function renderDashboard(cards, gateways) {
  return `<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد مدیریت | open-pay</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
    <style>
        :root { --primary: #2563eb; --primary-hover: #1d4ed8; --bg: #f1f5f9; --card-bg: #ffffff; --text: #1e293b; --text-light: #64748b; --border: #e2e8f0; --success: #22c55e; --danger: #ef4444; --radius: 12px; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Vazirmatn', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; background: var(--card-bg); padding: 1.5rem 2rem; border-radius: var(--radius); box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }
        .header h1 { font-size: 1.5rem; font-weight: 700; color: var(--primary); }
        .header .logout-btn { color: var(--danger); text-decoration: none; font-weight: 500; font-size: 0.9rem; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
        @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
        .panel { background: var(--card-bg); border-radius: var(--radius); box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); padding: 2rem; }
        .panel h2 { font-size: 1.2rem; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 2px solid var(--border); }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.4rem; font-size: 0.85rem; font-weight: 500; color: var(--text-light); }
        .form-group input, .form-group select { width: 100%; padding: 0.7rem 1rem; border: 2px solid var(--border); border-radius: 8px; font-family: 'Vazirmatn', sans-serif; font-size: 0.9rem; transition: border-color 0.2s; }
        .form-group input:focus, .form-group select:focus { outline: none; border-color: var(--primary); }
        .btn { display: inline-block; padding: 0.7rem 1.5rem; background: var(--primary); color: #fff; border: none; border-radius: 8px; font-family: 'Vazirmatn', sans-serif; font-size: 0.9rem; font-weight: 600; cursor: pointer; transition: background 0.2s; }
        .btn:hover { background: var(--primary-hover); }
        .btn-full { width: 100%; }
        .card-item { background: var(--bg); padding: 1rem; border-radius: 8px; margin-bottom: 0.75rem; display: flex; justify-content: space-between; align-items: center; }
        .card-item .card-info { font-size: 0.9rem; }
        .card-item .card-info strong { display: block; }
        .card-item .card-info span { color: var(--text-light); font-size: 0.8rem; }
        .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 50px; font-size: 0.75rem; font-weight: 600; }
        .badge-active { background: #dcfce7; color: #166534; }
        .badge-paid { background: #dbeafe; color: #1e40af; }
        .badge-expired { background: #fee2e2; color: #991b1b; }
        .gateway-link { word-break: break-all; font-size: 0.8rem; color: var(--text-light); background: #f8fafc; padding: 0.5rem; border-radius: 4px; margin-top: 0.5rem; display: none; }
        .gateway-link.show { display: block; }
        .toast { position: fixed; bottom: 2rem; left: 50%; transform: translateX(-50%); background: var(--text); color: #fff; padding: 0.75rem 1.5rem; border-radius: 8px; font-size: 0.9rem; opacity: 0; transition: opacity 0.3s; pointer-events: none; }
        .toast.show { opacity: 1; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>open-pay</h1>
            <a href="/admin/logout" class="logout-btn">خروج</a>
        </div>
        <div class="grid">
            <div class="panel">
                <h2>کارت‌های بانکی</h2>
                <form id="cardForm">
                    <div class="form-group">
                        <label>شماره کارت (بلو)</label>
                        <input type="text" name="card_number" placeholder="XXXX-XXXX-XXXX-XXXX" required>
                    </div>
                    <div class="form-group">
                        <label>نام و نام خانوادگی صاحب کارت</label>
                        <input type="text" name="holder_name" placeholder="نام کامل" required>
                    </div>
                    <button type="submit" class="btn btn-full">افزودن کارت</button>
                </form>
                <div id="cardsList" style="margin-top: 1.5rem;">
                     ${cards.map(card => `
                        <div class="card-item">
                            <div class="card-info">
                                <strong>${card.card_number}</strong>
                                <span>${card.holder_name}</span>
                            </div>
                            <span class="badge badge-active">فعال</span>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="panel">
                <h2>ساخت درگاه پرداخت</h2>
                <form id="gatewayForm">
                    <div class="form-group">
                        <label>انتخاب کارت</label>
                        <select name="card_id" required>
                            <option value="">-- انتخاب کنید --</option>
                            ${cards.map(card => `
                                <option value="${card.id}">${card.card_number} - ${card.holder_name}</option>
                            `).join('')}
                        </select>
                    </div>
                    <div class="form-group">
                        <label>عنوان (مثلاً: خرید اشتراک)</label>
                        <input type="text" name="title" placeholder="عنوان پرداخت" required>
                    </div>
                    <div class="form-group">
                        <label>مبلغ (تومان)</label>
                        <input type="number" name="amount" placeholder="مثلاً: 50000" required>
                    </div>
                    <div class="form-group">
                        <label>مدت اعتبار (دقیقه)</label>
                        <input type="number" name="expires_in_minutes" value="30" required>
                    </div>
                    <div class="form-group">
                        <label>آدرس بازگشت پس از پرداخت (اختیاری)</label>
                        <input type="url" name="redirect_url" placeholder="https://example.com/callback">
                    </div>
                    <button type="submit" class="btn btn-full">ساخت لینک پرداخت</button>
                </form>
                <div id="gatewayResult" style="margin-top: 1.5rem;"></div>
            </div>
        </div>
    </div>
    <div id="toast" class="toast"></div>
    <script>
    const toast = (msg) => {
        const el = document.getElementById('toast');
        el.textContent = msg;
        el.classList.add('show');
        setTimeout(() => el.classList.remove('show'), 3000);
    };

    document.getElementById('cardForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        const data = {
            card_number: form.card_number.value,
            holder_name: form.holder_name.value
        };
        const res = await fetch('/admin/cards', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        const result = await res.json();
        if (result.success) {
            toast('کارت با موفقیت اضافه شد');
            setTimeout(() => location.reload(), 1000);
        } else {
            toast(result.error || 'خطا در افزودن کارت');
        }
    });

    document.getElementById('gatewayForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        const data = {
            card_id: form.card_id.value,
            title: form.title.value,
            amount: parseInt(form.amount.value),
            expires_in_minutes: parseInt(form.expires_in_minutes.value),
            redirect_url: form.redirect_url.value || null
        };
        const res = await fetch('/admin/gateways', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        const result = await res.json();
        if (result.success) {
            const link = window.location.origin + '/p/' + result.gatewayId;
            document.getElementById('gatewayResult').innerHTML =
                '<div style="background: #f0fdf4; padding: 1rem; border-radius: 8px; border: 1px solid #bbf7d0;">' +
                '<p style="font-weight: 600; margin-bottom: 0.5rem;">لینک پرداخت ساخته شد:</p>' +
                '<code style="word-break: break-all; font-size: 0.8rem; display: block; padding: 0.5rem; background: #fff; border-radius: 4px;">' + link + '</code>' +
                '</div>';
            toast('لینک پرداخت با موفقیت ساخته شد');
        } else {
            toast(result.error || 'خطا در ساخت لینک');
        }
    });
</script>
</body>
</html>`;
}

function renderPaymentPage(gateway) {
  const expiryMinutes = Math.round((new Date(gateway.expires_at) - Date.now()) / 60000);
  return `<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>پرداخت | ${gateway.title}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
    <style>
        :root { --primary: #2563eb; --bg: #f1f5f9; --card-bg: #ffffff; --text: #1e293b; --text-light: #64748b; --border: #e2e8f0; --radius: 16px; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Vazirmatn', sans-serif; background: var(--bg); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1rem; }
        .payment-card { background: var(--card-bg); border-radius: var(--radius); box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.1); padding: 3rem; width: 100%; max-width: 480px; text-align: center; }
        .payment-card .title { font-size: 1.5rem; font-weight: 700; color: var(--text); margin-bottom: 0.5rem; }
        .payment-card .subtitle { color: var(--text-light); font-size: 0.9rem; margin-bottom: 2rem; }
        .amount-box { background: linear-gradient(135deg, #2563eb, #1d4ed8); color: #fff; border-radius: var(--radius); padding: 2rem; margin-bottom: 2rem; }
        .amount-box .amount-label { font-size: 0.85rem; opacity: 0.8; margin-bottom: 0.5rem; }
        .amount-box .amount-value { font-size: 2rem; font-weight: 700; }
        .card-details { background: #f8fafc; border: 2px dashed var(--border); border-radius: var(--radius); padding: 1.5rem; margin-bottom: 2rem; }
        .card-details .card-label { font-size: 0.8rem; color: var(--text-light); margin-bottom: 0.5rem; }
        .card-details .card-number { font-size: 1.4rem; font-weight: 700; letter-spacing: 2px; color: var(--text); direction: ltr; }
        .card-details .holder-name { font-size: 0.9rem; color: var(--text-light); margin-top: 0.5rem; }
        .timer { display: flex; align-items: center; justify-content: center; gap: 0.5rem; color: var(--text-light); font-size: 0.85rem; }
        .timer .timer-value { font-weight: 700; color: var(--primary); }
        .note { font-size: 0.8rem; color: var(--text-light); margin-top: 2rem; line-height: 1.8; }
    </style>
</head>
<body>
    <div class="payment-card">
        <div class="title">${gateway.title}</div>
        <div class="subtitle">لطفاً مبلغ زیر را به کارت مشخص شده واریز کنید</div>

        <div class="amount-box">
            <div class="amount-label">مبلغ قابل پرداخت</div>
            <div class="amount-value">${Number(gateway.amount).toLocaleString('fa-IR')} تومان</div>
        </div>

        <div class="card-details">
            <div class="card-label">شماره کارت</div>
            <div class="card-number">${gateway.card_number}</div>
            <div class="holder-name">به نام: ${gateway.holder_name}</div>
        </div>

        <div class="timer">
            <span>زمان باقی‌مانده:</span>
            <span class="timer-value" id="timer">${expiryMinutes}</span>
            <span>دقیقه</span>
        </div>

        <div class="note">
            پس از واریز مبلغ، سیستم به‌صورت خودکار پرداخت شما را تأیید و شما را به صفحه بعدی هدایت می‌کند.
        </div>
    </div>
    <script>
    let minutes = ${expiryMinutes};
    const timerEl = document.getElementById('timer');
    setInterval(function() {
        minutes--;
        if (minutes <= 0) {
            timerEl.textContent = '0';
            alert('زمان پرداخت به پایان رسیده است.');
            location.reload();
        } else {
            timerEl.textContent = minutes;
        }
    }, 60000);
</script>
</body>
</html>`;
}
