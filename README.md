# open-pay

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ramtinahmadi1020-create/open-pay)

یک درگاه پرداخت کارت به کارت امن و سرورلس بر پایه Cloudflare Workers.

## ویژگی‌ها

- پنل مدیریت امن با رمز عبور
- مدیریت چندین کارت بانکی بلو
- ساخت لینک‌های پرداخت یکبارمصرف
- تأیید خودکار تراکنش‌های بلو بانک
- ارسال Webhook با امضای HMAC
- رابط کاربری زیبا و واکنش‌گرا با فونت فارسی

## راه‌اندازی سریع

1. روی دکمه "Deploy to Cloudflare" در بالای همین صفحه کلیک کنید.
2. مخزن را به حساب Cloudflare خود متصل کنید.
3. مقادیر متغیرهای محیطی را وارد کنید (رمز ادمین، اطلاعات بلو بانک و ...).
4. پس از دیپلوی، به آدرس `https://open-pay.YOUR_SUBDOMAIN.workers.dev/admin/login` بروید و با رمز عبور وارد شوید.

## متغیرهای محیطی

| نام متغیر | توضیح |
|-----------|-------|
| `ADMIN_PASSWORD` | رمز عبور پنل مدیریت |
| `BLU_USERNAME` | نام کاربری بلو بانک |
| `BLU_PASSWORD` | رمز عبور بلو بانک |
| `TELEGRAM_BOT_TOKEN` | توکن ربات تلگرام (اختیاری) |
| `TELEGRAM_CHAT_ID` | چت آیدی تلگرام (اختیاری) |
| `HMAC_SECRET` | کلید مخفی برای امضای Webhook |

## لایسنس

MIT
