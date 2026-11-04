[English](README.md) | [Русский](README.ru.md) | **[فارسی](README.fa.md)** | [简体中文](README.zh.md)

# xui-doctor

ابزاری کوچک و فقط‌خواندنی برای بررسی سلامت و تنظیمات پنل‌های
[3x-ui](https://github.com/MHSanaei/3x-ui) و فورک آن
[still-ui](https://github.com/Dv2Corn/still-ui).

این ابزار وارد API پنل می‌شود، وضعیت سرور، اینباندها، هاست‌ها و تنظیمات را
می‌خواند و هر چیزی را که خراب یا پرخطر است، دسته‌بندی‌شده بر اساس شدت، چاپ
می‌کند؛ برای هر مورد هم یک خط راه‌حل می‌آورد. هیچ چیزی را در پنل تغییر
نمی‌دهد.

خروجی روی یک پنل آزمایشی یک‌بارمصرف (خط‌های بلند با "..." کوتاه شده‌اند):

```
$ XUI_API_TOKEN=... xui-doctor check --url http://127.0.0.1:12053/doctor-test/
xui-doctor v0.1.0: http://127.0.0.1:12053/doctor-test
panel: 3x-ui 3.11.0, Xray 26.10.21, auth: API token

== CRITICAL ==
- [xray] inbound #1 "reality-ios" (vless, port 24443): Xray 26.10.21 (>= 26.9.8) refuses REALITY
  ClientHellos without an X25519MLKEM768 key share; share links here use fp=ios, which has none,
  so clients using them cannot connect
  fix: Set the uTLS fingerprint to chrome, firefox or safari and let clients refresh the
  subscription, or pin Xray 26.6.27 in the panel's Xray version switcher ...
- [xray] host "edge-host" -> inbound #1 "reality-ios" (vless, port 24443): ... this host has
  "Mihomo X25519" on, so its Clash subscription turns ML-KEM off and mihomo clients are refused
- [tls] inbound #4 "trojan-tls-inline" (trojan, port 24445) inline certificate: certificate
  expired on 2026-11-01 23:25 UTC
  fix: Replace the inline certificate with a renewed one.

== WARN ==
- [xray] REALITY clients: ... sing-box based clients (sing-box, Hiddify, Karing, NekoBox; tested
  1.12.12 and 1.14.4) cannot connect with any fingerprint; ...
- [clients] clients: 1 client has an IP limit (limitIp) but fail2ban is not usable on the panel
  host (enabled=no, installed=no, usable=no), so the limit is not enforced
- [security] login: two-factor authentication is off
  fix: Enable it in Settings -> Authentication -> Two-factor authentication.

== INFO ==
- [tls] TLS inbounds: 1 certificate file not checked; run with --local on the panel host to read them

summary: 4 critical, 3 warn, 1 info, 3 ok
(OK lines hidden; use --verbose to show them)
```

## پنل‌های پشتیبانی‌شده

| پنل | آزموده با | توضیح |
|---|---|---|
| 3x-ui (MHSanaei) | v3.11.0 (ایمیج Docker `ghcr.io/mhsanaei/3x-ui:v3.11.0`) | API نسخهٔ v3.x؛ پنل‌های قدیمی‌تر 2.x شاید تا حدی کار کنند (آزموده نشده) |
| still-ui (Dv2Corn) | v1.3.0 (آرشیو انتشار) | از روی فیلد `upstreamVersion` در وضعیت سرور شناخته می‌شود |

ابزار می‌گوید کدام پنل را پیدا کرده است. در بررسی نسخه، 3x-ui با آخرین انتشار
`MHSanaei/3x-ui` و still-ui با آخرین انتشار `Dv2Corn/still-ui` مقایسه می‌شود.

## نصب

```
go install github.com/Dv2Corn/xui-doctor/cmd/xui-doctor@latest
```

یا یک فایل اجرایی ایستا بسازید (بدون CGO، فقط کتابخانهٔ استاندارد):

```
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o xui-doctor ./cmd/xui-doctor
```

## استفاده

```
xui-doctor check --url https://HOST:PORT/BASEPATH/ [--insecure] [--json] [--local]
                 [--dial-targets] [--offline] [--verbose] [--timeout 20s] [--lang en|ru]
```

اطلاعات ورود فقط از متغیرهای محیطی خوانده می‌شود تا در تاریخچهٔ شل یا فهرست
پردازش‌ها نماند:

| متغیر | معنا |
|---|---|
| `XUI_API_TOKEN` | توکن API (Settings -> Authentication -> API tokens). توکن *Administrator* همه چیز را می‌خواند؛ توکن *Monitoring* فقط اجازهٔ بررسی‌های Xray و نسخه را می‌دهد. |
| `XUI_USERNAME`، `XUI_PASSWORD` | نام کاربری و رمز پنل، وقتی توکنی تنظیم نشده باشد |
| `XUI_2FA_CODE` | کد فعلی ورود دومرحله‌ای، اگر 2FA روشن باشد |
| `XUI_URL` | مقدار پیش‌فرض `--url` |

| پرچم | معنا |
|---|---|
| `--url` | نشانی پنل همراه با مسیر URI آن (base path)؛ نشانی‌ای که نام کاربری و رمز داخلش باشد پذیرفته نمی‌شود |
| `--insecure` | پذیرفتن گواهی خودامضا یا گواهی صادرشده برای نام دیگر |
| `--json` | خروجی ماشین‌خوان |
| `--local` | ابزار روی سرور پنل اجرا می‌شود: فایل‌های گواهی و سوکت‌های در حال گوش‌دادن (`/proc/net`) را هم می‌خواند و مقصدهای REALITY را از همان‌جا می‌آزماید (مقصدهای محلی و خصوصی هم) |
| `--dial-targets` | مقصدهای REALITY را از همان جایی که ابزار اجرا می‌شود می‌آزماید (در گزارش هم همین گفته می‌شود: ممکن است سرور پنل نباشد)؛ مقصدهایی که به loopback، نشانی خصوصی، link-local، CGNAT، نشانی‌های مستندسازی، NAT64/6to4 یا دیگر نشانی‌های ویژهٔ IANA می‌رسند، کنار گذاشته می‌شوند |
| `--offline` | از GitHub آخرین انتشار را نمی‌پرسد |
| `--verbose` | خط‌های OK را هم چاپ می‌کند |
| `--lang` | زبان خروجی، `en` یا `ru`؛ بدون آن، locale روسی (مقدار `LC_ALL`، `LC_MESSAGES` یا `LANG` که با `ru` شروع شود، به همین ترتیب) خروجی را روسی می‌کند و در غیر این صورت انگلیسی است |

کدهای خروج: `0` چیزی جدی‌تر از INFO نیست، `1` هشدار، `2` مورد بحرانی، `3`
بررسی انجام نشد (نشانی نادرست، ورود رد شد، ...).

### زبان خروجی

خروجی متنی فعلاً فقط انگلیسی یا روسی است؛ فارسی و چینی هنوز وجود ندارد.
پیش‌فرض انگلیسی است. با `--lang ru` روسی می‌شود؛ بدون این پرچم، اولین متغیر
غیرخالی از میان `LC_ALL`، `LC_MESSAGES` و `LANG` تصمیم می‌گیرد: اگر با `ru`
شروع شود (مثلاً `ru_RU.UTF-8`) خروجی روسی است و هر مقدار دیگری، از جمله
`fa_IR.UTF-8` یا `zh_CN.UTF-8`، خروجی انگلیسی می‌دهد. `--lang en` در هر
locale خروجی را انگلیسی می‌کند.

خروجی `--json` همیشه انگلیسی است و هر مورد یک `id` ثابت پیام دارد تا
اسکریپت‌ها به متن پیام یا locale وابسته نباشند.

### چه چیزی ارسال می‌کند

فقط این درخواست‌ها، نسبت به نشانی پنل:

- نشست خود ابزار (با توکن لازم نیست): `GET /csrf-token`، `POST /login`، `POST /logout`؛
- خواندن داده‌ها: `GET /panel/api/server/status`، `GET /panel/api/inbounds/list`،
  `GET /panel/api/hosts/list`، `GET /panel/api/server/fail2banStatus`؛
- و `POST /panel/api/setting/all` که آن هم فقط خواندن است؛ پنل آن را با POST
  مسیریابی می‌کند و مقدارهای محرمانه (توکن ربات‌ها، رمز 2FA) را در پاسخ خالی
  می‌کند.

با `--local` یا `--dial-targets` با مقصدهای REALITY دست‌دهی TLS هم انجام
می‌دهد: هر نام یک بار resolve می‌شود و اتصال به همان نشانی بررسی‌شده می‌رود
(مهلت 5 ثانیه، حداکثر 20 دست‌دهی در هر اجرا؛ موارد کنارگذاشته فهرست
می‌شوند). بدون `--local` هرگز به نشانی غیرعمومی مقصد وصل نمی‌شود؛ نشانی‌ای
که واقعاً به آن وصل می‌شود هم دوباره بررسی می‌شود.

و اگر `--offline` نباشد، یک درخواست بدون احراز هویت به
`api.github.com/repos/<repo>/releases/latest`. UUID و رمز کلاینت‌ها و
کلیدهای خصوصی REALITY فقط برای مقایسه با هم در حافظه خوانده می‌شوند و هرگز
چاپ نمی‌شوند.

## بررسی‌ها

| ID | چه چیزی را می‌بیند |
|---|---|
| `xray` | وضعیت و نسخهٔ Xray در برابر تغییرات REALITY (پایین‌تر)؛ اثر انگشت uTLS اینباندهای REALITY و هاست‌های اشتراک؛ کلید "Mihomo X25519" هاست‌ها |
| `reality` | target، serverNames، privateKey و shortIds دقیقاً همان‌طور که Xray-core بررسی می‌کند؛ کلید عمومی خالی برای لینک‌ها؛ `show`؛ با `--local`/`--dial-targets`: TLS 1.3، h2 و گواهی معتبر برای هر serverName در مقصد |
| `tls` | انقضای گواهی‌های درون‌خطی اینباندهای TLS و گواهی‌ای که پنل ارائه کرد؛ با `--local` فایل‌های گواهی اینباندها، پنل و سرور اشتراک هم (منقضی: CRITICAL، کمتر از 7 روز: WARN) |
| `ports` | اینباندهای فعال (و پنل / سرور اشتراک) که یک پورت و یک ترابری را روی یک نشانی می‌گیرند، با همان قواعد TCP/UDP خود پنل؛ با `--local` اینباندهای فعالی که کسی رویشان گوش نمی‌دهد |
| `clients` | کلاینت‌هایی که تاریخشان گذشته یا حجمشان تمام شده ولی هنوز فعال‌اند؛ دو کلاینت با یک UUID/رمز در یک اینباند؛ محدودیت IP وقتی fail2ban کار نمی‌کند |
| `security` | admin/admin (فقط اگر ابزار را با همین اجرا کرده باشید)، HTTP ساده، مسیر URI برابر `/`، پورت پیش‌فرض 2053 و مسیرهای پیش‌فرض اشتراک، 2FA خاموش، وجود توکن ربات Telegram |
| `version` | نسخهٔ پنل در برابر آخرین انتشار GitHub |

اینباندهایی که روی نودهای دوردست اجرا می‌شوند در بررسی‌هایی که به Xray محلی
وابسته‌اند کنار گذاشته می‌شوند؛ ابزار را برای هر نود جداگانه اجرا کنید.

### بررسی‌هایی که سنجیده و کنار گذاشته شدند

- *یک ایمیل روی چند اینباند* - از 3x-ui 3.x هر کلاینت یک رکورد است که عمداً
  می‌تواند به چند اینباند وصل باشد.
- *قالب spiderX* - پنل برای هر کلاینت یک `spx` می‌سازد که همیشه با `/`
  شروع می‌شود.
- *خواندن نسخهٔ فایل اجرایی Xray روی دیسک* - API وضعیت همین حالا نسخهٔ هستهٔ
  در حال اجرا را گزارش می‌کند.
- *حدس زدن اطلاعات ورود پیش‌فرض* - ابزار هرگز رمزی را امتحان نمی‌کند؛ فقط
  وقتی خودتان آن را با admin/admin اجرا کرده باشید این را علامت می‌زند.

## چرا بررسی Xray لازم است

دو تغییر در سرور رسمی REALITY در Xray-core کلاینت‌هایی را که قبلاً کار
می‌کردند از کار می‌اندازد و پنل چیزی دربارهٔ آن نمی‌گوید:

1. **از 26.7.11 تا 26.7.28:** مقدار پیش‌فرض `minClientVer` در سرورهای REALITY
   برابر 26.3.27 است
   ([Xray-core af7eb680](https://github.com/XTLS/Xray-core/commit/af7eb68028732a8ee3c0e5d6ab2b8a657bb2e770)).
   کلاینت‌هایی که نسخهٔ Xray نمی‌فرستند (sing-box، mihomo) و کلاینت‌های Xray
   قدیمی‌تر از 26.3.27 رد می‌شوند، مگر اینکه `minClientVer` در اینباند صریحاً
   تنظیم شده باشد.
2. **از 26.9.8 به بعد:** سرور هر ClientHello را که پیش از X25519 اختیاری،
   کلید X25519MLKEM768 نداشته باشد رد می‌کند
   ([XTLS/REALITY 8cdf7bf9](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8)،
   که با
   [47cfe999](https://github.com/XTLS/Xray-core/commit/47cfe9994a6b39b1f673ba35e62b091bcce15a71) وارد Xray-core شد، نخستین بار در
   v26.9.8؛ این تگ در مخزن اصلی حذف شد و v26.9.9 نخستین انتشار منتشرشده
   است). در همان انتشار مقدار پیش‌فرض `minClientVer` دوباره کامنت شده است.
   hello ردشده مانند بازدیدکنندهٔ غیر REALITY به مقصد فرستاده می‌شود، پس
   کلاینت گواهی واقعی مقصد را می‌بیند.

جدول آزمون (فایل‌های اجرایی رسمی، همه روی loopback، مقصد `www.nvidia.com`،
4 درخواست برای هر خانه؛ اسکریپت در [`tools/reality-matrix`](tools/reality-matrix)):

| سرور | کلاینت Xray با chrome / firefox / safari | کلاینت Xray با ios / edge / qq | sing-box 1.12.12 و 1.14.4، هر fp | mihomo 1.19.33 | mihomo + `support-x25519mlkem768: true`، chrome |
|---|---|---|---|---|---|
| 26.6.27 | ok | ok | ok | ok | ok |
| 26.7.28 | ok | ok | رد | رد | رد |
| 26.9.9 | ok | **رد** | **رد** | **رد** | ok |
| 26.10.31 | ok | **رد** | **رد** | **رد** | ok |

کلاینت‌های Xray نسخهٔ 26.6.27 و 26.10.31 یکسان رفتار می‌کنند. `android` و
`360` در این آزمون با هیچ سروری کار نکردند؛ `random`/`randomized*` برای هر
اتصال hello دیگری انتخاب می‌کنند و فقط گاهی کار می‌کنند. نتیجهٔ سرتاسری از
طریق پنل هم همین بود: روی 3x-ui 3.11.0 (با Xray 26.10.21 همراهش) و still-ui
1.3.0 (Xray 26.10.31)، اینباندی با `fp=ios` برای کلاینت Xray با fp ios نتیجهٔ
0/3، با chrome و safari نتیجهٔ 3/3 و برای sing-box 1.14.4 نتیجهٔ 0/3 داد.

چه باید کرد، همان‌طور که گزارش می‌گوید: اثر انگشت لینک را به chrome، firefox
یا safari تغییر دهید، یا در انتخاب نسخهٔ Xray در پنل، Xray 26.6.27 را ثابت
کنید. hello با ML-KEM بزرگ‌تر است - اندازه‌گیری با Xray 26.10.31: chrome 1820،
firefox 1889، safari 1537 بایت در برابر 517 برای ios/edge/qq - و به دو قطعهٔ
TCP نیاز دارد که برخی شبکه‌های موبایل با آن مشکل دارند. اشتراک Clash خود
پنل از قبل برای کلاینت‌های mihomo مقدار `support-x25519mlkem768: true` را
می‌گذارد؛ هاستی که "Mihomo X25519" در آن روشن باشد این را خاموش می‌کند.

هسته‌ای که وصله شده و هنوز hello قدیمی را می‌پذیرد، همان رشتهٔ نسخه را گزارش
می‌کند؛ ابزار نمی‌تواند این دو را از هم تشخیص دهد، پس موارد `xray` را با
این نکته بخوانید.

## توسعه

```
go vet ./...
go test ./...
```

پیام‌ها در `internal/i18n/catalog.go` به انگلیسی و روسی هستند. اگر پیامی
متن روسی نداشته باشد، اگر دو متن فعل‌های قالب‌بندی (`%s`، `%d`، ...) متفاوتی
داشته باشند، یا اگر کد از IDای استفاده کند که در کاتالوگ نیست، آزمون شکست
می‌خورد.

`testdata/` پاسخ‌هایی را نگه می‌دارد که از پنل‌های آزمایشی یک‌بارمصرف 3x-ui
3.11.0 و still-ui 1.3.0 ضبط شده‌اند و UUIDها، کلیدها، رمزها و GUIDها در
آن‌ها با مقدارهای ساختگی جایگزین شده‌اند. `internal/doctor` آن‌ها را از طریق
یک پنل جعلی با همان قواعد CSRF و نشست پخش می‌کند و هر درخواستی بیرون از
مجموعهٔ فقط‌خواندنی بالا آزمون را شکست می‌دهد.

## مجوز

MIT. وابسته به پروژه‌های 3x-ui یا Xray-core نیست.
