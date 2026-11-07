package i18n

// entry is one message: a fmt format string per language. Both strings must
// use the same arguments with the same verbs; Russian may reorder them with
// explicit indexes (%[2]s). Arguments that are Texts or errors arrive as
// strings, so they take %s.
type entry struct{ en, ru string }

// messages is the catalog. IDs are stable: JSON output carries them.
var messages = map[string]entry{
	// Command line.
	"cli.usage": {
		en: `xui-doctor - read-only health and config checker for 3x-ui / still-ui panels

Usage:
  xui-doctor check --url https://HOST:PORT/BASEPATH/ [flags]
  xui-doctor version

Credentials come from the environment, never from flags:
  XUI_API_TOKEN               API token (Settings -> API Tokens; admin scope reads everything,
                              a monitor-scope token only allows the Xray/version checks)
  XUI_USERNAME, XUI_PASSWORD  panel login, used when no token is set
  XUI_2FA_CODE                current two-factor code, if 2FA is on

The tool sends GET requests plus POST /login, /logout and /panel/api/setting/all
(a read). It never changes the panel.

Output language: --lang en|ru. Without the flag, LC_ALL, LC_MESSAGES or LANG
starting with "ru" selects Russian. JSON output is always in English.

Exit code: 0 no warnings, 1 warnings, 2 critical findings, 3 the check could not run.

Flags for check:
`,
		ru: `xui-doctor - проверка панелей 3x-ui / still-ui только на чтение

Запуск:
  xui-doctor check --url https://ХОСТ:ПОРТ/ПУТЬ/ [ключи]
  xui-doctor version

Учётные данные берутся только из переменных окружения, не из ключей:
  XUI_API_TOKEN               токен API (Settings -> API Tokens; токен admin читает всё,
                              токен monitor - только для проверок Xray и версии)
  XUI_USERNAME, XUI_PASSWORD  логин панели, если токена нет
  XUI_2FA_CODE                текущий код 2FA, если она включена

Программа шлёт только GET и POST /login, /logout и /panel/api/setting/all
(это чтение). Панель она не меняет.

Язык вывода: --lang en|ru. Без ключа русский включается, если LC_ALL,
LC_MESSAGES или LANG начинается с "ru". Вывод JSON всегда на английском.

Код выхода: 0 - замечаний нет, 1 - есть предупреждения, 2 - есть критичные
проблемы, 3 - проверка не выполнена.

Ключи для check:
`,
	},
	"cli.unknown_command": {`unknown command %q; try: xui-doctor check --url ...`, `неизвестная команда %q; попробуйте: xui-doctor check --url ...`},
	"cli.missing_url":     {`missing --url (e.g. --url https://203.0.113.5:2053/abcdef/)`, `не задан --url (например, --url https://203.0.113.5:2053/abcdef/)`},
	"cli.hint_insecure":   {`hint: for a self-signed panel certificate add --insecure`, `подсказка: если у панели самоподписанный сертификат, добавьте --insecure`},
	"cli.flag.url":        {`panel URL including its base path (or XUI_URL)`, `адрес панели вместе с её путём (или XUI_URL)`},
	"cli.flag.insecure":   {`accept a self-signed or mismatched panel certificate`, `принять самоподписанный или выданный на другое имя сертификат панели`},
	"cli.flag.json":       {`print JSON instead of text`, `вывод в JSON вместо текста (тексты в JSON на английском)`},
	"cli.flag.local": {`running on the panel host: also read certificate files and listening sockets, and dial REALITY targets`,
		`запуск на сервере панели: ещё прочитать файлы сертификатов и слушающие сокеты и проверить цели REALITY`},
	"cli.flag.dial_targets": {`dial REALITY targets from this machine; non-public addresses only with --local (implied by --local)`,
		`проверить цели REALITY с этой машины; непубличные адреса - только с --local (--local включает и это)`},
	"cli.flag.offline": {`do not ask GitHub for the latest panel release`, `не спрашивать у GitHub последний выпуск панели`},
	"cli.flag.verbose": {`also print OK lines`, `печатать и строки OK`},
	"cli.flag.timeout": {`timeout per panel request`, `таймаут одного запроса к панели`},
	"cli.flag.lang":    {"output `language`: en or ru (default: from LC_ALL, LC_MESSAGES, LANG)", "`язык` вывода: en или ru (по умолчанию - по LC_ALL, LC_MESSAGES, LANG)"},

	// Text report.
	"report.panel":         {`panel: %s, Xray %s, auth: %s`, `панель: %s, Xray %s, авторизация: %s`},
	"report.auth_token":    {`API token`, `токен API`},
	"report.auth_password": {`password`, `пароль`},
	"report.local":         {`, local checks on`, `, локальные проверки включены`},
	"report.dial":          {`, dialing REALITY targets from this machine`, `, цели REALITY проверяются с этой машины`},
	"report.fix":           {`  fix: %s`, `  что делать: %s`},
	"report.count":         {`%d %s`, `%[2]s %[1]d`},
	"report.critical":      {`critical`, `CRITICAL`},
	"report.warn":          {`warn`, `WARN`},
	"report.info":          {`info`, `INFO`},
	"report.ok":            {`ok`, `OK`},
	"report.summary":       {`summary: %s`, `итого: %s`},
	"report.ok_hidden":     {`(OK lines hidden; use --verbose to show them)`, `(строки OK скрыты; показать их: --verbose)`},

	// Shared pieces.
	"check.ok":              {`no problems found`, `проблем не найдено`},
	"check.skipped":         {`skipped: could not read %s (%s)`, `пропущено: не удалось прочитать %s (%s)`},
	"section.status":        {`status`, `статус`},
	"section.inbounds":      {`inbounds`, `входы`},
	"section.hosts":         {`hosts`, `хосты`},
	"section.settings":      {`settings`, `настройки`},
	"section.fail2ban":      {`fail2ban`, `состояние fail2ban`},
	"section.not_permitted": {`these credentials may not read it, e.g. a monitor-scope token`, `этим учётным данным читать нельзя, например токену monitor`},
	"inbound.label":         {`inbound #%d %q (%s, port %d)`, `вход #%d %q (%s, порт %d)`},
	"list.more":             {`%s and %d more`, `%s и ещё %d`},
	"dur.days_hours":        {`%d %s %d %s`, `%d %s %d %s`},
	"dur.count":             {`%d %s`, `%d %s`},

	// Subjects.
	"subj.panel":           {`panel`, `панель`},
	"subj.login":           {`login`, `вход в панель`},
	"subj.transport":       {`transport`, `соединение`},
	"subj.base_path":       {`base path`, `путь панели`},
	"subj.panel_port":      {`panel port`, `порт панели`},
	"subj.sub_path":        {`subscription path`, `путь подписки`},
	"subj.panel_listener":  {`panel listener`, `адрес панели`},
	"subj.tg_bot":          {`telegram bot`, `бот Telegram`},
	"subj.clients":         {`clients`, `клиенты`},
	"subj.panel_cert":      {`panel HTTPS certificate`, `HTTPS-сертификат панели`},
	"subj.tls_inbounds":    {`TLS inbounds`, `входы TLS`},
	"subj.sockets":         {`sockets`, `сокеты`},
	"subj.xray":            {`xray`, `Xray`},
	"subj.nodes":           {`nodes`, `узлы`},
	"subj.reality_clients": {`REALITY clients`, `клиенты REALITY`},

	// version
	"version.desc":          {`%s %s`, `%s %s`},
	"version.desc_based":    {`%s %s (based on 3x-ui %s)`, `%s %s (на основе 3x-ui %s)`},
	"version.offline":       {`%s; latest release not looked up (--offline)`, `%s; последний выпуск не проверялся (--offline)`},
	"version.lookup_failed": {`%s; latest release lookup failed: %s`, `%s; не удалось узнать последний выпуск: %s`},
	"version.latest_is":     {`%s; latest release is %s`, `%s; последний выпуск: %s`},
	"version.outdated":      {`%s is older than the latest release %s of %s`, `%s: есть более новый выпуск %s (%s)`},
	"version.outdated.fix": {`Read the release notes, back up the database, then update from the panel or with the install script.`,
		`Прочитайте описание выпуска, сделайте копию базы и обновитесь из панели или скриптом установки.`},
	"version.latest": {`%s is the latest release`, `%s - последний выпуск`},

	// security
	"security.default_login": {`the panel accepts the default admin/admin login`, `панель пускает по логину и паролю по умолчанию admin/admin`},
	"security.default_login.fix": {`Change the username and password (Settings -> Authentication -> Admin credentials).`,
		`Смените логин и пароль (Settings -> Authentication -> Admin credentials).`},
	"security.plain_http_url": {`the panel is reached over plain HTTP on a non-loopback address; the login and session cookie travel unencrypted`,
		`в панель ходят по обычному HTTP и не через loopback: логин и cookie сессии идут без шифрования`},
	"security.plain_http_url.fix": {`Give the panel a certificate, or reach it only through an SSH tunnel (ssh -L) or a TLS reverse proxy.`,
		`Поставьте панели сертификат или заходите в неё только через SSH-туннель (ssh -L) либо обратный прокси с TLS.`},
	"security.root_path": {`the panel's web base path is "/", so scanners find the login page at the root`,
		`путь панели - "/", сканеры находят страницу входа прямо в корне`},
	"security.root_path.fix": {`Set a random URI path (Settings -> General -> URI Path) and use the new panel URL.`,
		`Задайте случайный путь (Settings -> General -> URI Path) и заходите по новому адресу.`},
	"security.default_port": {`the panel uses the default port 2053, which scanners probe for 3x-ui`,
		`панель на порту по умолчанию 2053, его сканеры проверяют в поисках 3x-ui`},
	"security.default_port.fix": {`Pick a random port (Settings -> General -> Listen Port) and open it in the firewall instead.`,
		`Выберите случайный порт (Settings -> General -> Listen Port) и откройте в файрволе его вместо 2053.`},
	"security.default_sub_path": {`the subscription path is the default "/sub/", so the subscription server is easy to fingerprint`,
		`путь подписки по умолчанию "/sub/", сервер подписки легко опознать`},
	"security.default_sub_path.fix": {`Set a random subscription path (Settings -> Subscription); clients then need the new link.`,
		`Задайте случайный путь подписки (Settings -> Subscription); клиентам понадобится новая ссылка.`},
	"security.default_json_path": {`the JSON subscription path is the default "/json/"`, `путь JSON-подписки по умолчанию "/json/"`},
	"security.default_json_path.fix": {`Set a random JSON subscription path; clients then need the new link.`,
		`Задайте случайный путь JSON-подписки; клиентам понадобится новая ссылка.`},
	"security.all_addresses": {`all addresses`, `всех адресах`},
	"security.plain_http_listen": {`the panel serves plain HTTP on %s; fine behind a TLS proxy or firewall, otherwise anyone on the path sees the login`,
		`панель отдаёт обычный HTTP на %s; за прокси с TLS или файрволом это нормально, иначе логин видит любой на пути`},
	"security.plain_http_listen.fix": {`Set a panel certificate, or set the listen IP to 127.0.0.1 and use an SSH tunnel.`,
		`Поставьте панели сертификат или слушайте только 127.0.0.1 и заходите через SSH-туннель.`},
	"security.no_2fa":     {`two-factor authentication is off`, `двухфакторная аутентификация выключена`},
	"security.no_2fa.fix": {`Enable it in Settings -> Authentication -> Two-factor authentication.`, `Включите её: Settings -> Authentication -> Two-factor authentication.`},
	"security.tg_bot_enabled": {`a Telegram bot token is enabled; the bot can manage clients and send database backups to its admin chats`,
		`бот Telegram включён: он может управлять клиентами и слать копии базы в чаты админов`},
	"security.tg_bot_disabled": {`a Telegram bot token is configured but disabled; the bot can manage clients and send database backups to its admin chats`,
		`токен бота Telegram задан, но бот выключен; включённый бот может управлять клиентами и слать копии базы в чаты админов`},
	"security.tg_bot.fix": {`Keep the token secret and the admin chat ID list short; revoke it in @BotFather if it leaked.`,
		`Держите токен в секрете, а список чатов админов коротким; если токен утёк, отзовите его в @BotFather.`},

	// clients
	"clients.shared_secret": {`clients %q and %q share one credential (UUID/password); Xray treats them as one user, so traffic, limits and removal hit the wrong client`,
		`у клиентов %q и %q один UUID/пароль: для Xray это один пользователь, и трафик, лимиты и удаление попадут не на того клиента`},
	"clients.shared_secret.fix": {`Give one of the clients a new UUID/password and send it the new link.`,
		`Выдайте одному из них новый UUID/пароль и отправьте ему новую ссылку.`},
	"clients.expired": {`%d %s past expiry but still enabled in the panel's traffic table: %s`,
		`срок истёк, но в таблице трафика панели всё ещё включены: %[1]d %[2]s (%[3]s)`},
	"clients.expired.fix": {`The panel's traffic job disables these periodically while Xray is running; if they stay enabled, check that Xray runs and read the panel log.`,
		`Панель сама отключает их по расписанию, пока работает Xray; если они так и остаются включены, проверьте, что Xray запущен, и посмотрите лог панели.`},
	"clients.exhausted": {`%d %s used up the traffic quota but still enabled: %s`,
		`трафик кончился, но всё ещё включены: %[1]d %[2]s (%[3]s)`},
	"clients.exhausted.fix": {`Same as above: the panel's traffic job should disable them; check the panel log.`,
		`То же, что выше: панель должна отключать их сама; посмотрите лог панели.`},
	"clients.iplimit": {`%d %s an IP limit (limitIp)`, `у %d %s задан лимит IP (limitIp)`},
	"clients.iplimit.how": {`the panel counts each client's source IPs from Xray's online stats and bans extra IPs with fail2ban (Windows: drops the connections); clients behind CGNAT or switching networks can trip it`,
		`панель считает IP каждого клиента по онлайн-статистике Xray и банит лишние через fail2ban (в Windows рвёт соединения); клиенты за CGNAT или при смене сети могут попасть под бан`},
	"clients.iplimit.no_status": {`%s; %s. fail2ban status not readable`, `%s; %s. Состояние fail2ban прочитать не удалось`},
	"clients.iplimit.unenforced": {`%s but fail2ban is not usable on the panel host (enabled=%s, installed=%s, usable=%s), so the limit is not enforced`,
		`%s, но fail2ban на сервере панели не работает (enabled=%s, installed=%s, usable=%s), так что лимит не соблюдается`},
	"clients.iplimit.unenforced.fix": {`Install/enable fail2ban (the x-ui (or still-ui) shell menu -> Fail2ban / IP Limit), or remove the limits so nobody relies on them.`,
		`Установите и включите fail2ban (консольное меню x-ui или still-ui -> Fail2ban / IP Limit) или уберите лимиты, чтобы на них никто не рассчитывал.`},
	"clients.iplimit.info": {`%s; %s`, `%s; %s`},

	// tls
	"tls.renew_panel":  {`Renew the panel certificate (Settings -> panel certificate, or your ACME client)`, `Обновите сертификат панели (Settings -> сертификат панели или ваш ACME-клиент)`},
	"tls.renew_inline": {`Replace the inline certificate with a renewed one`, `Замените встроенный сертификат новым`},
	"tls.renew_file":   {`Renew the certificate and restart Xray (or wait for the panel to reload it)`, `Обновите сертификат и перезапустите Xray (или подождите, пока панель его перечитает)`},
	"tls.fix_now":      {`%s.`, `%s.`},
	"tls.fix_soon":     {`%s; short-lived (e.g. IP) certificates must renew automatically.`, `%s; короткие сертификаты (например, на IP) должны продлеваться автоматически.`},
	"tls.panel_file":   {`panel certificate file`, `файл сертификата панели`},
	"tls.sub_file":     {`subscription certificate file`, `файл сертификата подписки`},
	"tls.subj_file":    {`%s %s`, `%s %s`},
	"tls.subj_inline":  {`%s inline certificate`, `%s, встроенный сертификат`},
	"tls.no_cert":      {`TLS is on but no certificate is configured`, `TLS включён, но сертификат не задан`},
	"tls.no_cert.fix":  {`Add a certificate (file paths or content) to the inbound's TLS settings.`, `Добавьте сертификат (пути к файлам или содержимое) в настройки TLS входа.`},
	"tls.inline_bad":   {`inline certificate does not parse: %s`, `встроенный сертификат не разбирается: %s`},
	"tls.files_unchecked": {`%d certificate %s not checked; run with --local on the panel host to read them`,
		`%d %s; чтобы их прочитать, запустите с --local на сервере панели`},
	"tls.read_failed":     {`cannot read certificate: %s`, `не удалось прочитать сертификат: %s`},
	"tls.read_failed.fix": {`Check the path in the panel and the file permissions.`, `Проверьте путь в панели и права на файл.`},
	"tls.expired":         {`certificate expired on %s`, `сертификат истёк %s`},
	"tls.expires_soon":    {`certificate expires in %s (%s)`, `сертификат истекает через %s (%s)`},
	"tls.not_yet_valid":   {`certificate is not valid yet (from %s); check the server clock`, `сертификат ещё не действует (с %s); проверьте часы сервера`},
	"tls.valid_until":     {`valid until %s`, `действует до %s`},
	"tls.no_pem":          {`no PEM certificate found`, `PEM-сертификат не найден`},

	// ports
	"ports.panel":     {`the panel web server`, `веб-сервер панели`},
	"ports.sub":       {`the subscription server`, `сервер подписки`},
	"ports.subj":      {`%s/%d`, `%s/%d`},
	"ports.subj_node": {`%s/%d on node #%d`, `%s/%d на узле #%d`},
	"ports.conflict": {`%s and %s use the same port; only one can bind it and Xray (or the panel) fails to start`,
		`%s и %s на одном порту: занять его может только один, и Xray (или панель) не запустится`},
	"ports.conflict.fix": {`Move one of them to another port, or bind them to different listen addresses.`,
		`Перенесите один из них на другой порт или повесьте их на разные адреса.`},
	"ports.list_failed":       {`cannot list listening sockets: %s`, `не удалось получить список слушающих сокетов: %s`},
	"ports.not_listening":     {`nothing listens on %s on this host although the inbound is enabled`, `на этом сервере никто не слушает %s, хотя вход включён`},
	"ports.not_listening.fix": {`Check the Xray log for a bind error; restart Xray from the panel.`, `Поищите в логе Xray ошибку bind и перезапустите Xray из панели.`},

	// reality
	"reality.parse_error":        {`cannot parse inbound JSON: %s`, `не удалось разобрать JSON входа: %s`},
	"reality.no_settings":        {`security is reality but realitySettings is missing`, `security = reality, но realitySettings нет`},
	"reality.no_settings.fix":    {`Open the inbound, re-select REALITY and save.`, `Откройте вход, заново выберите REALITY и сохраните.`},
	"reality.refused":            {`%s (Xray refuses to start with this inbound)`, `%s (с таким входом Xray не запустится)`},
	"reality.empty_target":       {`empty "target" (dest)`, `пустой "target" (dest)`},
	"reality.empty_target.fix":   {`Set the target to a TLS 1.3 site, e.g. example.com:443.`, `Укажите в target сайт с TLS 1.3, например example.com:443.`},
	"reality.bad_target":         {`"target" %q is not a port, a unix socket path or host:port`, `"target" %q - это не порт, не путь к unix-сокету и не хост:порт`},
	"reality.bad_client_ver":     {`"minClientVer" %q is not up to three dot-separated numbers below 256`, `"minClientVer" %q - это не до трёх чисел меньше 256 через точку`},
	"reality.bad_client_ver.fix": {`Write it as a version like 26.3.27, without a "v", or leave it empty.`, `Запишите его как версию, например 26.3.27, без "v", или оставьте пустым.`},
	"reality.empty_names":        {`empty "serverNames"`, `пустой "serverNames"`},
	"reality.empty_names.fix":    {`Add the domain(s) the target serves, e.g. the target's host name.`, `Добавьте домены, которые обслуживает цель, например её имя хоста.`},
	"reality.empty_key":          {`empty "privateKey"`, `пустой "privateKey"`},
	"reality.empty_key.fix": {`Generate a new X25519 key pair in the inbound form (clients need the new public key).`,
		`Создайте новую пару ключей X25519 в форме входа (клиентам нужен новый открытый ключ).`},
	"reality.bad_key":        {`"privateKey" is not a 32-byte base64url X25519 key`, `"privateKey" - не 32-байтный ключ X25519 в base64url`},
	"reality.bad_key.fix":    {`Generate a new X25519 key pair in the inbound form.`, `Создайте новую пару ключей X25519 в форме входа.`},
	"reality.empty_sids":     {`empty "shortIds"`, `пустой "shortIds"`},
	"reality.empty_sids.fix": {`Add at least one short ID (an empty string "" is allowed as one of them).`, `Добавьте хотя бы один short ID (пустая строка "" тоже годится).`},
	"reality.sid_long":       {`shortIds[%d] is longer than 16 hex characters`, `shortIds[%d] длиннее 16 hex-символов`},
	"reality.sid_not_hex":    {`shortIds[%d] is not an even-length hex string`, `shortIds[%d] - не hex-строка чётной длины`},
	"reality.sid.fix":        {`Use 0-16 hex characters, an even count.`, `Нужно 0-16 hex-символов, чётное число.`},
	"reality.no_pbk": {`the public key for share links is empty, so links carry no pbk and Xray clients refuse them (empty "password")`,
		`открытый ключ для ссылок пустой: в ссылках нет pbk, и клиенты Xray их не принимают (пустой "password")`},
	"reality.no_pbk.fix":  {`Open the inbound and regenerate or re-save the key pair.`, `Откройте вход и создайте заново или пересохраните пару ключей.`},
	"reality.show":        {`REALITY "show" (debug output) is on`, `включён REALITY "show" (отладочный вывод)`},
	"reality.show.fix":    {`Turn it off unless you are debugging.`, `Выключите, если не отлаживаете.`},
	"reality.unix_target": {`target is a unix socket; not dialed`, `цель - unix-сокет; не проверялась`},
	"reality.from_panel":  {`from the panel host`, `с сервера панели`},
	"reality.from_here":   {`from where xui-doctor runs (not necessarily the panel host)`, `оттуда, где запущен xui-doctor (это не обязательно сервер панели)`},
	"reality.subj_target": {`%s target %s`, `%s, цель %s`},
	"reality.subj_sni":    {`%s target %s sni %s`, `%s, цель %s, sni %s`},
	"reality.not_dialed":  {`not dialed: %s`, `не проверялась: %s`},
	"reality.no_resolve":  {`cannot resolve %s: %s`, `не удалось разрешить %s: %s`},
	"reality.no_address":  {`no address for %s`, `у %s нет адреса`},
	"reality.non_public": {`%s resolves to the non-public address %s; such targets are only dialed with --local (on the panel host)`,
		`%s указывает на непубличный адрес %s; такие цели проверяются только с --local (на сервере панели)`},
	"reality.handshake_failed": {`TLS handshake with the target failed %s: %s`, `TLS-рукопожатие с целью %s не прошло: %s`},
	"reality.handshake_failed.fix": {`Pick a target that answers TLS 1.3 for this name from the server; REALITY copies its handshake.`,
		`Выберите цель, которая с сервера отвечает по TLS 1.3 на это имя: REALITY копирует её рукопожатие.`},
	"reality.no_tls13":     {`target does not negotiate TLS 1.3 %s`, `цель не отвечает по TLS 1.3 %s`},
	"reality.no_tls13.fix": {`REALITY needs a TLS 1.3 target; choose another site.`, `REALITY нужна цель с TLS 1.3; выберите другой сайт.`},
	"reality.no_h2":        {`target did not select h2 (ALPN %q) %s`, `цель не выбрала h2 (ALPN %q) %s`},
	"reality.no_h2.fix":    {`Prefer a target that supports HTTP/2; browsers fingerprints offer h2.`, `Лучше взять цель с HTTP/2: отпечатки браузеров предлагают h2.`},
	"reality.unknown_root": {`target certificate chain is not trusted by this machine's CA store (%s); name not checked`,
		`хранилище CA этой машины не доверяет цепочке сертификата цели (%s); имя не проверено`},
	"reality.unknown_root.fix": {`Install the ca-certificates package where xui-doctor runs, then run again.`,
		`Установите пакет ca-certificates там, где запущен xui-doctor, и запустите проверку снова.`},
	"reality.bad_cert": {`target certificate does not verify for this server name %s: %s`, `сертификат цели не проходит проверку для этого имени %s: %s`},
	"reality.bad_cert.fix": {`List only names the target's certificate covers in serverNames.`,
		`Оставьте в serverNames только имена, которые покрывает сертификат цели.`},
	"reality.dial_cap": {`%d server %s not dialed: the run is limited to %d target handshakes`,
		`%d %s: за один запуск - не больше %d рукопожатий с целями`},
	"reality.target_ok": {`target %s (%s) answers TLS 1.3 + h2 with a valid certificate %s`,
		`цель %s (%s) отвечает по TLS 1.3 + h2 с действительным сертификатом %s`},

	// xray
	"xray.not_running":     {`Xray is not running (state: %s)`, `Xray не запущен (состояние: %s)`},
	"xray.not_running_msg": {`Xray is not running (state: %s): %s`, `Xray не запущен (состояние: %s): %s`},
	"xray.not_running.fix": {`Open the panel's overview and check the Xray log; restart Xray after fixing the config.`,
		`Откройте обзор панели и посмотрите лог Xray; исправьте конфиг и перезапустите Xray.`},
	"xray.bad_version": {`cannot parse the Xray version %q; REALITY compatibility not assessed`,
		`не удалось разобрать версию Xray %q; совместимость REALITY не оценивалась`},
	"xray.mlkem_unread": {`Xray %s (>= 26.9.8) refuses REALITY ClientHellos without an X25519MLKEM768 key share (fp=ios/edge/qq links, sing-box clients); inbound fingerprints could not be read with these credentials`,
		`Xray %s (>= 26.9.8) не пускает по REALITY ClientHello без ключа X25519MLKEM768 (ссылки с fp=ios/edge/qq, клиенты на sing-box); отпечатки входов с этими учётными данными прочитать не удалось`},
	"xray.mlkem_unread.fix": {`Run again with an admin-scope token or the panel login to see which inbounds are affected.`,
		`Запустите снова с токеном admin или с логином панели, чтобы увидеть, каких входов это касается.`},
	"xray.on_nodes": {`%d REALITY %s on remote nodes: their Xray version is not reported here; run xui-doctor against each node`,
		`%d %s на удалённых узлах: версию их Xray панель здесь не сообщает; запустите xui-doctor отдельно для каждого узла`},
	"xray.no_reality": {`Xray %s; no enabled REALITY inbounds on this panel's core`, `Xray %s; включённых входов REALITY на ядре этой панели нет`},
	"xray.min_client_ver": {`Xray %s defaults REALITY minClientVer to 26.3.27: sing-box clients (Hiddify, Karing, NekoBox...), mihomo/Clash clients and Xray clients older than 26.3.27 are refused`,
		`в Xray %s у REALITY по умолчанию minClientVer = 26.3.27: клиенты на sing-box (Hiddify, Karing, NekoBox...), mihomo/Clash и клиенты Xray версий ниже 26.3.27 не пускаются`},
	"xray.min_client_ver.fix": {`Set "minClientVer" explicitly on the inbound (e.g. "0.0.0" accepts every client), or switch Xray to 26.6.27.`,
		`Задайте во входе "minClientVer" явно ("0.0.0" пускает всех) или переключите Xray на 26.6.27.`},
	"xray.min_client_ver_set": {`Xray %s: REALITY inbounds set minClientVer explicitly`, `Xray %s: во входах REALITY minClientVer задан явно`},
	"xray.compatible": {`Xray %s accepts REALITY ClientHellos with or without ML-KEM (sing-box, mihomo and fp=ios clients work)`,
		`Xray %s принимает REALITY ClientHello и с ML-KEM, и без (клиенты sing-box, mihomo и с fp=ios работают)`},
	"xray.mlkem_head": {`Xray %s (>= 26.9.8) refuses REALITY ClientHellos without an X25519MLKEM768 key share`,
		`Xray %s (>= 26.9.8) не пускает по REALITY ClientHello без ключа X25519MLKEM768`},
	"xray.pin_fix": {`or pin Xray 26.6.27 in the panel's Xray version switcher (keeps old clients working, loses newer core fixes)`,
		`или закрепите Xray 26.6.27 в выборе версии Xray в панели (старые клиенты будут работать, но без новых исправлений ядра)`},
	"xray.size_note": {`ML-KEM ClientHellos are ~1.5-1.9 KB and need two TCP segments; a few mobile networks drop those.`,
		`ClientHello с ML-KEM весит ~1,5-1,9 КБ и не влезает в один TCP-сегмент; некоторые мобильные сети такие теряют.`},
	"xray.host_place":  {`host %q -> %s`, `хост %q -> %s`},
	"xray.fp_untested": {`fingerprint %q was not tested against an ML-KEM-only REALITY server`, `отпечаток %q не проверялся с сервером REALITY, который требует ML-KEM`},
	"xray.fp_refused": {`%s; share links here use fp=%s, which has none, so clients using them cannot connect`,
		`%s; ссылки здесь с fp=%s, а в нём такого ключа нет, и клиенты по ним не подключатся`},
	"xray.fp_refused.fix": {`Set the uTLS fingerprint to chrome, firefox or safari and let clients refresh the subscription, %s. %s`,
		`Поставьте отпечаток uTLS chrome, firefox или safari и пусть клиенты обновят подписку, %s. %s`},
	"xray.fp_random": {`%s; fp=%s picks a hello per connection, and some picks have no ML-KEM share, so connections fail at random`,
		`%s; fp=%s выбирает hello на каждое соединение, не во всех есть ML-KEM, поэтому соединения рвутся случайно`},
	"xray.fp_random.fix": {`Use chrome, firefox or safari instead, %s.`, `Используйте вместо него chrome, firefox или safari, %s.`},
	"xray.mihomo_host": {`%s; this host has "Mihomo X25519" on, so its Clash subscription turns ML-KEM off and mihomo clients are refused`,
		`%s; у этого хоста включён "Mihomo X25519", его подписка Clash выключает ML-KEM, и клиенты mihomo получают отказ`},
	"xray.mihomo_host.fix": {`Turn "Mihomo X25519" off for this host (it only makes sense with Xray < 26.9.8), %s.`,
		`Выключите "Mihomo X25519" у этого хоста (он нужен только с Xray < 26.9.8), %s.`},
	"xray.clients": {`%s: sing-box based clients (sing-box, Hiddify, Karing, NekoBox; tested 1.12.12 and 1.14.4) cannot connect with any fingerprint; mihomo/Clash clients connect only with reality-opts support-x25519mlkem768: true and a chrome/firefox/safari fingerprint (the panel's Clash subscription sets it; imported vless:// links and hand-written configs usually do not)`,
		`%s: клиенты на sing-box (sing-box, Hiddify, Karing, NekoBox; проверены 1.12.12 и 1.14.4) не подключаются ни с каким отпечатком; клиенты mihomo/Clash подключаются только с reality-opts support-x25519mlkem768: true и отпечатком chrome/firefox/safari (подписка Clash самой панели это ставит, импортированные ссылки vless:// и ручные конфиги обычно нет)`},
	"xray.clients.fix": {`Tell sing-box/Hiddify users to use an Xray-based client or the Clash subscription in a mihomo client, %s.`,
		`Предложите пользователям sing-box/Hiddify клиент на Xray или подписку Clash в клиенте mihomo, %s.`},

	// Errors.
	"api.forbidden":       {`not permitted for these credentials`, `с этими учётными данными нельзя`},
	"api.bad_url":         {`panel URL must look like https://host:port/basepath/`, `адрес панели должен выглядеть так: https://хост:порт/путь/`},
	"api.url_userinfo":    {`do not put credentials in the panel URL (%s); use XUI_API_TOKEN or XUI_USERNAME/XUI_PASSWORD`, `не пишите логин и пароль в адрес панели (%s); используйте XUI_API_TOKEN или XUI_USERNAME/XUI_PASSWORD`},
	"api.no_credentials":  {`no credentials: set XUI_API_TOKEN, or XUI_USERNAME and XUI_PASSWORD`, `нет учётных данных: задайте XUI_API_TOKEN или XUI_USERNAME и XUI_PASSWORD`},
	"api.login":           {`login: %s`, `вход: %s`},
	"api.login_refused":   {`login refused by the panel (wrong username, password or 2FA code, or too many attempts)`, `панель не пустила (неверный логин, пароль или код 2FA либо слишком много попыток)`},
	"api.csrf":            {`csrf token: %s`, `токен CSRF: %s`},
	"api.csrf_unexpected": {`csrf token: unexpected response (is the URL the panel's address including its base path?)`, `токен CSRF: неожиданный ответ (это точно адрес панели вместе с её путём?)`},
	"api.not_success":     {`%s: panel answered success=false: %s`, `%s: панель ответила success=false: %s`},
	"api.decode":          {`%s: cannot decode answer: %s`, `%s: не удалось разобрать ответ: %s`},
	"api.path_error":      {`%s: %s`, `%s: %s`},
	"api.http401":         {`%s: HTTP 401 (token or session not accepted)`, `%s: HTTP 401 (токен или сессия не приняты)`},
	"api.http404":         {`%s: HTTP 404 (wrong base path, or not logged in)`, `%s: HTTP 404 (неверный путь панели или нет входа)`},
	"api.redirect":        {`%s: HTTP %d redirect to %q (check the URL and its base path)`, `%s: HTTP %d, перенаправление на %q (проверьте адрес и путь панели)`},
	"api.not_json":        {`%s: not a JSON API answer (is this a 3x-ui panel?)`, `%s: это не ответ JSON API (точно панель 3x-ui?)`},
	"local.linux_only":    {`only supported on Linux`, `работает только в Linux`},
	"local.no_cert":       {`no certificate presented`, `сертификат не предъявлен`},
}

// plurals hold word forms: "one|many" in English and "one|few|many" in
// Russian (1, 21 / 2-4, 22-24 / 0, 5-20, 25-30). Some Russian forms carry the
// verb too, since it has to agree with the number.
var plurals = map[string]entry{
	"n.client_is":        {`client is|clients are`, `клиент|клиента|клиентов`},
	"n.client_has":       {`client has|clients have`, `клиент|клиента|клиентов`},
	"n.client_has_limit": {`client has|clients have`, `клиента|клиентов|клиентов`},
	"n.cert_file":        {`file|files`, `файл сертификата не проверен|файла сертификатов не проверены|файлов сертификатов не проверено`},
	"n.server_name":      {`name|names`, `имя сервера не проверено|имени сервера не проверены|имён сервера не проверено`},
	"n.inbound_runs":     {`inbound runs|inbounds run`, `вход REALITY работает|входа REALITY работают|входов REALITY работают`},
	"n.day":              {`day|days`, `день|дня|дней`},
	"n.hour":             {`hour|hours`, `час|часа|часов`},
	"n.minute":           {`minute|minutes`, `минуту|минуты|минут`},
}
