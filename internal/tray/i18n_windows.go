//go:build windows

package tray

import (
	"fmt"
	"sync"
)

// The texts of the icon, its menu, the agent window and the restart
// question, in the display language of the signed-in user's Windows
// (English when it is none of the console's languages).

var pGetUserUILang = kernel.NewProc("GetUserDefaultUILanguage")

// uiLang is the user's Windows display language as a console language code.
func uiLang() string {
	id, _, _ := pGetUserUILang.Call()
	switch id & 0x3ff { // primary language
	case 0x1a:
		return "sr"
	case 0x07:
		return "de"
	case 0x0c:
		return "fr"
	case 0x0a:
		return "es"
	case 0x10:
		return "it"
	case 0x16:
		return "pt"
	case 0x13:
		return "nl"
	case 0x15:
		return "pl"
	case 0x05:
		return "cs"
	case 0x1f:
		return "tr"
	case 0x19:
		return "ru"
	case 0x04:
		return "zh"
	case 0x11:
		return "ja"
	}
	return "en"
}

// textKeys are the English texts; texts holds them per language in the
// same order.
var textKeys = []string{
	"Agent status unknown (is the service running?)",
	"Connected to %s",
	"Agent not running",
	"Not connected to %s",
	"Managed by %s",
	"Open ControlZit Agent",
	"Hide this icon until the next sign-in",
	"Your administrator needs to restart this computer to finish installing updates.",
	"It restarts automatically on %s.",
	"Restart now? Save your work first. Choose No to be reminded later.",
	"ControlZit: restart needed",
	"Restarting to finish installing updates.",
	"Loading…",
	"Server",
	"Managed by",
	"Updates",
	"just now",
	"%d min ago",
	"%d h ago",
	"Connected",
	"Not connected",
	"This computer is managed and protected",
	"The agent cannot reach the server",
	"The ControlZit Agent service is not running",
	"Connected since %s.",
	"Last contact %s. It keeps trying.",
	"last contact %s",
	"Up to date",
	"%d missing",
	"%d security",
	"restart needed",
	"checked %s",
	"searching…",
	"Agent %s",
	"restart required by %s",
}

var texts = map[string][]string{
	"sr": {"Stanje agenta nepoznato (da li servis radi?)", "Povezan sa %s", "Agent ne radi", "Nije povezan sa %s", "Upravlja %s", "Otvori ControlZit Agent", "Sakrij ovu ikonicu do sledeće prijave",
		"Vaš administrator treba da restartuje ovaj računar da bi završio instalaciju ažuriranja.", "Restartuje se automatski %s.", "Restartovati sada? Prvo sačuvajte svoj rad. Izaberite Ne da vas podsetimo kasnije.", "ControlZit: potreban restart", "Restart radi završetka instalacije ažuriranja.",
		"Učitavanje…", "Server", "Upravlja", "Ažuriranja", "upravo sada", "pre %d min", "pre %d h", "Povezan", "Nije povezan",
		"Ovaj računar je upravljan i zaštićen", "Agent ne može da dođe do servera", "Servis ControlZit Agent ne radi", "Povezan od %s.", "Poslednji kontakt %s. Pokušava ponovo.", "poslednji kontakt %s",
		"Ažurno", "nedostaje: %d", "bezbednosnih: %d", "potreban restart", "provereno %s", "traži se…", "Agent %s", "restart potreban do %s"},
	"de": {"Agentstatus unbekannt (läuft der Dienst?)", "Verbunden mit %s", "Agent läuft nicht", "Nicht verbunden mit %s", "Verwaltet von %s", "ControlZit Agent öffnen", "Dieses Symbol bis zur nächsten Anmeldung ausblenden",
		"Ihr Administrator muss diesen Computer neu starten, um die Installation von Updates abzuschließen.", "Er startet automatisch am %s neu.", "Jetzt neu starten? Speichern Sie zuerst Ihre Arbeit. Wählen Sie Nein, um später erinnert zu werden.", "ControlZit: Neustart erforderlich", "Neustart, um die Installation der Updates abzuschließen.",
		"Wird geladen…", "Server", "Verwaltet von", "Updates", "gerade eben", "vor %d Min.", "vor %d Std.", "Verbunden", "Nicht verbunden",
		"Dieser Computer wird verwaltet und geschützt", "Der Agent erreicht den Server nicht", "Der Dienst ControlZit Agent läuft nicht", "Verbunden seit %s.", "Letzter Kontakt %s. Er versucht es weiter.", "letzter Kontakt %s",
		"Aktuell", "%d fehlen", "%d Sicherheit", "Neustart nötig", "geprüft %s", "wird gesucht…", "Agent %s", "Neustart nötig bis %s"},
	"fr": {"État de l'agent inconnu (le service fonctionne-t-il ?)", "Connecté à %s", "L'agent ne fonctionne pas", "Non connecté à %s", "Géré par %s", "Ouvrir ControlZit Agent", "Masquer cette icône jusqu'à la prochaine connexion",
		"Votre administrateur doit redémarrer cet ordinateur pour terminer l'installation des mises à jour.", "Il redémarre automatiquement le %s.", "Redémarrer maintenant ? Enregistrez d'abord votre travail. Choisissez Non pour un rappel plus tard.", "ControlZit : redémarrage nécessaire", "Redémarrage pour terminer l'installation des mises à jour.",
		"Chargement…", "Serveur", "Géré par", "Mises à jour", "à l'instant", "il y a %d min", "il y a %d h", "Connecté", "Non connecté",
		"Cet ordinateur est géré et protégé", "L'agent ne joint pas le serveur", "Le service ControlZit Agent ne fonctionne pas", "Connecté depuis le %s.", "Dernier contact %s. Il continue d'essayer.", "dernier contact %s",
		"À jour", "%d manquantes", "%d de sécurité", "redémarrage nécessaire", "vérifié %s", "recherche…", "Agent %s", "redémarrage requis avant le %s"},
	"es": {"Estado del agente desconocido (¿se está ejecutando el servicio?)", "Conectado a %s", "El agente no se está ejecutando", "No conectado a %s", "Administrado por %s", "Abrir ControlZit Agent", "Ocultar este icono hasta el próximo inicio de sesión",
		"Su administrador necesita reiniciar este equipo para terminar de instalar actualizaciones.", "Se reinicia automáticamente el %s.", "¿Reiniciar ahora? Guarde primero su trabajo. Elija No para recibir un recordatorio más tarde.", "ControlZit: reinicio necesario", "Reiniciando para terminar de instalar actualizaciones.",
		"Cargando…", "Servidor", "Administrado por", "Actualizaciones", "ahora mismo", "hace %d min", "hace %d h", "Conectado", "No conectado",
		"Este equipo está administrado y protegido", "El agente no puede llegar al servidor", "El servicio ControlZit Agent no se está ejecutando", "Conectado desde %s.", "Último contacto %s. Sigue intentándolo.", "último contacto %s",
		"Al día", "faltan %d", "%d de seguridad", "reinicio necesario", "comprobado %s", "buscando…", "Agente %s", "reinicio necesario antes del %s"},
	"it": {"Stato dell'agente sconosciuto (il servizio è in esecuzione?)", "Connesso a %s", "Agente non in esecuzione", "Non connesso a %s", "Gestito da %s", "Apri ControlZit Agent", "Nascondi questa icona fino al prossimo accesso",
		"L'amministratore deve riavviare questo computer per completare l'installazione degli aggiornamenti.", "Si riavvia automaticamente il %s.", "Riavviare ora? Salva prima il tuo lavoro. Scegli No per un promemoria più tardi.", "ControlZit: riavvio necessario", "Riavvio per completare l'installazione degli aggiornamenti.",
		"Caricamento…", "Server", "Gestito da", "Aggiornamenti", "proprio ora", "%d min fa", "%d h fa", "Connesso", "Non connesso",
		"Questo computer è gestito e protetto", "L'agente non raggiunge il server", "Il servizio ControlZit Agent non è in esecuzione", "Connesso dal %s.", "Ultimo contatto %s. Continua a riprovare.", "ultimo contatto %s",
		"Aggiornato", "%d mancanti", "%d di sicurezza", "riavvio necessario", "controllato %s", "ricerca…", "Agente %s", "riavvio necessario entro il %s"},
	"pt": {"Estado do agente desconhecido (o serviço está em execução?)", "Conectado a %s", "O agente não está em execução", "Não conectado a %s", "Gerenciado por %s", "Abrir ControlZit Agent", "Ocultar este ícone até o próximo logon",
		"O administrador precisa reiniciar este computador para concluir a instalação das atualizações.", "Ele reinicia automaticamente em %s.", "Reiniciar agora? Salve seu trabalho primeiro. Escolha Não para ser lembrado mais tarde.", "ControlZit: reinicialização necessária", "Reiniciando para concluir a instalação das atualizações.",
		"Carregando…", "Servidor", "Gerenciado por", "Atualizações", "agora mesmo", "há %d min", "há %d h", "Conectado", "Não conectado",
		"Este computador é gerenciado e protegido", "O agente não alcança o servidor", "O serviço ControlZit Agent não está em execução", "Conectado desde %s.", "Último contato %s. Continua tentando.", "último contato %s",
		"Atualizado", "%d pendentes", "%d de segurança", "reinicialização necessária", "verificado %s", "procurando…", "Agente %s", "reinicialização necessária até %s"},
	"nl": {"Status van de agent onbekend (draait de service?)", "Verbonden met %s", "Agent draait niet", "Niet verbonden met %s", "Beheerd door %s", "ControlZit Agent openen", "Dit pictogram verbergen tot de volgende aanmelding",
		"Uw beheerder moet deze computer opnieuw opstarten om de installatie van updates te voltooien.", "Hij start automatisch opnieuw op %s.", "Nu opnieuw opstarten? Sla eerst uw werk op. Kies Nee om later herinnerd te worden.", "ControlZit: herstart nodig", "Opnieuw opstarten om de installatie van updates te voltooien.",
		"Laden…", "Server", "Beheerd door", "Updates", "zojuist", "%d min geleden", "%d u geleden", "Verbonden", "Niet verbonden",
		"Deze computer wordt beheerd en beschermd", "De agent bereikt de server niet", "De service ControlZit Agent draait niet", "Verbonden sinds %s.", "Laatste contact %s. Hij blijft het proberen.", "laatste contact %s",
		"Bijgewerkt", "%d ontbreken", "%d beveiliging", "herstart nodig", "gecontroleerd %s", "zoeken…", "Agent %s", "herstart nodig vóór %s"},
	"pl": {"Stan agenta nieznany (czy usługa działa?)", "Połączono z %s", "Agent nie działa", "Brak połączenia z %s", "Zarządzany przez %s", "Otwórz ControlZit Agent", "Ukryj tę ikonę do następnego logowania",
		"Administrator musi ponownie uruchomić ten komputer, aby dokończyć instalację aktualizacji.", "Uruchomi się ponownie automatycznie %s.", "Uruchomić ponownie teraz? Najpierw zapisz pracę. Wybierz Nie, aby przypomnieć później.", "ControlZit: wymagane ponowne uruchomienie", "Ponowne uruchomienie w celu dokończenia instalacji aktualizacji.",
		"Ładowanie…", "Serwer", "Zarządzany przez", "Aktualizacje", "przed chwilą", "%d min temu", "%d godz. temu", "Połączono", "Brak połączenia",
		"Ten komputer jest zarządzany i chroniony", "Agent nie może połączyć się z serwerem", "Usługa ControlZit Agent nie działa", "Połączono od %s.", "Ostatni kontakt %s. Agent próbuje dalej.", "ostatni kontakt %s",
		"Aktualny", "brakuje: %d", "bezpieczeństwa: %d", "wymagane ponowne uruchomienie", "sprawdzono %s", "wyszukiwanie…", "Agent %s", "ponowne uruchomienie wymagane do %s"},
	"cs": {"Stav agenta neznámý (běží služba?)", "Připojeno k %s", "Agent neběží", "Nepřipojeno k %s", "Spravuje %s", "Otevřít ControlZit Agent", "Skrýt tuto ikonu do příštího přihlášení",
		"Správce potřebuje restartovat tento počítač, aby dokončil instalaci aktualizací.", "Restartuje se automaticky %s.", "Restartovat nyní? Nejprve uložte svou práci. Zvolte Ne a připomeneme vám to později.", "ControlZit: je potřeba restart", "Restart kvůli dokončení instalace aktualizací.",
		"Načítání…", "Server", "Spravuje", "Aktualizace", "právě teď", "před %d min", "před %d h", "Připojeno", "Nepřipojeno",
		"Tento počítač je spravován a chráněn", "Agent se nemůže spojit se serverem", "Služba ControlZit Agent neběží", "Připojeno od %s.", "Poslední kontakt %s. Zkouší to dál.", "poslední kontakt %s",
		"Aktuální", "chybí: %d", "bezpečnostních: %d", "je potřeba restart", "zkontrolováno %s", "hledání…", "Agent %s", "restart nutný do %s"},
	"tr": {"Aracı durumu bilinmiyor (hizmet çalışıyor mu?)", "%s sunucusuna bağlı", "Aracı çalışmıyor", "%s sunucusuna bağlı değil", "Yöneten: %s", "ControlZit Agent'ı aç", "Bu simgeyi sonraki oturum açmaya kadar gizle",
		"Yöneticinizin güncellemelerin kurulumunu tamamlamak için bu bilgisayarı yeniden başlatması gerekiyor.", "%s tarihinde otomatik olarak yeniden başlar.", "Şimdi yeniden başlatılsın mı? Önce çalışmanızı kaydedin. Daha sonra hatırlatılması için Hayır'ı seçin.", "ControlZit: yeniden başlatma gerekli", "Güncellemelerin kurulumunu tamamlamak için yeniden başlatılıyor.",
		"Yükleniyor…", "Sunucu", "Yöneten", "Güncellemeler", "az önce", "%d dk önce", "%d sa önce", "Bağlı", "Bağlı değil",
		"Bu bilgisayar yönetiliyor ve korunuyor", "Aracı sunucuya ulaşamıyor", "ControlZit Agent hizmeti çalışmıyor", "%s tarihinden beri bağlı.", "Son temas %s. Denemeye devam ediyor.", "son temas %s",
		"Güncel", "%d eksik", "%d güvenlik", "yeniden başlatma gerekli", "denetlendi %s", "aranıyor…", "Aracı %s", "%s tarihine kadar yeniden başlatma gerekli"},
	"ru": {"Состояние агента неизвестно (служба запущена?)", "Подключено к %s", "Агент не запущен", "Нет подключения к %s", "Управляет %s", "Открыть ControlZit Agent", "Скрыть этот значок до следующего входа",
		"Администратору нужно перезагрузить этот компьютер, чтобы завершить установку обновлений.", "Он перезагрузится автоматически %s.", "Перезагрузить сейчас? Сначала сохраните работу. Выберите «Нет», чтобы напомнить позже.", "ControlZit: нужна перезагрузка", "Перезагрузка для завершения установки обновлений.",
		"Загрузка…", "Сервер", "Управляет", "Обновления", "только что", "%d мин назад", "%d ч назад", "Подключено", "Нет подключения",
		"Этот компьютер управляется и защищён", "Агент не может связаться с сервером", "Служба ControlZit Agent не запущена", "Подключено с %s.", "Последний контакт %s. Агент пытается снова.", "последний контакт %s",
		"Актуально", "не хватает: %d", "безопасности: %d", "нужна перезагрузка", "проверено %s", "поиск…", "Агент %s", "перезагрузка нужна до %s"},
	"zh": {"代理状态未知（服务是否在运行？）", "已连接到 %s", "代理未运行", "未连接到 %s", "管理方：%s", "打开 ControlZit Agent", "隐藏此图标直到下次登录",
		"管理员需要重启此计算机以完成更新的安装。", "它将在 %s 自动重启。", "立即重启？请先保存您的工作。选择“否”稍后提醒。", "ControlZit：需要重启", "正在重启以完成更新的安装。",
		"正在加载…", "服务器", "管理方", "更新", "刚刚", "%d 分钟前", "%d 小时前", "已连接", "未连接",
		"此计算机受到管理和保护", "代理无法连接服务器", "ControlZit Agent 服务未运行", "自 %s 起已连接。", "上次联系 %s。代理会继续尝试。", "上次联系 %s",
		"已是最新", "缺少 %d 个", "%d 个安全更新", "需要重启", "检查于 %s", "正在搜索…", "代理 %s", "需在 %s 前重启"},
	"ja": {"エージェントの状態が不明です (サービスは実行中ですか?)", "%s に接続済み", "エージェントが実行されていません", "%s に接続されていません", "管理: %s", "ControlZit Agent を開く", "次回のサインインまでこのアイコンを非表示",
		"更新プログラムのインストールを完了するため、管理者がこのコンピューターを再起動する必要があります。", "%s に自動的に再起動します。", "今すぐ再起動しますか? 先に作業を保存してください。後で通知するには [いいえ] を選びます。", "ControlZit: 再起動が必要です", "更新プログラムのインストールを完了するために再起動しています。",
		"読み込み中…", "サーバー", "管理", "更新", "たった今", "%d 分前", "%d 時間前", "接続済み", "未接続",
		"このコンピューターは管理され、保護されています", "エージェントがサーバーに接続できません", "ControlZit Agent サービスが実行されていません", "%s から接続しています。", "最終接続 %s。再試行を続けています。", "最終接続 %s",
		"最新", "%d 件不足", "セキュリティ %d 件", "再起動が必要", "%s に確認", "検索中…", "エージェント %s", "%s までに再起動が必要"},
}

var (
	textsOnce sync.Once
	textMap   map[string]string
)

// lang is the language of this session (fixed when the icon starts).
func textsOf(lang string) map[string]string {
	m := map[string]string{}
	for i, k := range textKeys {
		m[k] = k
		if list := texts[lang]; i < len(list) {
			m[k] = list[i]
		}
	}
	return m
}

// T translates an English text of the icon and formats it.
func T(text string, args ...any) string {
	textsOnce.Do(func() { textMap = textsOf(uiLang()) })
	if t, ok := textMap[text]; ok {
		text = t
	}
	if len(args) > 0 {
		return fmt.Sprintf(text, args...)
	}
	return text
}

// windowTexts are the translations the agent window asks for.
func windowTexts() map[string]string {
	textsOnce.Do(func() { textMap = textsOf(uiLang()) })
	return textMap
}
