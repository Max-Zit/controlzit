#!/bin/bash
# Usage: DEV=<device id> VER=<agent version> bash tools/labtest/regress.sh  (credentials from .devdata/lab-server.txt; needs the lab, see NOTES.md)
# Lab regression of RMMZit against the lab server (CT 9600) and bz-win11.
cd /c/Users/Mili/Ai/rmm || exit 1
S=https://192.168.101.179:8443
A=https://192.168.101.179:8444
J=.gotmp/rj.txt; rm -f $J
PW=$(sed -n 's/^password: //p' .devdata/lab-server.txt)
C="curl -sk -b $J -c $J -H Origin:$S"
DEV=${DEV:-4}
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# --- security basics
check "anonymous console redirects to sign-in" '[ "$(curl -sk -o /dev/null -w %{http_code} $S/devices)" = 303 ]'
check "cross-site POST refused" '[ "$(curl -sk -o /dev/null -w %{http_code} -H Origin:https://evil.example -d name=x $S/customers)" = 403 ]'
check "agent port does not serve the console" '[ "$(curl -sk -o /dev/null -w %{http_code} $A/login)" = 404 ]'
check "agent stream needs a client certificate" '[ "$(curl -sk -o /dev/null -w %{http_code} "$A/agent/v1/stream?session=x")" = 401 ]'
check "TLS 1.1 refused" '! echo | openssl s_client -connect 192.168.101.179:8443 -tls1_1 2>/dev/null | grep -q "Protocol.*TLSv1.1"'
check "CSP header without inline" 'curl -skI $S/login | grep -qi "content-security-policy: default-src .none.; script-src .self."'

# --- sign-in
$C -o /dev/null --data-urlencode username=admin --data-urlencode "password=$PW" $S/login
# The checks read English texts; the admin account is switched back to Serbian at the end.
$C -o /dev/null -d lang=en $S/lang
check "admin signs in" '[ "$($C -o /dev/null -w %{http_code} $S/)" = 200 ]'
for p in / /customers /devices /alerts /users /audit /settings/network /settings/security /settings/monitoring /account /devices/$DEV /devices/$DEV/files /devices/$DEV/rd /sites/1; do
  check "page $p" '[ "$($C -o /dev/null -w %{http_code} $S$p)" = 200 ]'
done
check "audit chain intact" '$C $S/audit | grep -q "is intact"'

# --- device
D=$($C $S/devices/$DEV)
check "device online" 'echo "$D" | grep -q "badge ok\"><i></i>Online"'
check "agent ${VER:-0.2.0} reported" 'echo "$D" | grep -q "${VER:-0.2.0}"'
check "inventory software listed" 'echo "$D" | grep -q "Microsoft Edge"'
check "load panel" 'echo "$D" | grep -q "Load now"'
check "refresh inventory" '[ "$($C -o /dev/null -w %{http_code} -X POST $S/devices/$DEV/refresh)" = 303 ]'

# --- files
B=$S/devices/$DEV/files
check "drives listed" '$C $B | grep -q "class=\"drive\""'
for i in $(seq 1 30); do $C "$S/devices/$DEV" | grep -q "Disk health" && break; sleep 3; done
check "disk health on the device page" '$C "$S/devices/$DEV" | grep -q "Disk health"'
$C -o /dev/null --data-urlencode "dir=C:\\" -d name=cztest $B/mkdir  # the work folder (may exist already)
head -c 2500000 /dev/urandom > .gotmp/r-up.bin
$C -o /dev/null -F "dir=C:\\cztest" -F "overwrite=1" -F "file=@.gotmp/r-up.bin;filename=r-up.bin" $B/upload
$C -o .gotmp/r-down.bin "$B/download?path=C%3A%5Ccztest%5Cr-up.bin"
check "upload/download roundtrip 2.5 MB" 'cmp -s .gotmp/r-up.bin .gotmp/r-down.bin'
check "folder link works" '$C "$B?path=C%3A%5Ccztest" | grep -q "r-up.bin"'
$C -o .gotmp/r.zip "$B/zip?path=C%3A%5Ccztest"
check "folder ZIP valid" 'unzip -tq .gotmp/r.zip >/dev/null 2>&1 && unzip -l .gotmp/r.zip | grep -q r-up.bin'
$C -o /dev/null --data-urlencode "path=C:\\cztest\\r-up.bin" -d name=r-renamed.bin $B/rename
check "rename" '$C "$B?path=C%3A%5Ccztest" | grep -q "r-renamed.bin"'
$C -o /dev/null --data-urlencode "path=C:\\cztest\\r-renamed.bin" $B/delete
check "delete" '! $C "$B?path=C%3A%5Ccztest" | grep -q "r-renamed.bin"'
$C -o /dev/null --data-urlencode "path=C:\\Windows" -d recursive=1 $B/delete
check "C:\\Windows protected" '$C "$B?path=C%3A%5C" | grep -q ">Windows</a>"'

# --- remote desktop
CK=$(grep -o '__Host-czsession[[:space:]]*[^[:space:]]*' $J | awk '{print $2}')
GOTMPDIR=C:/Users/Mili/Ai/rmm/.gotmp go run ./tools/rdclient -console $S -device $DEV -cookie "$CK" -out .gotmp/r-rd.png -wait 6s > .gotmp/r-rd.log 2>&1
check "remote desktop delivers the screen" 'grep -q "^screen [0-9]*x[0-9]*" .gotmp/r-rd.log && [ -s .gotmp/r-rd.png ]'
check "remote desktop audited" '$C "$S/audit?q=rd.start" | grep -q "rd.start"'

# --- alerts and email (watch a service that is already stopped)
STOPPED=$(echo "$D" | sed 's/<[^>]*>/ /g' | grep -o "Automatic services that are not running: [A-Za-z0-9_.,-]*" | sed 's/.*running: //; s/,.*//')
before=$(curl -s "http://192.168.101.102:8025/api/v1/messages?limit=1" | grep -o '"total":[0-9]*' | cut -d: -f2)
rules="alerts_set=1&cpu_percent=90&cpu_minutes=15&mem_percent=90&mem_minutes=15&disk_percent=90&disk_min_free_gb=5&offline_minutes=15&reboot_days=7&defender_off=1&firewall_off=1"
$C -o /dev/null -d "email_on_open=1&email_on_resolve=1&recipients=stefan-test@maxzit.test" $S/settings/monitoring
# the alert rules come from a policy of the device, removed afterwards
APOL=$($C -o /dev/null -w '%{redirect_url}' -d "name=Regress+alerts&$rules&watch_services=$STOPPED" $S/policies/new | grep -o '[0-9]*$')
$C -o /dev/null -d "target=device:$DEV" $S/policies/$APOL/assign
sleep 4
check "alert opens for watched service $STOPPED" '$C $S/alerts | grep -q "$STOPPED"'
after=$(curl -s "http://192.168.101.102:8025/api/v1/messages?limit=1" | grep -o '"total":[0-9]*' | cut -d: -f2)
check "alert email sent" '[ "$after" -gt "$before" ]'
$C -o /dev/null -d "name=Regress+alerts&$rules&watch_services=Spooler" $S/policies/$APOL
sleep 4
check "alert resolves when the rule changes" '! $C $S/alerts | grep -q "$STOPPED"'
$C -o /dev/null -X POST $S/policies/$APOL/delete

# --- remote actions: services, processes, scripts, power
script() { # shell, script → body of the result page
  local loc
  printf "%s" "$2" > .gotmp/r-script.txt  # from a file: Git Bash would re-encode non-ASCII arguments
  loc=$($C -o /dev/null -w "%{redirect_url}" -d shell=$1 -d timeout=60 --data-urlencode "script@.gotmp/r-script.txt" $S/devices/$DEV/scripts)
  $C "$loc"
}
check "services page lists Spooler" '$C "$S/devices/$DEV/services?q=spooler" | grep -q "<code class=\"small muted\">Spooler</code>"'
check "processes page lists explorer.exe" '$C "$S/devices/$DEV/processes?q=explorer" | grep -qi "explorer.exe"'
$C -o /dev/null -d name=W32Time -d action=stop $S/devices/$DEV/services
check "service stopped from the console" 'script powershell "(Get-Service W32Time).Status" | grep -q "id=\"run-output\">Stopped"'
$C -o /dev/null -d name=W32Time -d action=start $S/devices/$DEV/services
check "service started from the console" 'script powershell "(Get-Service W32Time).Status" | grep -q "id=\"run-output\">Running"'
$C -o /dev/null -d name=RMMZitAgent -d action=stop $S/devices/$DEV/services
check "agent refuses to stop its own service" 'script cmd "sc query RMMZitAgent" | grep -q "RUNNING"'
check "PowerShell script output, UTF-8 and exit code" 'script powershell "Write-Output \"lab čćž \$env:USERNAME\"; exit 5" | grep -q "lab čćž SYSTEM\|lab čćž DESKTOP" && $C "$S/audit?q=script.run" | grep -q "exit code 5"'
check "cmd script output" 'script cmd "echo cmd-ok %COMPUTERNAME%" | grep -q "cmd-ok DESKTOP-NBB66OQ"'
check "activity history lists the scripts" '$C "$S/devices/$DEV/activity" | grep -q "Run a cmd script"'
# A long script goes to the activity; stopping it ends it within seconds.
printf "Start-Sleep -Seconds 240" > .gotmp/r-script.txt
$C -o /dev/null -d shell=powershell -d timeout=600 --data-urlencode "script@.gotmp/r-script.txt" $S/devices/$DEV/scripts
TID=$($C "$S/devices/$DEV/activity" | grep -o "activity/[0-9]*/cancel" | head -1 | grep -o "[0-9]*")
check "long script runs under Activity" '[ -n "$TID" ]'
$C -o /dev/null -X POST "$S/devices/$DEV/activity/$TID/cancel"
for i in 1 2 3 4 5 6 7 8 9 10; do $C "$S/devices/$DEV/activity" | grep -q data-autorefresh || break; sleep 2; done
check "stopped script shows as stopped" '$C "$S/devices/$DEV/activity" | grep -q "stopped from the console"'
check "script output in the audit log" '$C "$S/audit?q=script.run" | grep -q "lab čćž"'
check "service actions audited" '$C "$S/audit?q=service.stop" | grep -q "W32Time"'
check "unknown power action refused" '[ "$($C -o /dev/null -w %{http_code} -d action=hibernate -d delay=0 $S/devices/$DEV/power)" = 303 ] && ! $C "$S/audit?q=hibernate" | grep -q "hibernate of"'
check "audit chain still intact" '$C $S/audit | grep -q "is intact\|neprekinut\|netaknut"'

# --- roles: a technician of another customer sees nothing of this device
$C -o /dev/null -d "name=Other Customer QA" $S/customers
OC=$($C $S/customers | grep -o 'href="/customers/[0-9]*">Other Customer QA' | grep -o '[0-9]*' | head -1)
TPW="qa-tech-$(openssl rand -hex 6)"; QN="qatech$(openssl rand -hex 3)"
$C -o /dev/null -d username=$QN --data-urlencode "password=$TPW" -d role=technician -d customers=$OC $S/users
T=.gotmp/rt.txt; rm -f $T
curl -sk -b $T -c $T -H Origin:$S -o /dev/null --data-urlencode username=$QN --data-urlencode "password=$TPW" $S/login
curl -sk -b $T -c $T -H Origin:$S -o /dev/null --data-urlencode current="$TPW" --data-urlencode password="$TPW-new" --data-urlencode password2="$TPW-new" $S/account/password
check "technician cannot open the device" '[ "$(curl -sk -b $T -o /dev/null -w %{http_code} $S/devices/$DEV)" = 404 ]'
check "technician cannot open its files" '[ "$(curl -sk -b $T -o /dev/null -w %{http_code} "$S/devices/$DEV/files?path=C%3A%5C")" = 404 ]'
check "technician cannot open users" '[ "$(curl -sk -b $T -o /dev/null -w %{http_code} $S/users)" = 403 ]'
# clean up: disable the QA user
QU=$($C $S/users | grep -o "href=\"/users/[0-9]*\">$QN" | grep -o '[0-9]*' | head -1)
$C -o /dev/null -d role=technician -d disabled=1 $S/users/$QU

# --- agent updates
check "agent updates page shows the installer" '$C $S/settings/agents | grep -q "SHA-256"'
check "installer download needs an agent identity" '[ "$(curl -sk -o /dev/null -w %{http_code} $A/agent/v1/package)" = 401 ]'
check "agent runs the installer version" '$C $S/settings/agents | grep -q "All agents run the current version"'

# --- event logs and programs (winget)
check "System event log readable" '$C "$S/devices/$DEV/events?log=System&level=0&hours=720" | grep -q "events, newest first"'
check "installed programs listed from the registry" '$C "$S/devices/$DEV/software?view=list" | grep -q "name=\"name\" value=\"RMMZit Agent\""'
check "software library page with the Chocolatey setting" '$C "$S/software" | grep -q "name=\"chocolatey\""'
check "policies page" '$C "$S/policies" | grep -q "/policies/new"'
check "vulnerabilities page" '$C "$S/vulnerabilities" | grep -q "name=\"enabled\""'
check "device vulnerabilities tab" '$C "$S/devices/$DEV/vulnerabilities" | grep -q "devtabs"'
check "custom fields settings" '$C "$S/settings/fields" | grep -q "name=\"kind\""'
check "search finds the device" '$C "$S/search?q=DESKTOP-NBB" | grep -q "/devices/$DEV\""'
check "device list filters" '$C "$S/devices?os=linux" | grep -q "/devices/$LDEV\"" && ! $C "$S/devices?os=linux" | grep -q "/devices/$DEV\""'
check "report has security and health" '$C "$S/reports/view?customer=0&days=7" | grep -q "Security and health"'
check "policy editor has program updates and maintenance windows" '$C "$S/policies/new" | grep -q "name=\"apps_set\"" && $C "$S/policies/new" | grep -q "maint-rows"'
# network checks from the device, through a temporary device policy
NPOL=$($C -o /dev/null -w '%{redirect_url}' -d "name=Regress+checks&customer=0&net_set=1&net_name=Gateway&net_kind=ping&net_target=192.168.101.254&net_port=&net_minutes=5&net_name=Agent+port&net_kind=tcp&net_target=192.168.101.179&net_port=8444&net_minutes=5" $S/policies/new | grep -o '[0-9]*$')
$C -o /dev/null -d "target=device:$DEV" $S/policies/$NPOL/assign
for i in $(seq 1 40); do $C "$S/devices/$DEV" | grep -q "Agent port" && break; sleep 3; done
check "network checks run on the device" '$C "$S/devices/$DEV" | tr -d "\n" | grep -q "Agent port</b>.*badge ok.*Gateway</b>.*badge ok"'
$C -o /dev/null -X POST $S/policies/$NPOL/delete
check "device policy tab" '$C "$S/devices/$DEV/policy" | grep -q "Where the settings come from"'
# REST API with a short-lived read-only token, deleted afterwards.
TOK=$($C -d name=regress -d role=readonly -d days=1 $S/account/tokens | grep -o 'czt_[A-Za-z0-9_-]\{30,\}' | head -1)
check "API token reads the devices" 'curl -sk -H "Authorization: Bearer $TOK" "$S/api/v1/devices" | grep -q "\"id\": $DEV,"'
check "API refuses a read-only token for tasks" '[ "$(curl -sk -o /dev/null -w %{http_code} -H "Authorization: Bearer $TOK" -d "{\"kind\":\"patch.scan\"}" "$S/api/v1/devices/$DEV/tasks")" = 403 ]'
TDEL=$($C $S/account | grep -o "/account/tokens/[0-9]*/delete" | tail -1)
$C -o /dev/null -X POST "$S$TDEL"
check "deleted API token is refused" '[ "$(curl -sk -o /dev/null -w %{http_code} -H "Authorization: Bearer $TOK" "$S/api/v1/me")" = 401 ]'
check "BitLocker page lists the recovery keys" '$C "$S/devices/$DEV/bitlocker" | grep -q "{[0-9A-F-]\{36\}}"'

# --- Windows updates
check "device reports Windows updates" '$C $S/devices/$DEV/updates | grep -q "Searched"'
check "updates overview lists the device" '$C $S/updates | grep -q "/devices/$DEV/updates"'
check "Windows Update part on the policy page" '$C $S/policies/new | grep -q "name=\"mode\""'

# --- script library and jobs
LIBNAME="regress-$RANDOM"
SLOC=$($C -o /dev/null -w "%{redirect_url}" -d "name=$LIBNAME" -d shell=cmd -d timeout=60 --data-urlencode "script=echo lib-ok %COMPUTERNAME%" $S/scripts/new)
SID=${SLOC##*/}
JLOC=$($C -o /dev/null -w "%{redirect_url}" -d device=$DEV $S/scripts/$SID/run)
sleep 8
check "library job runs on the device" '$C "$JLOC" | grep -q "badge ok\"><i></i>succeeded"'
RLINK=$($C "$JLOC" | grep -o "/devices/$DEV/scripts/[0-9]*" | head -1)
check "library job output stored" '$C "$S$RLINK" | grep -q "lib-ok DESKTOP-NBB66OQ"'
$C -o /dev/null -d x=1 $S/scripts/$SID/delete

printf x > .gotmp/r-up.txt
check "remote desktop paste upload only into a staging folder" '[ "$($C -o /dev/null -w %{http_code} -F "dir=C:\cztest" -F "file=@.gotmp/r-up.txt;filename=x.txt" $S/devices/$DEV/rd/upload)" = 400 ]'

# --- Linux agent (LDEV: device ID of deb-vm)
if [ -n "$LDEV" ]; then
  check "Linux device online with its OS" '$C $S/devices/$LDEV | grep -q "Debian GNU/Linux"'
  check "Linux services listed" '$C "$S/devices/$LDEV/services?q=ssh" | grep -q ">ssh</code>"'
  printf '%s' 'echo linux-ok $(id -un)' > .gotmp/r-script.txt
  LLOC=$($C -o /dev/null -w "%{redirect_url}" -d shell=bash -d timeout=60 --data-urlencode "script@.gotmp/r-script.txt" $S/devices/$LDEV/scripts)
  check "Linux bash script as root" '$C "$LLOC" | grep -q "linux-ok root"'
  check "Linux updates searched" '$C $S/devices/$LDEV/updates | grep -q "Searched"'
  check "Linux agent runs $VER (self-update)" '$C $S/devices/$LDEV | grep -q "$VER"'
  check "Linux device offers the terminal" '$C $S/devices/$LDEV | grep -q "/devices/$LDEV/terminal"'
  GOTMPDIR=C:/Users/Mili/Ai/rmm/.gotmp go run ./tools/rdclient -console $S -device $LDEV -cookie "$CK" -term 'echo term-$((40+2)) $(id -un)' -wait 5s > .gotmp/r-term.log 2>&1
  check "Linux terminal runs a root shell" 'grep -q "term-42 root" .gotmp/r-term.log'
  GOTMPDIR=C:/Users/Mili/Ai/rmm/.gotmp go run ./tools/rdclient -console $S -device $LDEV -cookie "$CK" -out .gotmp/r-lrd.png -wait 6s > .gotmp/r-lrd.log 2>&1
  check "Linux remote desktop streams the X11 screen" 'grep -q "^screen 1600x900" .gotmp/r-lrd.log'
  sleep 2
  check "session ends keep the technician in the audit log" '$C "$S/audit?q=term.end" | grep -o "<td>[^<]*</td><td><code>term.end" | head -1 | grep -q "<td>admin</td>" && $C "$S/audit?q=rd.end" | grep -o "<td>[^<]*</td><td><code>rd.end" | head -1 | grep -q "<td>admin</td>"'
fi

$C -o /dev/null -d lang=sr $S/lang
echo "----"
echo "passed $pass, failed $fail"
