#!/bin/bash
# Usage: DEV=<device id> VER=<agent version> bash tools/labtest/regress.sh  (credentials from .devdata/lab-server.txt; needs the lab, see NOTES.md)
# Lab regression of ControlZit against the lab server (CT 9600) and bz-win11.
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
form="cpu_percent=90&cpu_minutes=15&mem_percent=90&mem_minutes=15&disk_percent=90&disk_min_free_gb=5&offline_minutes=15&reboot_days=7&defender_off=1&firewall_off=1&email_on_open=1&email_on_resolve=1&recipients=stefan-test@maxzit.test"
$C -o /dev/null -d "$form&watch_services=$STOPPED" $S/settings/monitoring
sleep 4
check "alert opens for watched service $STOPPED" '$C $S/alerts | grep -q "$STOPPED"'
after=$(curl -s "http://192.168.101.102:8025/api/v1/messages?limit=1" | grep -o '"total":[0-9]*' | cut -d: -f2)
check "alert email sent" '[ "$after" -gt "$before" ]'
$C -o /dev/null -d "$form&watch_services=Spooler" $S/settings/monitoring
sleep 4
check "alert resolves when the rule changes" '! $C $S/alerts | grep -q "$STOPPED"'

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

echo "----"
echo "passed $pass, failed $fail"
