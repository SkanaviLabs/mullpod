#!/usr/bin/env bash
# End-to-end checks against a running instance (start it with `make run` first).
# Usage: scripts/verify.sh
set -uo pipefail

cd "$(dirname "$0")/.."
# The API address comes from config.yaml; the proxy ports from the running instance.
API=${API:-http://$(python3 test/addrs.py api)}
PROXY=${PROXY:-$(python3 test/addrs.py main)}
[[ -n $PROXY ]] || { echo "no instance answering at $API (start it with: make run)"; exit 1; }
CHECK=https://am.i.mullvad.net/json
pass=0 fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
ip_via() { curl -s --max-time 25 -x "http://$1:x@$PROXY" "$CHECK" | json 'd.get("ip","")' 2>/dev/null; }

echo "1. health + catalog"
h=$(curl -s --max-time 10 "$API/health")
[[ $(echo "$h" | json 'd["status"]') == ok ]] && ok "health: $h" || bad "health: $h"
n=$(curl -s "$API/exits" | json 'd["total"]')
(( n > 400 )) && ok "$n exits in catalog" || bad "only $n exits"

echo "2. country per exit"
for cc in de jp br; do
  got=$(curl -s --max-time 30 "$API/ip?exit=$cc" | json '(d["server"], d["check"].get("country"), d["check"].get("ip"), d["check"].get("mullvad_exit_ip"))')
  [[ $got == *"'$cc-"* && $got == *True* ]] && ok "$cc → $got" || bad "$cc → $got"
done
exitip=$(ip_via de)
[[ -n $exitip ]] && ok "curl -x http://de:x@$PROXY → $exitip" || bad "HTTP proxy via de returned nothing"
sockip=$(curl -s --max-time 25 -x "socks5h://jp:x@$PROXY" "$CHECK" | json 'd.get("country")' 2>/dev/null)
[[ $sockip == Japan ]] && ok "SOCKS5 via jp → $sockip" || bad "SOCKS5 via jp → '$sockip'"
code=$(curl -s -o /dev/null -w '%{http_code}' -x "http://$PROXY" http://example.com)
[[ $code == 407 ]] && ok "no credentials on $PROXY → 407" || bad "no credentials → $code"

echo "3. 30 parallel any requests"
ips=$(for i in $(seq 30); do ip_via any & done; wait)
total=$(echo "$ips" | grep -c . ); distinct=$(echo "$ips" | grep . | sort -u | wc -l | tr -d ' ')
(( total == 30 && distinct >= 10 )) && ok "$total ok, $distinct distinct IPs" || bad "$total ok, $distinct distinct IPs"

echo "4. sticky session"
s="verify$RANDOM"
ips=$(for i in $(seq 10); do ip_via "any_$s"; done | sort -u)
(( $(echo "$ips" | grep -c .) == 1 )) && ok "10 requests, one IP: $ips" || bad "sticky gave: $(echo $ips)"

echo "5. Mullvad codes and session moves"
# am.i.mullvad.net reports the SOCKS name (de-fra-wg-socks5-005); map it to the server name.
server_via() { curl -s --max-time 25 -x "http://$1:x@$PROXY" "$CHECK" | json 'd.get("mullvad_exit_ip_hostname","").replace("-wg-socks5-","-wg-")' 2>/dev/null; }
country_via() { curl -s --max-time 25 -x "http://$1:x@$PROXY" "$CHECK" | json 'd.get("country","")' 2>/dev/null; }
for u in se us de-fra; do
  c=$(country_via "$u")
  case $u in se) want=Sweden;; us) want=USA;; de-fra) want=Germany;; esac
  [[ $c == "$want" ]] && ok "username '$u' → $c" || bad "username '$u' → '$c' (want $want)"
done
srv=$(curl -s "$API/exits?servers=1" | json '[ci for co in d["countries"] if co["code"]=="de" for ci in co["cities"] if ci["code"]=="de-fra"][0]["hostnames"][-1]')
p="pin$RANDOM"
got=$(server_via "${srv}_$p")
[[ $got == "$srv" ]] && ok "exact '${srv}_$p' → $got" || bad "exact '${srv}_$p' → '$got'"
for u in de-fra de any default; do
  got=$(server_via "${u}_$p")
  [[ $got == "$srv" ]] && ok "'${u}_$p' stays on $got" || bad "'${u}_$p' → '$got' (want $srv)"
done
jpsrv=$(server_via "jp_$p")
[[ $jpsrv == jp-* ]] && ok "'jp_$p' moves the session to Japan: $jpsrv" || bad "'jp_$p' → '$jpsrv'"
got=$(server_via "any_$p")
[[ $got == "$jpsrv" ]] && ok "'any_$p' stays on $got" || bad "'any_$p' → '$got' (want $jpsrv)"
desrv=$(server_via "de_$p")
[[ $desrv == de-* ]] && ok "'de_$p' moves it back to Germany: $desrv" || bad "'de_$p' → '$desrv'"
got=$(server_via "any_$p")
[[ $got == "$desrv" ]] && ok "'any_$p' stays on $got" || bad "'any_$p' → '$got' (want $desrv)"

entry_of() { curl -s "$API/health" | json 'd.get("tunnel_info",{}).get("entry","")'; }
echo "6. move the tunnel to another entry server live"
before=$(entry_of)
curl -s -XPOST "$API/tunnel/switch" >/dev/null
for i in $(seq 40); do e=$(entry_of); [[ -n $e && $e != "$before" ]] && [[ $(curl -s "$API/health" | json 'd["tunnel"]') == True ]] && break; sleep 1; done
after=$(entry_of)
[[ -n $after && $after != "$before" ]] && ok "entry $before → $after" || bad "entry stayed '$after'"
[[ -n $(ip_via de) ]] && ok "traffic flows after the switch" || bad "no traffic after the switch"
cur=$(curl -s --max-time 20 -x "http://current:x@$PROXY" "$CHECK" | json 'd.get("mullvad_exit_ip_hostname","").replace("-wg-socks5-","-wg-")' 2>/dev/null)
[[ $cur == "$after" ]] && ok "'current' leaves via the new entry ($cur)" || bad "'current' left via '$cur', want $after"

echo; echo "passed $pass, failed $fail"
(( fail == 0 ))
