// S3 AdBlock — DNS sinkhole + web dashboard for the ESP32-S3 SuperMini.
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://s3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include "lwip/etharp.h"
#include "lwip/netif.h"
#if __has_include("secrets.h")
#include "secrets.h"   // defines WIFI_SSID / WIFI_PASS
#else
#ifndef WIFI_SSID
#define WIFI_SSID "YOUR_WIFI_SSID"
#endif
#ifndef WIFI_PASS
#define WIFI_PASS "YOUR_WIFI_PASSWORD"
#endif
#endif
#include "led_indicator.h"

#ifndef HARDCODED_IP
static const IPAddress HARDCODED_IP(192, 168, 1, 50);
#endif
#ifndef HARDCODED_GW
static const IPAddress HARDCODED_GW(192, 168, 1, 1);
#endif
#ifndef HARDCODED_MASK
static const IPAddress HARDCODED_MASK(255, 255, 255, 0);
#endif
#ifndef HARDCODED_DNS
static const IPAddress HARDCODED_DNS(1, 1, 1, 1);
#endif

// ---- WiFi config (runtime, overrides secrets.h) ----
String cfgSsid = "";
String cfgPass = "";
bool cfgDhcp = true;
IPAddress cfgIp, cfgGw, cfgSubnet, cfgDns;
String lastGoodSsid = "", lastGoodPass = "";

static void saveWifiConfig();
static void loadWifiConfig() {
  File f = LittleFS.open("/wifi.cfg", "r"); if (!f) { Serial.println("[wifi] no config"); return; }
  cfgSsid = f.readStringUntil('\n'); cfgSsid.trim();
  cfgPass = f.readStringUntil('\n'); cfgPass.trim();
  cfgDhcp = f.readStringUntil('\n').toInt() != 0;
  cfgIp.fromString(f.readStringUntil('\n'));
  cfgGw.fromString(f.readStringUntil('\n'));
  cfgSubnet.fromString(f.readStringUntil('\n'));
  cfgDns.fromString(f.readStringUntil('\n'));
  f.close();
  if (!cfgDhcp && (cfgIp[0]==0 || cfgIp[3]==0)) {
    cfgIp = HARDCODED_IP; cfgGw = HARDCODED_GW;
    cfgSubnet = HARDCODED_MASK; cfgDns = HARDCODED_DNS;
    Serial.println("[wifi] using hardcoded static IP");
  }
}
static void saveWifiConfig() {
  File f = LittleFS.open("/wifi.cfg", "w"); if (!f) return;
  f.println(cfgSsid); f.println(cfgPass);
  f.println(cfgDhcp ? "1" : "0");
  f.println(cfgIp.toString()); f.println(cfgGw.toString());
  f.println(cfgSubnet.toString()); f.println(cfgDns.toString());
  f.close();
  Serial.printf("[wifi] saved: dhcp=%d", cfgDhcp);
  if (!cfgDhcp) Serial.printf(" ip=%s", cfgIp.toString().c_str());
  Serial.printf("\n");
}
static void saveLastGoodWifi() {
  File f = LittleFS.open("/lastwifi.cfg", "w"); if (!f) return;
  f.println(WiFi.SSID()); f.println(WiFi.psk());
  f.close();
}
static bool loadLastGoodWifi() {
  File f = LittleFS.open("/lastwifi.cfg", "r"); if (!f) return false;
  lastGoodSsid = f.readStringUntil('\n'); lastGoodSsid.trim();
  lastGoodPass = f.readStringUntil('\n'); lastGoodPass.trim();
  f.close();
  return lastGoodSsid.length() > 0;
}
static bool tryConnect(const String& ssid, const String& pass, int timeoutSec) {
  if (ssid.length() == 0) return false;
  WiFi.disconnect(); delay(100);
  WiFi.mode(WIFI_STA); WiFi.setSleep(false);
  if (cfgDhcp) {
    WiFi.config(0u, 0u, 0u);
  } else {
    WiFi.config(cfgIp, cfgGw, cfgSubnet, cfgDns);
  }
  WiFi.begin(ssid.c_str(), pass.c_str());
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < timeoutSec * 4) {
    delay(250); tries++;
  }
  return WiFi.status() == WL_CONNECTED;
}

// ---- config ----
static const IPAddress UPSTREAM(9, 9, 9, 9);     // Quad9
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[600];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static bool inFlash(uint64_t h) {
  int32_t lo = 0, hi = (int32_t)numHashes - 1; uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    blocklist.seek((uint32_t)mid * HASH_BYTES); blocklist.read(b, HASH_BYTES);
    uint64_t v = 0; for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    if (v < h) lo = mid + 1; else if (v > h) hi = mid - 1; else return true;
  }
  return false;
}
static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }
static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (inFlash(h) || inCustom(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";  led_indicator_trigger_new_client();
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
static int forwardUpstream(int qlen) {
  upstreamCli.beginPacket(UPSTREAM, 53); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  uint32_t t0 = millis();
  while (millis() - t0 < 1000) { int sz = upstreamCli.parsePacket(); if (sz > 0) return upstreamCli.read(buf, sizeof(buf)); delay(1); }
  return 0;
}
static void handleDns() {
  int sz = dnsServer.parsePacket(); if (sz <= 0) return;
  IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
  int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) return;
  char domain[256]; uint16_t qtype = 0; int qend = qlen;
  size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
  Dev* c = getClient((uint32_t)cip);
  bool ban = c && c->banned;
  bool blocked = ban || (dl && numHashes && isBlocked(domain));
  int rlen;
  if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; led_indicator_trigger(true); }
  else         { rlen = forwardUpstream(qlen);     totalAllowed++; if (c) c->allowed++; led_indicator_trigger(false); }
  if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }

const char PAGE[] PROGMEM = R"HTML(<!DOCTYPE html>

<html><head>
<meta charset="utf-8"/>
<meta content="width=device-width,initial-scale=1" name="viewport"/>
<title>S3 AdBlock - Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{
    font:12px/1.4 "SF Mono", Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    background-attachment: fixed;
    color: #e2e8f0;
    padding: 20px;
    min-height: 100vh;
}
header{
    border-bottom: 2px solid #00f7ff;
    margin-bottom: 24px;
    padding-bottom: 8px;
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    color: #00f7ff;
    text-shadow: 0 0 10px rgba(0, 247, 255, 0.3);
}
h1{font-size:16px;font-weight:700;text-transform:uppercase;letter-spacing:1px}
h1 span{font-weight:400;color: #94a3b8;font-size:12px;margin-left:8px}
.wrap{max-width:1200px;margin:0 auto}
.cards{
    display:grid;
    grid-template-columns:repeat(auto-fill, minmax(160px, 1fr));
    gap:0;
    border-top:1px solid rgba(0, 247, 255, 0.2);
    border-left:1px solid rgba(0, 247, 255, 0.2);
    margin-bottom:24px;
    box-shadow: 0 0 15px rgba(0, 0, 0, 0.3);
}
.card{
    border-right:1px solid rgba(0, 247, 255, 0.2);
    border-bottom:1px solid rgba(0, 247, 255, 0.2);
    padding:10px 12px;
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(4px);
}
.card .l{font-size:10px;color:#94a3b8;text-transform:uppercase;font-weight:600;margin-bottom:4px}
.card .v{font-size:14px;font-weight:700;color:#fff}
.card .v.b{color:#ff4d4d; text-shadow: 0 0 8px rgba(255, 77, 77, 0.4);}
.card .v.a{color:#00f7ff; text-shadow: 0 0 8px rgba(0, 247, 255, 0.4);}
h2{
    font-size:11px;
    font-weight:800;
    color:#00f7ff;
    margin:24px 0 8px;
    text-transform:uppercase;
    letter-spacing:0.5px;
    border-left:3px solid #00f7ff;
    padding-left:8px;
}
table{
    width:100%;
    border-collapse:collapse;
    margin-bottom:16px;
    border:1px solid rgba(0, 247, 255, 0.2);
    background: rgba(15, 23, 42, 0.4);
}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid rgba(0, 247, 255, 0.1);font-size:12px}
th{background: rgba(0, 247, 255, 0.1); color:#00f7ff; font-weight:600;font-size:11px;text-transform:uppercase}
tr:last-child td{border-bottom:none}
tr:hover td{background: rgba(0, 247, 255, 0.05)}
.b{color:#ff4d4d;font-weight:600}
.a{color:#00f7ff;font-weight:600}
.tag{background:rgba(220, 38, 38, 0.2);color:#ff4d4d;border:1px solid #dc2626;border-radius:2px;padding:0 4px;font-size:10px;font-weight:700}
button{
    background:transparent;
    color:#00f7ff;
    border:1px solid #00f7ff;
    border-radius:0;
    padding:4px 8px;
    cursor:pointer;
    font-size:11px;
    font-weight:600;
    text-transform:uppercase;
    transition:all 0.2s ease;
}
button:hover{background:#00f7ff;color:#1a1a2e;box-shadow: 0 0 10px rgba(0, 247, 255, 0.5);}
button.ban{border-color:#ff4d4d;color:#ff4d4d}
button.ban:hover{background:#ff4d4d;color:#fff;box-shadow: 0 0 10px rgba(255, 77, 77, 0.5);}
button.sec{border-color:#94a3b8;color:#94a3b8}
button.sec:hover{background:#94a3b8;color:#1a1a2e}
button:disabled{opacity:0.3;cursor:not-allowed}
input,select{
    background: rgba(15, 23, 42, 0.8);
    border:1px solid rgba(0, 247, 255, 0.3);
    color:#fff;
    border-radius:0;
    padding:5px 8px;
    font-size:12px;
    outline:none;
    font-family:inherit;
}
input:focus,select:focus{border-color:#00f7ff; box-shadow: 0 0 5px rgba(0, 247, 255, 0.3);}
.inp-group{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px}
.hint{color:#94a3b8;font-size:11px;margin-top:4px}
label{font-size:11px;font-weight:700;width:100px;color:#94a3b8;text-transform:uppercase}
.section-box{
    border:1px solid rgba(0, 247, 255, 0.2);
    padding:16px;
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(8px);
    margin-bottom:16px;
}
h3 {font-size: 11px; text-transform: uppercase; color: #fff; margin-bottom: 10px;}
</style></head>
<body><header><h1>S3 AdBlock <span id="host">@ 19.33.0.200</span></h1><div>Utility Dashboard v1.2</div></header><div class="wrap"><div class="cards" id="sys"><div class="card"><div class="l">Total blocked</div><div class="v b">31</div></div><div class="card"><div class="l">Total allowed</div><div class="v a">643</div></div><div class="card"><div class="l">Blocklist</div><div class="v">1,552,512 domains</div></div><div class="card"><div class="l">Clients</div><div class="v">4</div></div><div class="card"><div class="l">WiFi Signal</div><div class="v">-59 dBm</div></div><div class="card"><div class="l">Free RAM</div><div class="v">235 KB</div></div><div class="card"><div class="l">Uptime</div><div class="v">0d 0h 4m</div></div></div><h2>Network Clients</h2><table id="ct"><thead><tr><th>Client IP</th><th>MAC Address</th><th>Blocked</th><th>Allowed</th><th>Actions</th></tr></thead><tbody><tr><td>19.33.0.12</td><td>ee:c4:69:91:61:f6</td><td class="b">17</td><td class="a">220</td><td><button class="ban" onclick="fetch('/ban?ip=19.33.0.12').then(load)">Ban</button></td></tr><tr><td>19.33.0.104</td><td>00:00:00:00:00:00</td><td class="b">11</td><td class="a">165</td><td><button class="ban" onclick="fetch('/ban?ip=19.33.0.104').then(load)">Ban</button></td></tr><tr><td>19.33.0.13</td><td>c2:7a:75:1a:1f:45</td><td class="b">3</td><td class="a">161</td><td><button class="ban" onclick="fetch('/ban?ip=19.33.0.13').then(load)">Ban</button></td></tr><tr><td>19.33.0.32</td><td>00:00:00:00:00:00</td><td class="b">0</td><td class="a">97</td><td><button class="ban" onclick="fetch('/ban?ip=19.33.0.32').then(load)">Ban</button></td></tr></tbody></table><div style="display:grid;grid-template-columns:1fr 1fr;gap:20px"><div><h2>WiFi Network</h2><div class="section-box"><div class="inp-group"><label>SSID</label><input id="wSsid" placeholder="Network name" style="flex:1"/></div><div class="inp-group"><label>Password</label><input id="wPass" placeholder="WiFi password" style="flex:1" type="password"/></div><div class="inp-group" style="margin-top:12px"><button id="saveWifiBtn" onclick="saveWifi()">Save &amp; Reboot</button> <span class="hint" id="wMsg"></span></div><div class="hint">Updates SSID/Password and triggers device restart.</div></div><h2>IP Configuration</h2><div class="section-box"><div class="inp-group"><label>IP Mode</label><select id="wDhcp" style="flex:1"><option value="1">DHCP (Automatic)</option><option value="0">Static IP</option></select></div><div id="wStatic" style="display: block; margin-top:8px; border-top:1px solid rgba(0, 247, 255, 0.1); padding-top:8px;"><div class="inp-group"><label>IP</label><input id="wIp" placeholder="192.168.1.100" style="flex:1"/></div><div class="inp-group"><label>Gateway</label><input id="wGw" placeholder="192.168.1.1" style="flex:1"/></div><div class="inp-group"><label>Subnet</label><input id="wSn" placeholder="255.255.255.0" style="flex:1"/></div><div class="inp-group"><label>DNS</label><input id="wDns" placeholder="8.8.8.8" style="flex:1"/></div></div><div class="inp-group" style="margin-top:12px"><button onclick="saveIp()">Apply Settings</button> <span class="hint" id="ipMsg"></span></div></div></div><div><h2>Custom Rules</h2><div class="section-box"><div class="inp-group"><input id="dom" placeholder="ads.example.com" style="flex:1"/><button onclick="addDom()">Add Domain</button></div><table id="cl" style="margin-top:10px"><tbody><tr><td style="color:#94a3b8">No custom domains defined.</td></tr></tbody></table></div><h2>System Maintenance</h2><div class="section-box"><h3>Update Blocklist</h3><form action="http://19.33.0.200/upload" class="inp-group" enctype="multipart/form-data" id="upf" method="POST" style="margin:12px 0"><input accept=".bin" id="blf" name="file" style="flex:1" type="file"/><button>Upload</button></form><div class="hint" id="blmsg"></div><div class="hint">Upload prebuilt blocklist.bin files here.</div><h3 style="margin-top:20px">Remote Sync</h3><div class="inp-group" style="margin-top:8px"><input id="uurl" placeholder="https://host/blocklist.bin" style="flex:1"/> Every <input id="uiv" style="width:40px" value="24"/>h</div><div class="inp-group"><button onclick="saveUpd()">Save Config</button> <button class="sec" onclick="fetchNow()">Fetch Now</button></div><div class="hint">Status: <span id="ustat">Never</span></div><h3 style="margin-top:20px">Firmware OTA</h3><form action="http://19.33.0.200/update" class="inp-group" enctype="multipart/form-data" id="fwf" method="POST" style="margin:12px 0"><input accept=".bin" id="fwb" name="file" style="flex:1" type="file"/><button>Flash</button></form><div class="hint" id="fwmsg"></div><h3 style="margin-top:20px">Hardware Control</h3><div class="inp-group" style="margin-top:8px"><button onclick="doReboot()" style="border-color:#94a3b8">Reboot Device</button> <span class="hint" id="rMsg"></span><div class="inp-group" style="margin-top:8px"><label>LED Brightness</label><input type="range" id="ledBr" min="1" max="255" value="128" style="flex:1;max-width:200px" onchange="var v=this.value;fetch('/led',{method:'POST',body:new URLSearchParams({br:v})}).then(function(){ledVal.textContent=v});"><span id="ledVal" class="hint">128</span></div></div></div></div></div></div><script>function fmt(n){return typeof n==='number'?n.toLocaleString():n}async function load(){let s=await(await fetch('/stats.json')).json();host.textContent='@ '+s.ip;sys.innerHTML=[['Total blocked',fmt(s.blocked),'b'],['Total allowed',fmt(s.allowed),'a'],['Blocklist',fmt(s.domains)+' domains',''],['Clients',s.clients.length,''],['WiFi',s.rssi+' dBm',''],['Free RAM',Math.round(s.heap/1024)+' KB',''],['Uptime',s.uptime,'']].map(function(c){return '<div class=card><div class=l>'+c[0]+'</div><div class="v '+c[2]+'">'+c[1]+'</div></div>';}).join('');ct.tBodies[0].innerHTML=s.clients.sort(function(a,b){return (b.blocked+b.allowed)-(a.blocked+a.allowed);}).map(function(c){return '<tr><td>'+c.ip+(c.banned?' <span class=tag>BANNED</span>':'')+'</td><td>'+c.mac+'</td><td class=b>'+fmt(c.blocked)+'</td><td class=a>'+fmt(c.allowed)+'</td><td><button class=ban onclick="fetch(\'/ban?ip='+c.ip+'\').then(load)">'+(c.banned?'Unban':'Ban')+'</button></td></tr>';}).join('');cl.tBodies[0].innerHTML=s.custom.map(function(d){return '<tr><td>'+d+'</td><td style=text-align:right><button onclick="fetch(\'/unblock?d='+encodeURIComponent(d)+'\').then(load)">Remove</button></td></tr>';}).join('')||'<tr><td style=color:#94a3b8>No custom domains defined.</td></tr>';if(document.activeElement!=uurl)uurl.value=s.upurl||'';if(document.activeElement!=uiv)uiv.value=s.upiv||24;ustat.textContent=s.upstat||'Never';if(document.activeElement!=wSsid)wSsid.value=s.ssid||'';wDhcp.value=s.dhcp?'1':'0';wDhcp.onchange();if(!s.dhcp&&s.ip){wIp.value=s.ip;wGw.value=s.gw||'';wSn.value=s.subnet||'';wDns.value=s.dns||'';}}function addDom(){var d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d)).then(function(){dom.value='';load();});}}function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24)).then(load);}function fetchNow(){ustat.textContent='fetching...';fetch('/fetchnow').then(function(r){return r.text();}).then(function(t){ustat.textContent=t;load();});}function saveIp(){var b=event.target;b.disabled=true;ipMsg.textContent='Saving IP...';var p=new URLSearchParams();p.set('dhcp',wDhcp.value);if(wDhcp.value=='0'){p.set('ip',wIp.value.trim());p.set('gw',wGw.value.trim());p.set('subnet',wSn.value.trim());p.set('dns',wDns.value.trim());}fetch('/ipcfg',{method:'POST',body:p}).then(function(r){return r.text();}).then(function(t){ipMsg.textContent=t;setTimeout(function(){b.disabled=false;},2000);}).catch(function(){ipMsg.textContent='Error';b.disabled=false;});}function saveWifi(){var b=saveWifiBtn;b.disabled=true;wMsg.textContent='Saving WiFi...';var p=new URLSearchParams();p.set('ssid',wSsid.value.trim());p.set('pass',wPass.value);p.set('dhcp',wDhcp.value);if(wDhcp.value=='0'){p.set('ip',wIp.value.trim());p.set('gw',wGw.value.trim());p.set('subnet',wSn.value.trim());p.set('dns',wDns.value.trim());}fetch('/wificfg',{method:'POST',body:p}).then(function(r){return r.text();}).then(function(t){wMsg.textContent=t;setTimeout(function(){b.disabled=false;},3000);}).catch(function(){wMsg.textContent='Error';b.disabled=false;});}function doReboot(){rMsg.textContent='Rebooting...';fetch('/reboot').then(function(r){return r.text();}).then(function(t){rMsg.textContent=t+', page will reload...';setTimeout(function(){location.reload();},5000);});}var refreshTimer = setInterval(load,3000);wDhcp.onchange=function(){wStatic.style.display=this.value=='0'?'block':'none';};upf.onsubmit=function(e){e.preventDefault();var b=upf.querySelector('button');b.disabled=1;blmsg.textContent='Uploading...';fetch('/upload',{method:'POST',body:new FormData(upf)}).then(function(r){return r.text();}).then(function(t){blmsg.textContent=t;b.disabled=0;load();}).catch(function(){blmsg.textContent='Error';b.disabled=0;});}
fwf.onsubmit=function(e){e.preventDefault();var b=fwf.querySelector('button');b.disabled=1;fwmsg.textContent='Uploading...';fetch('/update',{method:'POST',body:new FormData(fwf)}).then(function(r){return r.text();}).then(function(t){fwmsg.textContent=t;setTimeout(function(){b.disabled=0;},2000);if(t=='ok, rebooting')setTimeout(function(){location.reload();},3000);}).catch(function(){fwmsg.textContent='Error';b.disabled=0;});}
load();var ledLoad=function(){fetch('/led').then(function(r){return r.json();}).then(function(j){if(!document.activeElement||document.activeElement!=ledBr){ledBr.value=j.br;ledVal.textContent=j.br;}});};ledLoad();</script></body></html>)HTML";

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"ssid\":\"" + jesc(WiFi.SSID()) + "\",\"dhcp\":" + (cfgDhcp ? "true" : "false") + ",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"brightness\":" + String(led_indicator_get_brightness()) + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
static void handleBan() {
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
}
static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;       // sorted hash blob -> 5-byte multiple
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static File upFile;
static void handleUploadDone() {
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: empty or size not a multiple of 5 (not a blocklist.bin?)");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upOk = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static void handleFwUpdateDone() {
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  led_indicator_init();
  Serial.println("\n[s3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) { numHashes = blocklist.size() / HASH_BYTES; Serial.printf("blocklist: %u domains\n", numHashes); }
  loadCustom(); loadBanned(); loadUpdateCfg();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  loadWifiConfig();
  if (cfgSsid.length() > 0) {
    Serial.printf("[wifi] connecting to %s (dhcp=%d)\n", cfgSsid.c_str(), cfgDhcp);
    if (!tryConnect(cfgSsid, cfgPass, 15)) {
      Serial.println("[wifi] failed, trying last good");
      if (loadLastGoodWifi()) tryConnect(lastGoodSsid, lastGoodPass, 15);
    }
  } else {
    cfgSsid = WIFI_SSID; cfgPass = WIFI_PASS; cfgDhcp = true;
    WiFi.disconnect(); delay(50);
    WiFi.mode(WIFI_STA); WiFi.setSleep(false);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.print("WiFi"); while (WiFi.status() != WL_CONNECTED) { delay(300); Serial.print("."); }
  }
  saveLastGoodWifi();
  Serial.printf("\nWiFi up: %s\n", WiFi.localIP().toString().c_str());
  MDNS.begin("s3adblock"); MDNS.addService("http", "tcp", 80);

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA
  web.on("/fetchnow", []() { fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/wificfg", []() {
    if (web.method() == HTTP_POST) {
      String ns = web.arg("ssid"); ns.trim();
      cfgSsid = ns; String np = web.arg("pass"); if (np.length() > 0) cfgPass = np;
      cfgDhcp = web.arg("dhcp") != "0";
      cfgIp.fromString(web.arg("ip")); cfgGw.fromString(web.arg("gw"));
        cfgSubnet.fromString(web.arg("subnet")); cfgDns.fromString(web.arg("dns"));
        if (!cfgDhcp && cfgIp[3] == 0) { web.send(200, "text/plain", "error: IP ends with .0"); return; }
      saveWifiConfig();
      web.send(200, "text/plain", "saved, rebooting...");
      delay(100);
      tryConnect(cfgSsid, cfgPass, 20);
      saveLastGoodWifi();
      delay(300); ESP.restart();
    } else {
      String j = "{\"ssid\":\"" + jesc(cfgSsid) + "\",\"dhcp\":" + (cfgDhcp ? "true" : "false");
      if (!cfgDhcp) j += ",\"ip\":\"" + cfgIp.toString() + "\",\"gw\":\"" + cfgGw.toString() + "\",\"subnet\":\"" + cfgSubnet.toString() + "\",\"dns\":\"" + cfgDns.toString() + "\"";
      j += "}";
      web.send(200, "application/json", j);
    }
  });
  web.on("/ipcfg", []() {
    if (web.method() == HTTP_POST) {
      cfgDhcp = web.arg("dhcp") != "0";
      cfgIp.fromString(web.arg("ip")); cfgGw.fromString(web.arg("gw"));
        cfgSubnet.fromString(web.arg("subnet")); cfgDns.fromString(web.arg("dns"));
        if (!cfgDhcp && cfgIp[3] == 0) { web.send(200, "text/plain", "error: IP ends with .0"); return; }
      saveWifiConfig();
      web.send(200, "text/plain", cfgDhcp ? "saved (DHCP)" : ("saved: " + cfgIp.toString()));
      delay(100);
      String ssid = WiFi.SSID(); String pass = WiFi.psk();
      WiFi.disconnect(); delay(200);
      WiFi.mode(WIFI_STA); WiFi.setSleep(false);
      if (cfgDhcp) WiFi.config((uint32_t)0, (uint32_t)0, (uint32_t)0);
      else WiFi.config(cfgIp, cfgGw, cfgSubnet, cfgDns);
      WiFi.begin(ssid.c_str(), pass.c_str());
      int w = 0; while (WiFi.status() != WL_CONNECTED && w < 120) { delay(500); w++; }
      if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("[ipcfg] reconnect IP: %s\n", WiFi.localIP().toString().c_str());
      }
    }
  });
  web.on("/led", []() { if (web.method() == HTTP_POST) { int br = web.arg("br").toInt(); if (br < 0) br = 0; if (br > 255) br = 255; led_indicator_set_brightness(br); web.send(200, "text/plain", String(br)); } else { web.send(200, "application/json", "{\"br\":" + String(led_indicator_get_brightness()) + "}"); } });
  web.on("/reboot", []() { web.send(200, "text/plain", "rebooting"); delay(300); ESP.restart(); });
  web.on("/setupdate", []() {
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("s3adblock");   // pio run -t upload --upload-port s3adblock.local
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  handleDns();
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  led_indicator_update();
  delay(1);
}
