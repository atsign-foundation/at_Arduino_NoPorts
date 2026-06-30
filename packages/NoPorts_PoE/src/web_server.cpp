#include "web_server.h"
#include "nvsconfig.h"
#include <LittleFS.h>
#include <Arduino.h>
#ifdef NOPORTS_POE_P4
#include <ETH.h>
#include "led.h"
#endif

extern "C" {
#include "atauth.h"
}

// ─── Singletons ───────────────────────────────────────────────────────────
static WebServer   *_srv = nullptr;
static NoPortsDaemon  *_daemon  = nullptr;
static bool           *_running = nullptr;
static DaemonStats    *_stats   = nullptr;
static EnrollStatus   *_enroll  = nullptr;
static void          (*_restart_cb)() = nullptr;

static uint32_t _start_ms       = 0;    // set at web_server_begin() time
static bool     _restart_pending = false; // set by settings POST, cleared by loop()
static bool     _localhost_only  = false; // mirrors NVS_KEY_WEB_LOCAL; set at bind time

static void _rebind(bool local);  // forward declaration — defined near web_server_begin()

// ─── Common page chrome ───────────────────────────────────────────────────
// CSS is deliberately compact (fits ~1.5 KB) so pages render fast over 100 Mbps Ethernet.

static const char CSS[] =
  "*{box-sizing:border-box;margin:0;padding:0}"
  "body{font-family:system-ui,sans-serif;background:#0E1117;color:#e0e0e0;min-height:100vh}"
  ".nav{background:#181C24;padding:12px 16px;border-bottom:1px solid #2a3042;"
        "display:flex;align-items:center;gap:12px}"
  ".logo{color:#F06000;font-weight:700;font-size:1.1em}"
  ".nav a{color:#8B9BB4;text-decoration:none;padding:5px 10px;border-radius:4px;font-size:.85em}"
  ".nav a:hover{background:#252d3d}"
  ".ctr{max-width:640px;margin:20px auto;padding:0 16px}"
  ".card{background:#181C24;border:1px solid #2a3042;border-radius:8px;"
         "padding:16px;margin-bottom:14px}"
  ".card h2{color:#F06000;font-size:.8em;text-transform:uppercase;letter-spacing:.1em;"
             "margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #2a3042}"
  ".row{display:flex;justify-content:space-between;align-items:center;"
        "padding:7px 0;border-bottom:1px solid #1a2032}"
  ".row:last-child{border-bottom:0}"
  ".lbl{color:#8B9BB4;font-size:.82em}"
  ".val{font-weight:500;font-size:.9em}"
  ".badge{padding:2px 10px;border-radius:20px;font-size:.72em;font-weight:700}"
  ".ok{background:#18A06025;color:#18A060;border:1px solid #18A06060}"
  ".err{background:#E8404025;color:#E84040;border:1px solid #E8404060}"
  ".dim{background:#2a304225;color:#8B9BB4;border:1px solid #2a304260}"
  "label{display:block;color:#8B9BB4;font-size:.82em;margin-top:14px;margin-bottom:4px}"
  "input,textarea,select{width:100%;padding:8px 10px;background:#0E1117;"
                          "border:1px solid #2a3042;border-radius:5px;color:#e0e0e0;font-size:.9em}"
  "input:focus,textarea:focus,select:focus{outline:none;border-color:#F06000}"
  "textarea{resize:vertical;min-height:72px;font-family:monospace;font-size:.82em}"
  ".btn{display:inline-flex;align-items:center;padding:8px 18px;border-radius:5px;"
        "border:0;cursor:pointer;font-size:.88em;font-weight:600;text-decoration:none;"
        "transition:opacity .15s}"
  ".pr{background:#F06000;color:#fff}"
  ".sc{background:#252d3d;color:#e0e0e0}"
  ".dr{background:#E84040;color:#fff}"
  ".btn:hover{opacity:.82}"
  ".btns{display:flex;gap:8px;margin-top:16px;flex-wrap:wrap}"
  ".msg{padding:10px 12px;border-radius:5px;font-size:.85em;margin-top:12px}"
  ".msg.ok{background:#18A06020;color:#18A060;border:1px solid #18A06040}"
  ".msg.err{background:#E8404020;color:#E84040;border:1px solid #E8404040}"
  ".msg.inf{background:#F0600020;color:#F06000;border:1px solid #F0600040}"
  ".hide{display:none}"
  ".hint{color:#8B9BB4;font-size:.75em;margin-top:3px}"
  "h1{color:#F06000;font-size:1.1em;margin-bottom:4px}"
  ".sub{color:#8B9BB4;font-size:.82em;margin-bottom:16px}";

// Stream a full page: header + CSS + nav + body + footer
static void _send_page(const String &title, const String &body) {
  String page;
  page.reserve(4096);
  page  = "<!DOCTYPE html><html><head><meta charset=UTF-8>";
  page += "<meta name=viewport content='width=device-width,initial-scale=1'>";
  page += "<title>NoPorts PoE &#8212; "; page += title; page += "</title>";
  page += "<style>"; page += CSS; page += "</style></head><body>";
  page += "<nav class=nav><span class=logo>NoPorts PoE</span>";
  page += "<a href='/'>Dashboard</a><a href='/settings'>Settings</a>";
  page += "<a href='/config'>Config</a></nav>";
  page += "<div class=ctr>"; page += body; page += "</div></body></html>";
  _srv->send(200, "text/html; charset=utf-8", page);
}

static void _send_json(int code, const String &json) {
  _srv->send(code, "application/json", json);
}

// ─── Dashboard (/  +  /api/status) ───────────────────────────────────────

static void _handle_status() {
  char upbuf[24];
  nvs_format_uptime(millis() - _start_ms, upbuf, sizeof(upbuf));

  const char *state_str = "stopped";
  if (_running && *_running && _daemon) {
    switch (_stats->state) {
      case DAEMON_MONITORING:   state_str = "running";  break;
      case DAEMON_AUTHENTICATING: state_str = "auth";   break;
      case DAEMON_INITIALIZING: state_str = "init";     break;
      case DAEMON_ERROR:        state_str = "error";    break;
      default: break;
    }
  }

  String ip;
#ifdef NOPORTS_TEST_WIFI_AP
  ip = WiFi.softAPIP().toString();
#elif defined(NOPORTS_POE_P4)
  ip = ETH.localIP().toString();
#else
  ip = "0.0.0.0";
#endif

  String j;
  j.reserve(512);
  j  = "{\"state\":\""; j += state_str;
  j += "\",\"atsign\":\"";  j += nvs_load(NVS_KEY_ATSIGN);
  j += "\",\"device\":\"";  j += nvs_load(NVS_KEY_DEVICE);
  j += "\",\"version\":\"" POE_APP_VERSION "\"";
  j += ",\"uptime\":\"";    j += upbuf;
  j += "\",\"uptime_s\":";  j += (millis() - _start_ms) / 1000;
  j += ",\"tunnels\":";     j += (_stats ? _stats->total_tunnels : 0);
  j += ",\"pings\":";       j += (_stats ? _stats->total_pings   : 0);
  j += ",\"bytes_in\":";    j += (_stats ? _stats->bytes_in      : 0);
  j += ",\"bytes_out\":";   j += (_stats ? _stats->bytes_out     : 0);
  j += ",\"relay_cpu\":";   j += (_stats ? _stats->relay_cpu     : 0);
  j += ",\"active_relays\":"; j += (_stats ? _stats->active_relays : 0);
  j += ",\"pcb_count\":";   j += (_stats ? _stats->pcb_count     : 0);
  j += ",\"pcb_max\":";     j += (_stats ? _stats->pcb_max       : 5);
  j += ",\"configured\":";  j += nvs_is_configured() ? "true" : "false";
  j += ",\"enrolled\":";    j += LittleFS.exists(ATKEYS_PATH) ? "true" : "false";
  j += ",\"ip\":\"";        j += ip; j += "\"}";
  _send_json(200, j);
}

static void _handle_dashboard() {
  String b;
  b.reserve(2048);

  String atsign  = nvs_load(NVS_KEY_ATSIGN);
  String device  = nvs_load(NVS_KEY_DEVICE);
  bool enrolled  = LittleFS.exists(ATKEYS_PATH);
  bool configured = nvs_is_configured();

  if (!configured || !enrolled) {
    b  = "<div class=card>";
    b += "<h1>Welcome to NoPorts PoE</h1>";
    b += "<p class=sub>Connect your device to the atSign network.</p>";
    b += "<div class=btns><a class='btn pr' href='/setup'>Set Up Device</a></div>";
    b += "</div>";
    return _send_page("Setup", b);
  }

  b  = "<div class=card>";
  b += "<h2>Device</h2>";
  b += "<div class=row><span class=lbl>atSign</span><span class=val id=at>";
  b += atsign; b += "</span></div>";
  b += "<div class=row><span class=lbl>Device</span><span class=val>";
  b += device; b += "</span></div>";
  b += "<div class=row><span class=lbl>IP</span><span class=val id=ip></span></div>";
  b += "<div class=row><span class=lbl>Uptime</span><span class=val id=up></span></div>";
  b += "<div class=row><span class=lbl>Version</span><span class=val>" POE_APP_VERSION "</span></div>";
  b += "</div>";

  b += "<div class=card><h2>Daemon</h2>";
  b += "<div class=row><span class=lbl>State</span>"
       "<span class=val><span class='badge dim' id=state>&#8230;</span></span></div>";
  b += "<div class=row><span class=lbl>Tunnels (total)</span><span class=val id=tun>&#8230;</span></div>";
  b += "<div class=row><span class=lbl>Pings (total)</span><span class=val id=ping>&#8230;</span></div>";
  b += "<div class=row><span class=lbl>Active relays</span><span class=val id=rel>&#8230;</span></div>";
  b += "<div class=row><span class=lbl>Throughput &#8595;</span><span class=val id=tin>&#8230;</span></div>";
  b += "<div class=row><span class=lbl>Throughput &#8593;</span><span class=val id=tout>&#8230;</span></div>";
  b += "<div class=row><span class=lbl>Relay CPU</span><span class=val id=cpu>&#8230;</span></div>";
  b += "</div>";

  b += "<div class=btns>";
  b += "<a class='btn sc' href='/settings'>Rules</a>";
  b += "<a class='btn sc' href='/config'>Config</a>";
#ifdef NOPORTS_POE_P4
  b += "<button class='btn sc' id=idbtn onclick=identify()>Identify</button>";
#endif
  b += "<button class='btn dr' onclick=\"if(confirm('Reset device?'))fetch('/api/reset',{method:'POST'})"
       ".then(()=>location.reload())\">Reset</button>";
  b += "</div>";

  // Auto-refresh JS
  b += "<script>"
       "function fmt(n){if(n<1024)return n+'B';if(n<1048576)return(n/1024).toFixed(1)+'KB';"
       "return(n/1048576).toFixed(2)+'MB'}"
       "function upd(){fetch('/api/status').then(r=>r.json()).then(d=>{"
       "var s=document.getElementById('state');"
       "s.textContent=d.state||'?';"
       "s.className='badge '+(d.state==='running'?'ok':d.state==='error'?'err':'dim');"
       "document.getElementById('up').textContent=d.uptime||'';"
       "document.getElementById('ip').textContent=d.ip||'';"
       "document.getElementById('tun').textContent=d.tunnels||0;"
       "document.getElementById('ping').textContent=d.pings||0;"
       "document.getElementById('rel').textContent=(d.active_relays||0)+'/'+(d.pcb_max||5);"
       "document.getElementById('tin').textContent=fmt(d.bytes_in||0)+'/s';"
       "document.getElementById('tout').textContent=fmt(d.bytes_out||0)+'/s';"
       "document.getElementById('cpu').textContent=(d.relay_cpu||0)+'%';"
       "}).catch(()=>{})}"
       "upd();setInterval(upd,5000);"
#ifdef NOPORTS_POE_P4
       "var _idTimer=null;"
       "function identify(){"
       "var btn=document.getElementById('idbtn');"
       "fetch('/api/identify',{method:'POST'}).then(r=>r.json()).then(d=>{"
       "if(!d.ok)return;"
       "var secs=d.seconds;"
       "btn.disabled=true;"
       "if(_idTimer)clearInterval(_idTimer);"
       "_idTimer=setInterval(function(){"
       "secs--;btn.textContent='Identify ('+secs+'s)';"
       "if(secs<=0){clearInterval(_idTimer);btn.disabled=false;btn.textContent='Identify';}"
       "},1000);"
       "})}"
#endif
       "</script>";

  _send_page("Dashboard", b);
}

// ─── First-run setup (/setup  +  /api/setup) ─────────────────────────────

static void _handle_setup_get() {
  String b;
  b.reserve(2048);
  b  = "<div class=card>";
  b += "<h1>Device Setup</h1>";
  b += "<p class=sub>Enter your atSign credentials to enrol this device on the NoPorts network.</p>";
  b += "<label>atSign <span style='color:#E84040'>*</span>";
  b += "<input id=at name=at placeholder='@mydevice' autocomplete=off></label>";
  b += "<label>Device name <span style='color:#E84040'>*</span>";
  b += "<input id=dev name=dev placeholder='esp32_poe' autocomplete=off></label>";
  b += "<label>Manager atSign(s) <span style='color:#E84040'>*</span>";
  b += "<input id=mgrs placeholder='@manager1,@manager2'></label>";
  b += "<p class=hint>Comma-separated list of atSigns allowed to open tunnels.</p>";
  b += "<label>PermitOpen rules <span style='color:#E84040'>*</span>";
  b += "<input id=po placeholder='localhost:22,localhost:2222'></label>";
  b += "<p class=hint>host:port pairs this device will relay. Use *:0 to allow all.</p>";
  b += "<div id=msg></div>";
  b += "<div class=btns><button class='btn pr' onclick=save()>Save &amp; Enrol</button></div>";
  b += "</div>";

  b += "<script>"
       "function save(){"
       "var at=document.getElementById('at').value.trim(),"
       "dev=document.getElementById('dev').value.trim(),"
       "mgrs=document.getElementById('mgrs').value.trim(),"
       "po=document.getElementById('po').value.trim();"
       "if(!at||!dev||!mgrs||!po){"
       "document.getElementById('msg').innerHTML='<div class=\"msg err\">All fields are required.</div>';"
       "return;}"
       "fetch('/api/setup',{method:'POST',"
       "headers:{'Content-Type':'application/json'},"
       "body:JSON.stringify({at:at,device:dev,managers:mgrs,permitopen:po})})"
       ".then(r=>r.json()).then(d=>{"
       "if(d.ok)location.href='/enroll';"
       "else document.getElementById('msg').innerHTML='<div class=\"msg err\">'+d.error+'</div>';"
       "}).catch(e=>{"
       "document.getElementById('msg').innerHTML='<div class=\"msg err\">'+e+'</div>';"
       "});}"
       "</script>";

  _send_page("Setup", b);
}

static void _handle_setup_post() {
  if (!_srv->hasArg("plain")) { return _send_json(400, "{\"ok\":false,\"error\":\"No body\"}"); }
  String body = _srv->arg("plain");

  // Minimal JSON parse (no cJSON dependency in web layer)
  auto extract = [&](const char *key) -> String {
    String k = "\""; k += key; k += "\":\"";
    int p = body.indexOf(k);
    if (p < 0) return "";
    p += k.length();
    int e = body.indexOf('"', p);
    return e < 0 ? "" : body.substring(p, e);
  };

  String at   = extract("at");
  String dev  = extract("device");
  String mgrs = extract("managers");
  String po   = extract("permitopen");

  if (at.isEmpty() || dev.isEmpty() || mgrs.isEmpty() || po.isEmpty()) {
    return _send_json(400, "{\"ok\":false,\"error\":\"Missing fields\"}");
  }

  nvs_save(NVS_KEY_ATSIGN,    at.c_str());
  nvs_save(NVS_KEY_DEVICE,    dev.c_str());
  nvs_save(NVS_KEY_MANAGERS,  mgrs.c_str());
  nvs_save(NVS_KEY_MANAGER,   mgrs.c_str());  // legacy key
  nvs_save(NVS_KEY_PERMITOPEN, po.c_str());
  nvs_save(NVS_KEY_RULES_MODE, "0");           // managers mode

  Serial.printf("[web] Setup saved: %s / %s\n", at.c_str(), dev.c_str());
  _send_json(200, "{\"ok\":true}");
}

// ─── Enrollment (/enroll  +  /api/enroll  +  /api/enroll-status) ─────────

static const char *ROOT_DOMAIN      = "root.atsign.org";
static const char *ENROLL_APP_NAME  = "noports";
static const char *ENROLL_NS        = "sshnp:rw,sshrvd:rw";

static void _handle_enroll_get() {
  String atsign = nvs_load(NVS_KEY_ATSIGN);
  String b;
  b.reserve(2048);
  b  = "<div class=card>";
  b += "<h1>Enrol Device</h1>";
  b += "<p class=sub>Open your atSign app, tap the device &rarr; OTP button, and enter the code below.</p>";
  b += "<div class=row><span class=lbl>atSign</span><span class=val>"; b += atsign; b += "</span></div>";
  b += "<label>One-Time Passcode (OTP) <span style='color:#E84040'>*</span>";
  b += "<input id=otp placeholder='abc123' autocomplete=off maxlength=30></label>";
  b += "<div id=msg></div><div id=prog class=hide>";
  b += "<div class='msg inf' id=ptext>Connecting&#8230;</div>";
  b += "<p style='color:#8B9BB4;font-size:.8em;margin-top:8px'>"
       "Approval may take up to 5 minutes &mdash; waiting for your atSign app.</p>";
  b += "</div>";
  b += "<div class=btns id=btn_row>";
  b += "<button class='btn pr' id=enroll_btn onclick=doEnroll()>Enrol</button>";
  b += "</div></div>";

  b += "<script>"
       "var polling=false;"
       "function doEnroll(){"
       "var otp=document.getElementById('otp').value.trim();"
       "if(!otp){document.getElementById('msg').innerHTML='<div class=\"msg err\">Enter OTP.</div>';return;}"
       "document.getElementById('enroll_btn').disabled=true;"
       "document.getElementById('prog').classList.remove('hide');"
       "document.getElementById('msg').innerHTML='';"
       "fetch('/api/enroll',{method:'POST',"
       "headers:{'Content-Type':'application/json'},"
       "body:JSON.stringify({otp:otp})})"
       ".then(r=>r.json()).then(d=>{"
       "if(d.ok){polling=true;poll();}"
       "else{document.getElementById('msg').innerHTML='<div class=\"msg err\">'+d.error+'</div>';}"
       "}).catch(e=>{"
       "document.getElementById('msg').innerHTML='<div class=\"msg err\">'+e+'</div>';"
       "});}"
       "function poll(){"
       "if(!polling)return;"
       "fetch('/api/enroll-status').then(r=>r.json()).then(d=>{"
       "document.getElementById('ptext').textContent=d.message||'...';"
       "if(d.state==='ok'){polling=false;location.href='/';}"
       "else if(d.state==='fail'){"
       "polling=false;"
       "document.getElementById('prog').classList.add('hide');"
       "document.getElementById('enroll_btn').disabled=false;"
       "document.getElementById('msg').innerHTML='<div class=\"msg err\">'+d.message+'</div>';}"
       "else setTimeout(poll,2000);"
       "}).catch(()=>setTimeout(poll,3000));}"
       "</script>";

  _send_page("Enrol", b);
}

struct EnrollTaskArgs {
  char          atsign[64];
  char          device[64];
  char          otp[32];
  EnrollStatus *enroll;  // pointer back to shared status struct
};

static void _enroll_task(void *param) {
  EnrollTaskArgs *a = (EnrollTaskArgs *)param;
  EnrollStatus   *e = a->enroll;

  Serial.printf("[enroll] atsign=%s device=%s\n", a->atsign, a->device);

  if (!LittleFS.begin(true)) {
    strlcpy(e->message, "LittleFS mount failed", sizeof(e->message));
    e->phase = ENROLL_FAIL;
    free(a); vTaskDelete(nullptr); return;
  }
  if (LittleFS.exists(ATKEYS_PATH)) LittleFS.remove(ATKEYS_PATH);

  int ret = atauth_enroll_command(
    a->atsign, ROOT_DOMAIN, ATKEYS_PATH_VFS,
    a->otp, ENROLL_APP_NAME, a->device, ENROLL_NS, nullptr
  );

  if (ret == 0) {
    nvs_set_configured(true);
    strlcpy(e->message, "Enrolled successfully!", sizeof(e->message));
    e->phase = ENROLL_OK;
    Serial.println("[enroll] SUCCESS");
  } else {
    char msg[64];
    snprintf(msg, sizeof(msg), "Enrollment failed (err=%d)", ret);
    strlcpy(e->message, msg, sizeof(e->message));
    e->phase = ENROLL_FAIL;
    Serial.printf("[enroll] FAILED err=%d\n", ret);
  }
  free(a);
  vTaskDelete(nullptr);
}

static void _handle_enroll_post() {
  if (!_srv->hasArg("plain")) return _send_json(400, "{\"ok\":false,\"error\":\"No body\"}");

  String body = _srv->arg("plain");
  auto extract = [&](const char *key) -> String {
    String k = "\""; k += key; k += "\":\"";
    int p = body.indexOf(k);
    if (p < 0) return "";
    p += k.length();
    int e = body.indexOf('"', p);
    return e < 0 ? "" : body.substring(p, e);
  };

  String otp = extract("otp");
  if (otp.isEmpty()) return _send_json(400, "{\"ok\":false,\"error\":\"No OTP\"}");
  if (_enroll->phase != ENROLL_IDLE) return _send_json(409, "{\"ok\":false,\"error\":\"Already enrolled or running\"}");

  _enroll->phase = ENROLL_RUNNING;
  _enroll->started_ms = millis();
  strlcpy(_enroll->message, "Connecting to atServer...", sizeof(_enroll->message));

  EnrollTaskArgs *args = (EnrollTaskArgs *)malloc(sizeof(EnrollTaskArgs));
  if (!args) {
    _enroll->phase = ENROLL_FAIL;
    strlcpy(_enroll->message, "Out of memory", sizeof(_enroll->message));
    return _send_json(500, "{\"ok\":false,\"error\":\"OOM\"}");
  }

  strlcpy(args->atsign, nvs_load(NVS_KEY_ATSIGN).c_str(), sizeof(args->atsign));
  strlcpy(args->device, nvs_load(NVS_KEY_DEVICE).c_str(),  sizeof(args->device));
  strlcpy(args->otp,    otp.c_str(),                        sizeof(args->otp));
  args->enroll = _enroll;

  xTaskCreatePinnedToCore(_enroll_task, "enroll", 32768, args, 5, nullptr, 1);
  _send_json(200, "{\"ok\":true}");
}

static void _handle_enroll_status() {
  String j = "{\"state\":\"";
  switch (_enroll->phase) {
    case ENROLL_RUNNING: j += "running"; break;
    case ENROLL_OK:      j += "ok";      break;
    case ENROLL_FAIL:    j += "fail";    break;
    default:             j += "idle";    break;
  }
  j += "\",\"message\":\""; j += _enroll->message;
  j += "\",\"elapsed_s\":"; j += (millis() - _enroll->started_ms) / 1000;
  j += "}";
  _send_json(200, j);
}

// ─── Settings (/settings  +  /api/settings) ──────────────────────────────

static void _handle_settings_get() {
  String mode    = nvs_load(NVS_KEY_RULES_MODE);
  String mgrs    = nvs_load(NVS_KEY_MANAGERS);
  if (mgrs.isEmpty()) mgrs = nvs_load(NVS_KEY_MANAGER);
  String po      = nvs_load(NVS_KEY_PERMITOPEN);
  String pol_at  = nvs_load(NVS_KEY_POLICY_AT);

  String b;
  b.reserve(2048);
  b  = "<div class=card>";
  b += "<h1>Rules &amp; Managers</h1>";
  b += "<p class=sub>Control who can open tunnels through this device.</p>";

  b += "<label>Authorization mode";
  b += "<select id=mode onchange=modeChange()>";
  b += (mode == "1") ? "<option value=0>Managers list</option><option value=1 selected>Policy atSign</option>"
                     : "<option value=0 selected>Managers list</option><option value=1>Policy atSign</option>";
  b += "</select></label>";

  b += "<div id=mgr_block>";
  b += "<label>Manager atSign(s)<textarea id=mgrs rows=3>"; b += mgrs; b += "</textarea></label>";
  b += "<p class=hint>One per line or comma-separated. These atSigns can open tunnels.</p>";
  b += "<label>PermitOpen rules<textarea id=po rows=3>"; b += po; b += "</textarea></label>";
  b += "<p class=hint>host:port per line or comma-separated. Use *:0 to allow all.</p>";
  b += "</div>";

  b += "<div id=pol_block class=";
  b += (mode == "1") ? "''" : "hide";
  b += ">";
  b += "<label>Policy atSign<input id=pol_at placeholder='@mypolicysvc' value='"; b += pol_at; b += "'></label>";
  b += "<p class=hint>This atSign service handles authorization via RPC.</p>";
  b += "</div>";

  b += "<div id=msg></div>";
  b += "<div class=btns>"
       "<button class='btn pr' onclick=save()>Save</button>"
       "<a class='btn sc' href='/'>Cancel</a></div>";
  b += "</div>";

  b += "<script>"
       "function modeChange(){"
       "var m=document.getElementById('mode').value;"
       "document.getElementById('mgr_block').className=m==='1'?'hide':'';"
       "document.getElementById('pol_block').className=m==='0'?'hide':'';}"
       "function save(){"
       "var mode=document.getElementById('mode').value,"
       "mgrs=document.getElementById('mgrs').value.replace(/\\n/g,','),"
       "po=document.getElementById('po').value.replace(/\\n/g,','),"
       "pol=document.getElementById('pol_at').value.trim();"
       "if(mode==='0'){var m=mgrs.trim();if(!m||m.indexOf('@')<0){"
       "document.getElementById('msg').innerHTML='<div class=\"msg err\">At least one manager atSign (starting with @) is required</div>';return;}}"
       "fetch('/api/settings',{method:'POST',"
       "headers:{'Content-Type':'application/json'},"
       "body:JSON.stringify({mode:mode,managers:mgrs,permitopen:po,policy_at:pol})})"
       ".then(r=>r.json()).then(d=>{"
       "if(d.ok){"
       "document.getElementById('msg').innerHTML='<div class=\"msg ok\">Saved. Restarting daemon&#8230;</div>';"
       "setTimeout(()=>location.href='/',3000);}"
       "else{document.getElementById('msg').innerHTML='<div class=\"msg err\">'+d.error+'</div>';}"
       "});}"
       "</script>";

  _send_page("Settings", b);
}

static void _handle_settings_post() {
  if (!_srv->hasArg("plain")) return _send_json(400, "{\"ok\":false,\"error\":\"No body\"}");
  String body = _srv->arg("plain");

  auto extract = [&](const char *key) -> String {
    String k = "\""; k += key; k += "\":\"";
    int p = body.indexOf(k);
    if (p < 0) return "";
    p += k.length();
    int e = body.indexOf('"', p);
    return e < 0 ? "" : body.substring(p, e);
  };

  String mode = extract("mode");
  String mgrs = extract("managers");
  String po   = extract("permitopen");
  String pol  = extract("policy_at");

  if (mode != "1") {
    String m = mgrs; m.trim();
    if (m.isEmpty() || m.indexOf('@') < 0) {
      return _send_json(400, "{\"ok\":false,\"error\":\"At least one manager atSign (starting with @) is required\"}");
    }
  }

  nvs_save(NVS_KEY_RULES_MODE, mode.c_str());
  if (mode == "1") {
    nvs_save(NVS_KEY_POLICY_AT, pol.c_str());
  } else {
    nvs_save(NVS_KEY_MANAGERS,  mgrs.c_str());
    nvs_save(NVS_KEY_MANAGER,   mgrs.c_str());
    nvs_save(NVS_KEY_PERMITOPEN, po.c_str());
  }

  Serial.println("[web] Settings saved — daemon restart deferred to loop()");
  _send_json(200, "{\"ok\":true}");
  _restart_pending = true;  // handled by loop() after this response is sent
}

// ─── Config (/config  +  /api/config) ────────────────────────────────────

static void _handle_config_get() {
  String ka  = nvs_load(NVS_KEY_WORKER_KEEPALIVE);
  String mrs = nvs_load(NVS_KEY_MAX_RELAYS);
  int ka_val  = ka.isEmpty()  ? 4 : constrain(ka.toInt(),  0, 15);
  int mrs_val = mrs.isEmpty() ? 5 : constrain(mrs.toInt(), 1, 8);
  bool wl = _localhost_only;

  String b;
  b.reserve(2048);
  b  = "<div class=card>";
  b += "<h1>Advanced Config</h1>";
  b += "<p class=sub>Tune performance parameters. Changes take effect immediately.</p>";

  b += "<label>Worker keep-alive (minutes, 0 = off)";
  b += "<input type=number id=ka min=0 max=15 value="; b += ka_val; b += "></label>";
  b += "<p class=hint>Heartbeat to keep atServer TLS session alive. 4 min recommended.</p>";

  b += "<label>Max concurrent relay sub-connections (1&#8211;8)";
  b += "<input type=number id=mrs min=1 max=8 value="; b += mrs_val; b += "></label>";
  b += "<p class=hint>Higher values allow more parallel SSH sessions per tunnel.</p>";

  b += "<label style='display:flex;align-items:center;gap:8px;margin-top:14px'>"
       "<input type=checkbox id=wl style='width:auto'";
  if (wl) b += " checked";
  b += "> Restrict web UI to localhost only (NoPorts access only)</label>";
  b += "<p class=hint style='color:#F06000'>&#9888; When enabled, this page is only reachable "
       "via a NoPorts tunnel &mdash; direct LAN access will return 403.</p>";

#ifdef NOPORTS_POE_P4
  {
    String lm = nvs_load(NVS_KEY_LED_MODE);
    int lm_val = lm.isEmpty() ? 2 : constrain(lm.toInt(), 0, 3);
    b += "<label>LED indicator";
    b += "<select id=led>";
    const char *opts[] = {"Off (Stealth)", "Heartbeat", "Status", "Full"};
    for (int i = 0; i < 4; i++) {
      b += "<option value="; b += i;
      if (i == lm_val) b += " selected";
      b += ">"; b += opts[i]; b += "</option>";
    }
    b += "</select></label>";
    b += "<p class=hint>"
         "Off: always dark. "
         "Heartbeat: single blink = OK, patterns for problems. "
         "Status: colour shows state (blue=no net, amber=unconfigured, green=running, red=error). "
         "Full: status + white flash on each tunnel.</p>";
  }
#endif

  b += "<div id=msg></div>";
  b += "<div class=btns>"
       "<button class='btn pr' onclick=save()>Save</button>"
       "<a class='btn sc' href='/'>Cancel</a></div>";
  b += "</div>";

  b += "<script>"
       "function save(){"
       "var ka=document.getElementById('ka').value,"
       "mrs=document.getElementById('mrs').value,"
       "wl=document.getElementById('wl').checked,"
       "led=document.getElementById('led')?document.getElementById('led').value:null;"
       "var body={keepalive:ka,max_relays:mrs,web_local:wl};"
       "if(led!==null)body.led_mode=led;"
       "fetch('/api/config',{method:'POST',"
       "headers:{'Content-Type':'application/json'},"
       "body:JSON.stringify(body)})"
       ".then(r=>r.json()).then(d=>{"
       "if(d.ok){"
       "document.getElementById('msg').innerHTML='<div class=\"msg ok\">Saved.</div>';"
       "setTimeout(()=>location.href='/',2000);}"
       "else document.getElementById('msg').innerHTML='<div class=\"msg err\">'+d.error+'</div>';"
       "});}"
       "</script>";

  _send_page("Config", b);
}

static void _handle_config_post() {
  if (!_srv->hasArg("plain")) return _send_json(400, "{\"ok\":false,\"error\":\"No body\"}");
  String body = _srv->arg("plain");

  auto extract = [&](const char *key) -> String {
    String k = "\""; k += key; k += "\":";
    int p = body.indexOf(k);
    if (p < 0) return "";
    p += k.length();
    // skip optional quote
    bool quoted = (body[p] == '"');
    if (quoted) p++;
    int e = p;
    while (e < (int)body.length() && body[e] != ',' && body[e] != '}' && body[e] != '"') e++;
    return body.substring(p, e);
  };

  String ka  = extract("keepalive");
  String mrs = extract("max_relays");
  String wl  = extract("web_local");
  String lm  = extract("led_mode");

  if (!ka.isEmpty())  nvs_save(NVS_KEY_WORKER_KEEPALIVE, ka.c_str());
  if (!mrs.isEmpty()) nvs_save(NVS_KEY_MAX_RELAYS, mrs.c_str());
  bool rebind_needed = false;
  bool new_local = _localhost_only;
  if (!wl.isEmpty()) {
    new_local = (wl == "true" || wl == "1");
    if (new_local != _localhost_only) {
      if (new_local && !(_running && *_running)) {
        return _send_json(400, "{\"ok\":false,\"error\":\"Cannot restrict to localhost: NoPorts daemon must be running first\"}");
      }
      nvs_save(NVS_KEY_WEB_LOCAL, new_local ? "1" : "0");
      rebind_needed = true;
    }
  }

  // Apply daemon tunables immediately
  if (_daemon && _running && *_running) {
    if (!ka.isEmpty()) {
      uint32_t ms = (uint32_t)constrain(ka.toInt(), 0, 15) * 60000UL;
      _daemon->setWorkerKeepaliveMs(ms);
    }
    if (!mrs.isEmpty()) {
      _daemon->setMaxRelays((uint8_t)constrain(mrs.toInt(), 1, 8));
    }
  }

#ifdef NOPORTS_POE_P4
  if (!lm.isEmpty()) {
    nvs_save(NVS_KEY_LED_MODE, lm.c_str());
    led_set_mode((LedMode)constrain(lm.toInt(), 0, 3));
  }
#endif

  Serial.printf("[web] Config saved: ka=%s mrs=%s web_local=%s led=%s\n",
                ka.c_str(), mrs.c_str(), wl.c_str(), lm.c_str());
  _send_json(200, "{\"ok\":true}");
  // Rebind AFTER the response is sent so the current request completes cleanly.
  if (rebind_needed) _rebind(new_local);
}

// ─── Identify (/api/identify) ─────────────────────────────────────────────

#ifdef NOPORTS_POE_P4
static void _handle_identify() {
  led_identify(15000);
  Serial.println("[web] Identify: 15 s LED cycle started");
  _send_json(200, "{\"ok\":true,\"seconds\":15}");
}
#endif

// ─── Factory reset (/api/reset) ───────────────────────────────────────────

static void _handle_reset() {
  Serial.println("[web] Factory reset requested");
  _send_json(200, "{\"ok\":true,\"message\":\"Rebooting...\"}");

  if (_running && *_running && _daemon) {
    _daemon->stop();
    *_running = false;
  }

  if (LittleFS.begin(false)) {
    if (LittleFS.exists(ATKEYS_PATH)) LittleFS.remove(ATKEYS_PATH);
  }

  nvs_save(NVS_KEY_ATSIGN,    "");
  nvs_save(NVS_KEY_DEVICE,    "");
  nvs_save(NVS_KEY_MANAGERS,  "");
  nvs_save(NVS_KEY_MANAGER,   "");
  nvs_save(NVS_KEY_PERMITOPEN,"");
  nvs_set_configured(false);

  delay(500);
  ESP.restart();
}

// ─── 404 ──────────────────────────────────────────────────────────────────

static void _handle_not_found() {
  _srv->send(404, "text/plain", "Not found");
}

// ─── Internal helpers ─────────────────────────────────────────────────────

static void _register_routes() {
  _srv->on("/",                   HTTP_GET,  _handle_dashboard);
  _srv->on("/setup",              HTTP_GET,  _handle_setup_get);
  _srv->on("/enroll",             HTTP_GET,  _handle_enroll_get);
  _srv->on("/settings",           HTTP_GET,  _handle_settings_get);
  _srv->on("/config",             HTTP_GET,  _handle_config_get);
  _srv->on("/api/status",         HTTP_GET,  _handle_status);
  _srv->on("/api/enroll-status",  HTTP_GET,  _handle_enroll_status);
  _srv->on("/api/setup",          HTTP_POST, _handle_setup_post);
  _srv->on("/api/enroll",         HTTP_POST, _handle_enroll_post);
  _srv->on("/api/settings",       HTTP_POST, _handle_settings_post);
  _srv->on("/api/config",         HTTP_POST, _handle_config_post);
  _srv->on("/api/reset",          HTTP_POST, _handle_reset);
#ifdef NOPORTS_POE_P4
  _srv->on("/api/identify",       HTTP_POST, _handle_identify);
#endif
  _srv->onNotFound(_handle_not_found);
}

// Stop, destroy and recreate the server socket bound to the right address,
// then re-register all routes and start listening.
static void _rebind(bool local) {
  if (_srv) {
    _srv->stop();
    delete _srv;
    _srv = nullptr;
  }
  _localhost_only = local;
  IPAddress addr = local ? IPAddress(127, 0, 0, 1) : IPAddress(0, 0, 0, 0);
  _srv = new WebServer(addr, 80);
  _register_routes();
  _srv->begin();
  Serial.printf("[web] Rebound to %s:80\n", local ? "127.0.0.1" : "0.0.0.0");
}

// ─── Public ───────────────────────────────────────────────────────────────

void web_server_begin(NoPortsDaemon *daemon,
                      bool          *running,
                      DaemonStats   *stats,
                      EnrollStatus  *enroll,
                      void        (*restart_cb)()) {
  _daemon     = daemon;
  _running    = running;
  _stats      = stats;
  _enroll     = enroll;
  _restart_cb = restart_cb;
  _start_ms   = millis();

  _enroll->phase      = ENROLL_IDLE;
  _enroll->message[0] = '\0';

  _localhost_only = (nvs_load(NVS_KEY_WEB_LOCAL) == "1");
  // Safety: localhost-only with no daemon configured = permanent lockout. Fall back.
  if (_localhost_only && !nvs_is_configured()) {
    _localhost_only = false;
    Serial.println("[web] web_local=1 but not configured — binding to 0.0.0.0 for safety");
  }
  IPAddress addr = _localhost_only ? IPAddress(127, 0, 0, 1) : IPAddress(0, 0, 0, 0);
  _srv = new WebServer(addr, 80);
  _register_routes();
  _srv->begin();
  Serial.printf("[web] HTTP server started on %s:80\n",
                _localhost_only ? "127.0.0.1" : "0.0.0.0");
}

void web_server_handle() {
  _srv->handleClient();
}

bool web_server_restart_pending() {
  return _restart_pending;
}

void web_server_clear_restart() {
  _restart_pending = false;
}

String web_server_ip() {
#ifdef NOPORTS_TEST_WIFI_AP
  return WiFi.softAPIP().toString();
#elif defined(NOPORTS_POE_P4)
  return ETH.localIP().toString();
#else
  return "0.0.0.0";
#endif
}

bool web_server_is_local() {
  return _localhost_only;
}
