/**
 * @file noports_relay.cpp
 * @brief TCP socket relay implementation for ESP32
 *
 * This replaces the srv (socket relay valve) from the C sshnpd.
 * Instead of fork() + pthreads, we use FreeRTOS tasks.
 * Instead of mbedtls_net, we use ESP32 WiFiClient.
 *
 * The relay bridges:
 *   RVD (rendezvous host:port) <--> Local service (host:port)
 *
 * With optional AES-CTR end-to-end encryption of the traffic.
 */

#include "noports/noports_relay.h"
#include "noports/noports_log.h"
#include <WiFiClient.h>
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <lwip/sockets.h>   // recv, MSG_PEEK, MSG_DONTWAIT
#include <errno.h>

#define TAG "noports_relay"

// Buffer size for relay forwarding
// 4 KB lets us read multiple full TCP segments per iteration (MSS ~1436).
// Both buf and crypt_buf are heap-allocated so this doesn't affect stack.
// Smaller = more heap for TLS reconnects under load (each saves 2×delta).
#define RELAY_BUF_SIZE 4096

// Buffer size for early data captured during Phase 2 polling
#define EARLY_BUF_SIZE 256

// Stack size for relay FreeRTOS task
// With all large buffers (earlyA/B, cmsgA/B, buf, crypt_buf) on the heap,
// actual stack usage is ~1200 bytes. 6KB provides comfortable headroom.
#define RELAY_TASK_STACK_SIZE 6144

// Maximum concurrent sub-connections per relay (multi mode).
// Each sub uses 2 sockets (rvd + local) + optional AES state (~1KB).
//
// === Logical PCB pool separation ===
// ESP32 Arduino lwIP has a single global pool of 10 TCP PCBs.
// We partition it logically:
//   ATSERVER pool (reserved):  monitor(1) + worker(1) + spare(1) = 3
//   RELAY pool (tracked):      ctrl(1) + N×2(subs) ≤ 7
// A runtime counter (_relay_pcb_count) tracks every socket the relay
// opens/closes.  New subs are refused if they would exceed the relay
// budget, guaranteeing the atServer TLS connections can never be
// starved by relay traffic.
#define LWIP_TOTAL_PCBS       10
#define RESERVED_ATSERVER_PCBS 3   // monitor + worker + 1 spare for reconnect
#define MAX_RELAY_PCBS        (LWIP_TOTAL_PCBS - RESERVED_ATSERVER_PCBS)  // 7
#define MAX_RELAY_SUBS        4   // sub slots; PCB limit caps active to 3

// Runtime counter for relay-owned TCP PCBs (ctrl + sub sockets).
// Incremented on every successful connect(), decremented on every stop().
static volatile int _relay_pcb_count = 0;

// Minimum free heap required before opening a new sub-connection.
// TLS handshakes (monitor/worker reconnect) need ~20-25KB of heap.
// If heap is below this threshold, we evict or refuse new subs to
// protect the atServer connections.
#define MIN_HEAP_FOR_SUB 35000

// AES-CTR encryption state
struct aes_ctr_state {
  mbedtls_aes_context ctx;
  unsigned char nonce_counter[16];
  unsigned char stream_block[16];
  size_t nc_off;
};

// Per-sub stall timeout: absolute safety net for connections where the
// peer vanished without sending FIN/RST (e.g. network partition).
// Normal cleanup uses _peer_closed() (immediate) and slot eviction
// (evicts least-recently-active sub when a new connect: arrives and
// all slots are full).  This is just the backstop.
#define SUB_STALL_TIMEOUT_MS 900000UL  // 15 minutes

// Minimum idle time (ms) before a sub can be evicted for a new request.
// Protects mid-transfer HTTP responses from being killed.  Subs that
// finished their response will be detected by _peer_closed() and cleaned
// up immediately; keep-alive subs become evictable after this period.
// Without this, a browser loading a complex page creates a vicious cycle:
// new HTTP request → evict active sub → that request fails → browser
// retries → more evictions → nothing completes.
#define SUB_EVICTION_GRACE_MS 2000UL

// When all sub slots are busy, incoming connect: messages are queued
// instead of dropped.  When a slot frees up (peer_closed / write fail),
// the oldest queued connect is processed immediately.  This prevents
// browser HTTP requests from timing out while waiting for a sub-channel
// that the ESP32 never connected to.
#define CONNECT_QUEUE_SIZE    6   // enough for typical browser parallelism
#define CONNECT_MSG_MAX     384   // max connect: message length

struct PendingConnect {
  char msg[CONNECT_MSG_MAX];
  bool pending;
};

// NOTE: We do NOT use WiFiClient::connected() for disconnect detection.
// On ESP32/lwIP, connected() calls recv(fd, dummy, 0, MSG_DONTWAIT)
// which erroneously returns ENOTCONN on idle sockets — killing
// perfectly healthy connections.  Instead we use _peer_closed() which
// calls recv(fd, tmp, 1, MSG_PEEK|MSG_DONTWAIT) — standard POSIX
// behavior that reliably returns 0 on FIN and EAGAIN when alive.
// Detection layers:
//   - _peer_closed():  detects FIN/RST immediately after data drains
//   - _write_all():    catches dead sockets on write failure
//   - Slot eviction:   evicts oldest-idle sub when slots full
//   - SUB_STALL_TIMEOUT_MS: absolute safety net (15 min)
//   - ctrl_lost + DRAIN_TIMEOUT_MS: catches control channel drops

// Sub-connection in a multi-session relay
struct RelaySub {
  WiFiClient rvd;       // data connection to SRVD
  WiFiClient local;     // connection to local service
  aes_ctr_state *enc;   // AES-CTR encrypter (local->SRVD, D2C direction)
  aes_ctr_state *dec;   // AES-CTR decrypter (SRVD->local, C2D direction)
  bool active;
  bool encrypted;
  unsigned long last_activity_ms; // millis() of last data transfer
};

// Internal: check if a WiFiClient's peer has closed the connection.
// Uses recv(MSG_PEEK|MSG_DONTWAIT) with size 1 on the raw fd.
// This is MORE reliable than WiFiClient::connected() which uses
// recv(fd, dummy, 0) and erroneously returns ENOTCONN on idle sockets.
//  - Returns true  when FIN received (peer closed) or socket error
//  - Returns false when socket is alive (data available or EAGAIN)
static bool _peer_closed(WiFiClient &client) {
  int fd = client.fd();
  if (fd < 0) return true;
  char tmp;
  int res = recv(fd, &tmp, 1, MSG_PEEK | MSG_DONTWAIT);
  if (res > 0) return false;   // data available → alive
  if (res == 0) return true;   // FIN received → closed
  // res < 0: EAGAIN/EWOULDBLOCK means alive-but-no-data
  return (errno != EAGAIN && errno != EWOULDBLOCK);
}

// Internal: create a single AES-CTR state from base64 key and IV
static aes_ctr_state *_create_aes_ctr_state(const unsigned char *key_b64,
                                              const unsigned char *iv_b64) {
  unsigned char aes_key[32];
  size_t olen;

  int res = mbedtls_base64_decode(aes_key, sizeof(aes_key), &olen,
                                  key_b64, strlen((const char *)key_b64));
  if (res != 0 || olen != 32) {
    NOPORTS_LOGE(TAG, "Failed to decode AES key (res=%d, len=%u)", res, (unsigned)olen);
    return NULL;
  }

  unsigned char iv[16];
  res = mbedtls_base64_decode(iv, sizeof(iv), &olen,
                              iv_b64, strlen((const char *)iv_b64));
  if (res != 0 || olen != 16) {
    NOPORTS_LOGE(TAG, "Failed to decode IV (res=%d, len=%u)", res, (unsigned)olen);
    return NULL;
  }

  aes_ctr_state *state = (aes_ctr_state *)calloc(1, sizeof(aes_ctr_state));
  if (!state) return NULL;

  mbedtls_aes_init(&state->ctx);
  res = mbedtls_aes_setkey_enc(&state->ctx, aes_key, 256);
  if (res != 0) {
    free(state);
    return NULL;
  }
  memcpy(state->nonce_counter, iv, 16);
  state->nc_off = 0;
  memset(state->stream_block, 0, 16);

  return state;
}

// Internal: create encrypter and decrypter from base64 key(s) and IV(s)
// If key_d2c_b64/iv_d2c_b64 are non-NULL, twin-key mode: enc uses D2C, dec uses C2D
// Otherwise, single-key mode: both enc and dec use the same key/IV
static int _create_enc_dec(const unsigned char *key_c2d_b64, const unsigned char *iv_c2d_b64,
                           const unsigned char *key_d2c_b64, const unsigned char *iv_d2c_b64,
                           aes_ctr_state **enc_out, aes_ctr_state **dec_out) {
  // Decrypter always uses C2D key (decrypts what client encrypted)
  aes_ctr_state *dec = _create_aes_ctr_state(key_c2d_b64, iv_c2d_b64);
  if (!dec) return -1;

  // Encrypter uses D2C key if available, else same C2D key
  aes_ctr_state *enc;
  if (key_d2c_b64 && iv_d2c_b64) {
    enc = _create_aes_ctr_state(key_d2c_b64, iv_d2c_b64);
    NOPORTS_LOGI(TAG, "Twin-key mode: separate keys for enc (D2C) and dec (C2D)");
  } else {
    enc = _create_aes_ctr_state(key_c2d_b64, iv_c2d_b64);
    NOPORTS_LOGI(TAG, "Single-key mode: same key for enc and dec");
  }
  if (!enc) {
    mbedtls_aes_free(&dec->ctx);
    free(dec);
    return -1;
  }

  *enc_out = enc;
  *dec_out = dec;
  return 0;
}

// Internal: write all bytes to a WiFiClient, handling partial writes.
// WiFiClient.write() may write fewer bytes than requested if the TCP
// send buffer is full. We must retry to avoid dropping data, which
// would desynchronize the AES-CTR counter on the other side.
static bool _write_all(WiFiClient *client, const uint8_t *data, size_t len) {
  size_t written = 0;
  unsigned long start = millis();
  while (written < len) {
    // Do NOT check client->connected() here — it's unreliable on ESP32
    // (see comment near SUB_STALL_TIMEOUT_MS).  write() returning 0
    // continuously will hit the 5s stall timeout below.
    size_t n = client->write(data + written, len - written);
    if (n > 0) {
      written += n;
      start = millis(); // reset timeout on progress
    } else {
      // TCP buffer full — yield briefly and retry
      if ((millis() - start) > 5000) {
        NOPORTS_LOGE(TAG, "write_all stalled for 5s, giving up (%u/%u)",
                     (unsigned)written, (unsigned)len);
        return false;
      }
      vTaskDelay(pdMS_TO_TICKS(1));
    }
  }
  return true;
}

// Internal: encrypt/decrypt in-place using AES-CTR
static int _aes_ctr_crypt(aes_ctr_state *state, size_t len,
                          const unsigned char *input, unsigned char *output) {
  return mbedtls_aes_crypt_ctr(&state->ctx, len,
                               &state->nc_off, state->nonce_counter,
                               state->stream_block, input, output);
}

// Internal: close a relay sub-connection and free its resources.
// Uses graceful FIN close (no SO_LINGER/RST).
// lwIP auto-recycles the oldest TIME_WAIT PCB when the pool is full,
// so explicit RST is unnecessary and harmful — RST causes the REMOTE
// peer (web server) to reject subsequent SYNs from the same client.
static void _close_relay_sub(RelaySub *sub, int index) {
  NOPORTS_LOGI(TAG, "Sub[%d] closing", index);
  if (sub->rvd.fd() >= 0) { sub->rvd.stop(); _relay_pcb_count--; }
  if (sub->local.fd() >= 0) { sub->local.stop(); _relay_pcb_count--; }
  if (_relay_pcb_count < 0) _relay_pcb_count = 0;  // safety clamp
  if (sub->enc) {
    mbedtls_aes_free(&sub->enc->ctx);
    free(sub->enc);
    sub->enc = NULL;
  }
  if (sub->dec) {
    mbedtls_aes_free(&sub->dec->ctx);
    free(sub->dec);
    sub->dec = NULL;
  }
  sub->active = false;
  sub->encrypted = false;
  // Reset WiFiClient objects for potential slot reuse
  sub->rvd = WiFiClient();
  sub->local = WiFiClient();
}

// Internal: recount active subs and update relay->active_sessions
static void _update_active_session_count(NoPortsRelay *relay, RelaySub *subs) {
  uint8_t count = 0;
  for (int i = 0; i < MAX_RELAY_SUBS; i++) {
    if (subs[i].active) count++;
  }
  relay->active_sessions = count;
}

// Internal: reclaim any subs whose peer has already closed.
// Called before attempting eviction so dead subs free their slots/PCBs
// without needing to evict a live connection.
static void _reclaim_dead_subs(RelaySub *subs) {
  for (int i = 0; i < MAX_RELAY_SUBS; i++) {
    if (!subs[i].active) continue;
    bool rvd_dead  = !subs[i].rvd.available()   && _peer_closed(subs[i].rvd);
    bool local_dead = !subs[i].local.available() && _peer_closed(subs[i].local);
    if (rvd_dead || local_dead) {
      NOPORTS_LOGI(TAG, "Sub[%d] reclaimed (peer already closed)", i);
      _close_relay_sub(&subs[i], i);
    }
  }
}

// Internal: find the best eviction victim among active subs.
// Only considers subs that have been idle > SUB_EVICTION_GRACE_MS.
// Returns -1 if all active subs are still transferring data.
static int _find_evictable_sub(RelaySub *subs) {
  int victim = -1;
  unsigned long oldest_activity = ULONG_MAX;
  unsigned long now = millis();
  for (int i = 0; i < MAX_RELAY_SUBS; i++) {
    if (!subs[i].active) continue;
    if ((now - subs[i].last_activity_ms) > SUB_EVICTION_GRACE_MS &&
        subs[i].last_activity_ms < oldest_activity) {
      oldest_activity = subs[i].last_activity_ms;
      victim = i;
    }
  }
  return victim;
}

// Internal: handle a "connect:..." control message in multi mode.
// Opens a new data connection to SRVD and a new connection to the local
// service, then marks the sub slot as active for bidirectional relay.
//
// Eviction strategy (three tiers):
//  1. Reclaim dead subs (peer already closed) — free cleanup
//  2. Evict subs idle > SUB_EVICTION_GRACE_MS — keep-alive waiters
//  3. Drop this connect request — protect mid-transfer connections
// This prevents the "eviction churn" cycle where browsers loading
// complex pages trigger rapid evict→create→evict chains that prevent
// any HTTP response from completing.
static int _handle_connect_msg(NoPortsRelay *relay, RelaySub *subs,
                               const char *msg) {
  // Step 1: Reclaim any subs whose peer has already closed.
  // This is free — those connections are already done.
  _reclaim_dead_subs(subs);

  // PCB budget guard: refuse if opening 2 more sockets would exceed
  // the relay pool.  This guarantees atServer PCBs are never stolen.
  if (_relay_pcb_count + 2 > MAX_RELAY_PCBS) {
    int victim = _find_evictable_sub(subs);
    if (victim >= 0) {
      unsigned long idle_ms = millis() - subs[victim].last_activity_ms;
      NOPORTS_LOGW(TAG, "Sub[%d] evicted (idle %lums, PCBs %d/%d)",
                   victim, idle_ms, _relay_pcb_count, MAX_RELAY_PCBS);
      _close_relay_sub(&subs[victim], victim);
    } else {
      NOPORTS_LOGW(TAG, "Multi: PCBs %d/%d, all subs active — dropping connect",
                   _relay_pcb_count, MAX_RELAY_PCBS);
      return -1;
    }
  }

  // Heap guard: protect atServer TLS connections.
  // If heap is too low for a TLS handshake, try to free an idle sub.
  uint32_t heap = esp_get_free_heap_size();
  if (heap < MIN_HEAP_FOR_SUB) {
    int victim = _find_evictable_sub(subs);
    if (victim >= 0) {
      NOPORTS_LOGW(TAG, "Sub[%d] evicted (heap %u < %u, idle %lums)",
                   victim, (unsigned)heap, MIN_HEAP_FOR_SUB,
                   millis() - subs[victim].last_activity_ms);
      _close_relay_sub(&subs[victim], victim);
    } else {
      NOPORTS_LOGW(TAG, "Multi: heap %u < %u, all subs active — dropping connect",
                   (unsigned)heap, MIN_HEAP_FOR_SUB);
      return -1;
    }
  }

  // Find free sub slot
  int slot = -1;
  for (int i = 0; i < MAX_RELAY_SUBS; i++) {
    if (!subs[i].active) { slot = i; break; }
  }

  // All slots full — try to evict the longest-idle sub.
  // Only evicts subs idle > SUB_EVICTION_GRACE_MS.  If all subs are
  // actively transferring, we drop this connect request.  The SRVD
  // sub-channel will timeout and the browser will retry once a slot
  // frees up naturally (via _peer_closed).
  if (slot < 0) {
    int victim = _find_evictable_sub(subs);
    if (victim >= 0) {
      unsigned long idle_ms = millis() - subs[victim].last_activity_ms;
      NOPORTS_LOGW(TAG, "Sub[%d] evicted (idle %lums) to make room", victim, idle_ms);
      _close_relay_sub(&subs[victim], victim);
      slot = victim;
    } else {
      NOPORTS_LOGW(TAG, "Multi: all %d subs active — dropping connect (heap=%u)",
                   MAX_RELAY_SUBS, (unsigned)esp_get_free_heap_size());
      return -1;
    }
  }

  if (slot < 0) {
    NOPORTS_LOGE(TAG, "Multi: no free sub slots (max %d)", MAX_RELAY_SUBS);
    return -1;
  }

  RelaySub *sub = &subs[slot];
  sub->enc = NULL;
  sub->dec = NULL;
  sub->encrypted = false;

  // Parse: "connect:key:iv[:keyD2C:ivD2C]" or "connect:no:encrypt"
  const char *data_start = msg + 8; // skip "connect:"

  if (strcmp(data_start, "no:encrypt") == 0 || *data_start == '\0') {
    NOPORTS_LOGI(TAG, "Sub[%d] plain (no e2ee)", slot);
  } else {
    // Parse colon-separated fields from a mutable copy
    char parse_buf[384];
    strncpy(parse_buf, data_start, sizeof(parse_buf) - 1);
    parse_buf[sizeof(parse_buf) - 1] = '\0';

    char *fields[4] = {NULL, NULL, NULL, NULL};
    int nfields = 0;
    char *p = parse_buf;
    fields[nfields++] = p;
    while (*p && nfields < 4) {
      if (*p == ':') {
        *p = '\0';
        fields[nfields++] = p + 1;
      }
      p++;
    }

    if (nfields < 2) {
      NOPORTS_LOGE(TAG, "Sub[%d] malformed connect (need key:iv, got %d)",
                   slot, nfields);
      return -1;
    }

    const char *key_d2c = (nfields >= 4) ? fields[2] : NULL;
    const char *iv_d2c  = (nfields >= 4) ? fields[3] : NULL;

    int rc = _create_enc_dec(
      (const unsigned char *)fields[0], (const unsigned char *)fields[1],
      (const unsigned char *)key_d2c,   (const unsigned char *)iv_d2c,
      &sub->enc, &sub->dec);
    if (rc != 0) {
      NOPORTS_LOGE(TAG, "Sub[%d] AES setup failed", slot);
      return -1;
    }
    sub->encrypted = true;
    NOPORTS_LOGI(TAG, "Sub[%d] e2ee %s", slot,
                 key_d2c ? "twin-key" : "single-key");
  }

  // Connect to SRVD (new data socket)
  sub->rvd = WiFiClient();
  if (!sub->rvd.connect(relay->config.rvd_host, relay->config.rvd_port)) {
    NOPORTS_LOGE(TAG, "Sub[%d] failed to connect to SRVD", slot);
    goto sub_fail;
  }
  _relay_pcb_count++;
  sub->rvd.setNoDelay(true);
  if (relay->config.rv_auth && relay->config.rvd_auth_string) {
    sub->rvd.print(relay->config.rvd_auth_string);
    sub->rvd.print("\n");
    sub->rvd.flush();
  }

  // Connect to local service
  sub->local = WiFiClient();
  if (!sub->local.connect(relay->config.local_host, relay->config.local_port)) {
    NOPORTS_LOGE(TAG, "Sub[%d] failed to connect local %s:%d",
                 slot, relay->config.local_host, relay->config.local_port);
    sub->rvd.stop();
    _relay_pcb_count--;  // rvd was counted
    goto sub_fail;
  }
  sub->local.setNoDelay(true);
  _relay_pcb_count++;

  sub->active = true;
  sub->last_activity_ms = millis();
  _update_active_session_count(relay, subs);
  NOPORTS_LOGI(TAG, "Sub[%d] active: SRVD <-> %s:%d (sessions=%d, pcbs=%d/%d, heap=%u)",
               slot, relay->config.local_host, relay->config.local_port,
               relay->active_sessions, _relay_pcb_count, MAX_RELAY_PCBS,
               (unsigned)esp_get_free_heap_size());
  return 0;

sub_fail:
  if (sub->enc) { mbedtls_aes_free(&sub->enc->ctx); free(sub->enc); sub->enc = NULL; }
  if (sub->dec) { mbedtls_aes_free(&sub->dec->ctx); free(sub->dec); sub->dec = NULL; }
  sub->encrypted = false;
  return -1;
}

// Internal: FreeRTOS relay task – dual-connection, poll-both architecture
//
// The NPT client opens 2 connections to SRVD (control + data).
// SRVD pairs connections FIFO. The daemon opens 2 connections too.
// We don't know which daemon connection pairs with which client connection,
// so we poll BOTH for the connect: message. Whichever receives it is the
// control channel; the other becomes the data channel for relay traffic.
// We keep the control channel alive (closing it causes SRVD port teardown).
// Inner function: runs the relay logic. Returns normally so C++ destructors
// (sockA) run. The outer wrapper calls vTaskDelete(NULL) after this returns.
static void _relay_task_inner(NoPortsRelay *relay) {
  uint8_t *buf = (uint8_t *)malloc(RELAY_BUF_SIZE);
  uint8_t *crypt_buf = NULL;

  if (!buf) {
    NOPORTS_LOGE(TAG, "Failed to allocate relay buffer");
    relay->state = RELAY_ERROR;
    return;
  }

  crypt_buf = (uint8_t *)malloc(RELAY_BUF_SIZE);
  if (!crypt_buf) {
    NOPORTS_LOGE(TAG, "Failed to allocate crypto buffer");
    free(buf);
    relay->state = RELAY_ERROR;
    return;
  }

  NOPORTS_LOGI(TAG, "Relay task started: %s:%d <-> %s:%d (free heap: %u)",
               relay->config.rvd_host, relay->config.rvd_port,
               relay->config.local_host, relay->config.local_port,
               (unsigned)esp_get_free_heap_size());

  // Declare ALL variables before any goto (C++ requirement)
  WiFiClient sockA;           // first connection to SRVD
  // sockB = relay->rvd_client  // second connection to SRVD
  WiFiClient *ctrl = NULL;     // whichever gets connect: message
  WiFiClient *data = NULL;     // the other one – used for relay
  aes_ctr_state *ctrl_dec_A = NULL;  // decrypter for sockA if it's ctrl
  aes_ctr_state *ctrl_dec_B = NULL;  // decrypter for rvd_client if it's ctrl
  aes_ctr_state *data_enc = NULL;
  aes_ctr_state *data_dec = NULL;
  bool data_encrypted = false;
  unsigned long idle_since = 0;
  const unsigned long IDLE_TIMEOUT_MS =
      (relay->config.idle_timeout_ms > 0) ? relay->config.idle_timeout_ms : 60000UL;
  unsigned long total_rvd_to_local = 0;
  unsigned long total_local_to_rvd = 0;
  unsigned long last_stats_time = 0;

  // Raw bytes consumed from each socket during Phase 2 polling.
  // The data socket may receive encrypted data before we know which socket
  // is which. We save raw bytes so we can replay them through data_dec later.
  // Heap-allocated to reduce stack pressure (prevents stack overflow).
  uint8_t *earlyA = (uint8_t *)calloc(EARLY_BUF_SIZE, 1);
  uint8_t *earlyB = (uint8_t *)calloc(EARLY_BUF_SIZE, 1);
  int earlyLenA = 0, earlyLenB = 0;

  if (!earlyA || !earlyB) {
    NOPORTS_LOGE(TAG, "Failed to allocate early buffers");
    free(buf);
    free(crypt_buf);
    if (earlyA) free(earlyA);
    if (earlyB) free(earlyB);
    relay->state = RELAY_ERROR;
    return;
  }

  // ======================================================================
  // PHASE 1: Open 2 connections to SRVD, authenticate both
  // ======================================================================
  relay->state = RELAY_CONNECTING;

  NOPORTS_LOGI(TAG, "Connecting to RVD %s:%d (sockA)",
               relay->config.rvd_host, relay->config.rvd_port);
  if (!sockA.connect(relay->config.rvd_host, relay->config.rvd_port)) {
    NOPORTS_LOGE(TAG, "Failed to connect to RVD (sockA)");
    relay->state = RELAY_ERROR;
    goto cleanup;
  }
  _relay_pcb_count++;
  sockA.setNoDelay(true);
  NOPORTS_LOGI(TAG, "Connected to RVD (sockA)");

  if (relay->config.rv_auth && relay->config.rvd_auth_string) {
    relay->state = RELAY_AUTHENTICATING;
    sockA.print(relay->config.rvd_auth_string);
    sockA.print("\n");
    sockA.flush();
    NOPORTS_LOGI(TAG, "Auth sent (sockA)");
  }

  NOPORTS_LOGI(TAG, "Connecting to RVD %s:%d (sockB)",
               relay->config.rvd_host, relay->config.rvd_port);
  if (!relay->rvd_client.connect(relay->config.rvd_host, relay->config.rvd_port)) {
    NOPORTS_LOGE(TAG, "Failed to connect to RVD (sockB)");
    relay->state = RELAY_ERROR;
    goto cleanup;
  }
  _relay_pcb_count++;
  relay->rvd_client.setNoDelay(true);
  NOPORTS_LOGI(TAG, "Connected to RVD (sockB)");

  if (relay->config.rv_auth && relay->config.rvd_auth_string) {
    relay->rvd_client.print(relay->config.rvd_auth_string);
    relay->rvd_client.print("\n");
    relay->rvd_client.flush();
    NOPORTS_LOGI(TAG, "Auth sent (sockB)");
  }

  NOPORTS_LOGI(TAG, "Both SRVD connections established");

  // Set up separate decrypters for each socket (so we can try both)
  if (relay->decrypter) {
    // We already have one decrypter (for the connect: message).
    // Create a second one from the same session keys for the other socket.
    ctrl_dec_A = (aes_ctr_state *)relay->decrypter;
    relay->decrypter = NULL;  // take ownership

    // Create duplicate for sockB from the same C2D session keys
    if (relay->config.session_aes_key && relay->config.session_iv) {
      ctrl_dec_B = _create_aes_ctr_state(relay->config.session_aes_key,
                                          relay->config.session_iv);
    }
  }

  // ======================================================================
  // PHASE 2: Poll BOTH sockets for the connect: message
  // SRVD FIFO pairing means we don't know which socket pairs with the
  // client's control socket. Read from whichever gets data first.
  // Use separate heap buffers so we don't disturb the relay buffers.
  // ======================================================================
  {
    unsigned long connect_wait_start = millis();
    const unsigned long CONNECT_TIMEOUT_MS = 30000;
    char *cmsgA = (char *)calloc(256, 1);  // connect: msg buffer for sockA
    char *cmsgB = (char *)calloc(256, 1);  // connect: msg buffer for sockB
    if (!cmsgA || !cmsgB) {
      NOPORTS_LOGE(TAG, "Failed to allocate cmsg buffers");
      if (cmsgA) free(cmsgA);
      if (cmsgB) free(cmsgB);
      relay->state = RELAY_ERROR;
      goto cleanup;
    }
    int posA = 0, posB = 0;
    bool got_connect = false;
    char *connect_msg = NULL;

    NOPORTS_LOGI(TAG, "Waiting for connect: on either socket (e2ee=%d)...",
                 ctrl_dec_A != NULL);

    while ((millis() - connect_wait_start) < CONNECT_TIMEOUT_MS && !got_connect) {
      // Check sockA
      if (sockA.connected() && sockA.available() && posA < 254) {
        if (ctrl_dec_A) {
          uint8_t raw, dec;
          if (sockA.read(&raw, 1) == 1) {
            if (earlyLenA < EARLY_BUF_SIZE) earlyA[earlyLenA++] = raw;
            _aes_ctr_crypt(ctrl_dec_A, 1, &raw, &dec);
            cmsgA[posA++] = (char)dec;
            if (dec == '\n') {
              got_connect = true;
              ctrl = &sockA;
              data = &relay->rvd_client;
              connect_msg = cmsgA;
              NOPORTS_LOGI(TAG, "connect: arrived on sockA");
            }
          }
        } else {
          uint8_t b;
          if (sockA.read(&b, 1) == 1) {
            if (earlyLenA < EARLY_BUF_SIZE) earlyA[earlyLenA++] = b;
            cmsgA[posA++] = (char)b;
            if (b == '\n') {
              got_connect = true;
              ctrl = &sockA;
              data = &relay->rvd_client;
              connect_msg = cmsgA;
              NOPORTS_LOGI(TAG, "connect: arrived on sockA (plain)");
            }
          }
        }
        if (got_connect) break;
      }

      // Check sockB (rvd_client)
      if (relay->rvd_client.connected() && relay->rvd_client.available() && posB < 254) {
        if (ctrl_dec_B) {
          uint8_t raw, dec;
          if (relay->rvd_client.read(&raw, 1) == 1) {
            if (earlyLenB < EARLY_BUF_SIZE) earlyB[earlyLenB++] = raw;
            _aes_ctr_crypt(ctrl_dec_B, 1, &raw, &dec);
            cmsgB[posB++] = (char)dec;
            if (dec == '\n') {
              got_connect = true;
              ctrl = &relay->rvd_client;
              data = &sockA;
              connect_msg = cmsgB;
              NOPORTS_LOGI(TAG, "connect: arrived on sockB");
            }
          }
        } else {
          uint8_t b;
          if (relay->rvd_client.read(&b, 1) == 1) {
            if (earlyLenB < EARLY_BUF_SIZE) earlyB[earlyLenB++] = b;
            cmsgB[posB++] = (char)b;
            if (b == '\n') {
              got_connect = true;
              ctrl = &relay->rvd_client;
              data = &sockA;
              connect_msg = cmsgB;
              NOPORTS_LOGI(TAG, "connect: arrived on sockB (plain)");
            }
          }
        }
        if (got_connect) break;
      }

      if (!sockA.connected() && !relay->rvd_client.connected()) {
        NOPORTS_LOGE(TAG, "Both SRVD sockets disconnected while waiting for connect:");
        relay->state = RELAY_ERROR;
        goto cleanup;
      }

      vTaskDelay(pdMS_TO_TICKS(20));
    }

    if (!got_connect || !connect_msg) {
      NOPORTS_LOGE(TAG, "Timed out waiting for connect: on both sockets (A=%d B=%d)",
                   posA, posB);
      relay->state = RELAY_ERROR;
      goto cleanup;
    }

    // Strip trailing newline
    int cmsg_len = (connect_msg == cmsgA) ? posA : posB;
    if (cmsg_len > 0 && connect_msg[cmsg_len - 1] == '\n')
      connect_msg[cmsg_len - 1] = '\0';
    connect_msg[cmsg_len] = '\0';

    NOPORTS_LOGI(TAG, "Received: %s", connect_msg);

    if (strncmp(connect_msg, "connect:", 8) != 0) {
      NOPORTS_LOGE(TAG, "Invalid connect message (expected 'connect:' prefix)");
      relay->state = RELAY_ERROR;
      goto cleanup;
    }

    char *key_start = connect_msg + 8;

    if (strcmp(key_start, "no:encrypt") == 0 || *key_start == '\0') {
      NOPORTS_LOGI(TAG, "No e2ee for data channel, plain relay");
      data_encrypted = false;
    } else {
      // Parse fields: connect:keyC2D:ivC2D[:keyD2C:ivD2C]\n
      // Split on colons to find all fields
      char *fields[4] = {NULL, NULL, NULL, NULL};
      int nfields = 0;
      char *p = key_start;
      fields[nfields++] = p;
      while (*p && nfields < 4) {
        if (*p == ':') {
          *p = '\0';
          fields[nfields++] = p + 1;
        }
        p++;
      }

      if (nfields < 2) {
        NOPORTS_LOGE(TAG, "Invalid connect message (need at least key:iv, got %d fields)", nfields);
        relay->state = RELAY_ERROR;
        goto cleanup;
      }

      char *key_c2d = fields[0];
      char *iv_c2d = fields[1];
      char *key_d2c = (nfields >= 4) ? fields[2] : NULL;
      char *iv_d2c = (nfields >= 4) ? fields[3] : NULL;

      NOPORTS_LOGI(TAG, "Data E2EE: keyC2D=%d iv=%d %s",
                   (int)strlen(key_c2d), (int)strlen(iv_c2d),
                   key_d2c ? "TWIN-KEY" : "single-key");

      int enc_res = _create_enc_dec((const unsigned char *)key_c2d,
                                     (const unsigned char *)iv_c2d,
                                     (const unsigned char *)key_d2c,
                                     (const unsigned char *)iv_d2c,
                                     &data_enc, &data_dec);
      if (enc_res != 0) {
        NOPORTS_LOGE(TAG, "Failed to create data channel AES-CTR state");
        relay->state = RELAY_ERROR;
        goto cleanup;
      }
      data_encrypted = true;
    }
    free(cmsgA);
    free(cmsgB);
  }

  // ======================================================================
  // PHASE 3: Bridge data socket ↔ local service
  // Keep control socket alive (SRVD tears down port if either side closes)
  // ======================================================================

  // Free control channel decrypters – no longer needed
  if (ctrl_dec_A) {
    mbedtls_aes_free(&ctrl_dec_A->ctx);
    free(ctrl_dec_A);
    ctrl_dec_A = NULL;
  }
  if (ctrl_dec_B) {
    mbedtls_aes_free(&ctrl_dec_B->ctx);
    free(ctrl_dec_B);
    ctrl_dec_B = NULL;
  }
  if (relay->encrypter) {
    mbedtls_aes_free(&((aes_ctr_state *)relay->encrypter)->ctx);
    free(relay->encrypter);
    relay->encrypter = NULL;
  }

  NOPORTS_LOGI(TAG, "Data socket: %s, control kept alive",
               (data == &sockA) ? "sockA" : "sockB");

  // Connect to local service
  NOPORTS_LOGI(TAG, "Connecting to local service %s:%d",
               relay->config.local_host, relay->config.local_port);
  if (!relay->local_client.connect(relay->config.local_host, relay->config.local_port)) {
    NOPORTS_LOGE(TAG, "Failed to connect to local service %s:%d",
                 relay->config.local_host, relay->config.local_port);
    relay->state = RELAY_ERROR;
    goto cleanup;
  }
  _relay_pcb_count++;
  NOPORTS_LOGI(TAG, "Connected to local service (pcbs=%d/%d)",
               _relay_pcb_count, MAX_RELAY_PCBS);
  relay->local_client.setNoDelay(true);

  // Replay any early bytes consumed from the data socket during Phase 2.
  // During polling, we read from both sockets not knowing which is data.
  // Those raw bytes were encrypted with the DATA CHANNEL key but we consumed
  // them from the TCP buffer. We must replay them through data_dec so the
  // AES-CTR counter stays in sync with the client.
  {
    uint8_t *early_raw = (data == &relay->rvd_client) ? earlyB : earlyA;
    int early_len = (data == &relay->rvd_client) ? earlyLenB : earlyLenA;
    if (early_len > 0) {
      NOPORTS_LOGI(TAG, "Replaying %d early bytes from data socket", early_len);
      if (data_encrypted && data_dec) {
        _aes_ctr_crypt(data_dec, early_len, early_raw, crypt_buf);
        _write_all(&relay->local_client, crypt_buf, early_len);
      } else {
        _write_all(&relay->local_client, early_raw, early_len);
      }
      total_rvd_to_local += early_len;
    }
  }

  relay->state = RELAY_RUNNING;
  relay->start_ms = millis();
  NOPORTS_LOGI(TAG, "Relay running for session %s (e2ee=%d) data=%s",
               relay->config.session_id, data_encrypted,
               (data == &sockA) ? "sockA" : "sockB");

  NOPORTS_LOGI(TAG, "Data: c=%d a=%d | Ctrl: c=%d a=%d",
               data->connected(), data->available(),
               ctrl->connected(), ctrl->available());

  idle_since = millis();
  last_stats_time = millis();

  // Bidirectional relay loop: data ↔ local_client
  while (relay->should_run) {
    bool activity = false;

    // Data socket (RVD) -> Local (with optional decryption)
    if (data->available()) {
      int n = data->read(buf, RELAY_BUF_SIZE);
      if (n > 0) {
        activity = true;
        idle_since = millis();
        total_rvd_to_local += n;
        relay->bytes_in = (uint32_t)total_rvd_to_local;
        if (total_rvd_to_local == (unsigned long)n) {
          NOPORTS_LOGI(TAG, "First RVD->Local: %d bytes", n);
        }
        if (data_encrypted && data_dec) {
          _aes_ctr_crypt(data_dec, n, buf, crypt_buf);
          if (!_write_all(&relay->local_client, crypt_buf, n)) {
            NOPORTS_LOGI(TAG, "Local write failed (RVD->Local)");
            break;
          }
        } else {
          if (!_write_all(&relay->local_client, buf, n)) {
            NOPORTS_LOGI(TAG, "Local write failed (RVD->Local)");
            break;
          }
        }
      } else if (n < 0) {
        NOPORTS_LOGI(TAG, "Data read error");
        break;
      }
    }

    // Local -> Data socket (RVD) (with optional encryption)
    if (relay->local_client.available()) {
      int n = relay->local_client.read(buf, RELAY_BUF_SIZE);
      if (n > 0) {
        activity = true;
        idle_since = millis();
        total_local_to_rvd += n;
        relay->bytes_out = (uint32_t)total_local_to_rvd;
        if (total_local_to_rvd == (unsigned long)n) {
          NOPORTS_LOGI(TAG, "First Local->RVD: %d bytes", n);
        }
        if (data_encrypted && data_enc) {
          _aes_ctr_crypt(data_enc, n, buf, crypt_buf);
          if (!_write_all(data, crypt_buf, n)) {
            NOPORTS_LOGI(TAG, "Data write failed (Local->RVD)");
            break;
          }
        } else {
          if (!_write_all(data, buf, n)) {
            NOPORTS_LOGI(TAG, "Data write failed (Local->RVD)");
            break;
          }
        }
      } else if (n < 0) {
        NOPORTS_LOGI(TAG, "Local read error");
        break;
      }
    }

    // Drain control channel (heartbeats / keepalive messages)
    // The NPT client sends periodic heartbeats on the control channel.
    // If we don't read them, the TCP receive buffer fills up and SRVD
    // may tear down the port. Read and discard any data.
    if (ctrl && ctrl->available()) {
      int n = ctrl->read(buf, RELAY_BUF_SIZE);
      if (n > 0) {
        activity = true;  // heartbeat counts as activity for idle timeout
        idle_since = millis();
        NOPORTS_LOGD(TAG, "Ctrl channel heartbeat: %d bytes drained", n);
      }
    }

    // Periodic stats
    if ((millis() - last_stats_time) > 10000) {
      NOPORTS_LOGI(TAG, "Stats: R->L %lu, L->R %lu | data(c=%d) ctrl(c=%d) local(c=%d)",
                   total_rvd_to_local, total_local_to_rvd,
                   data->connected(), ctrl->connected(),
                   relay->local_client.connected());
      last_stats_time = millis();
    }

    // Peer-close detection using reliable recv(MSG_PEEK).
    // Only close when all buffered data has been drained (available()==0)
    // so we never discard unread bytes.
    {
      bool data_closed  = !data->available()  && _peer_closed(*data);
      bool local_closed = !relay->local_client.available() && _peer_closed(relay->local_client);
      if (data_closed || local_closed) {
        NOPORTS_LOGI(TAG, "%s closed (R->L %lu, L->R %lu)",
                     data_closed ? "Data" : "Local",
                     total_rvd_to_local, total_local_to_rvd);
        break;
      }
    }

    if ((millis() - idle_since) > IDLE_TIMEOUT_MS) {
      NOPORTS_LOGI(TAG, "Idle timeout (R->L %lu, L->R %lu)",
                   total_rvd_to_local, total_local_to_rvd);
      break;
    }

    // Always yield at least 1 tick.  The relay task runs at priority 5
    // on Core 1; the Arduino loop (which drives the NoPorts monitor,
    // worker, UI, and touch) runs at priority 1.  taskYIELD() only
    // yields to tasks at the SAME priority, so it never gives the main
    // loop CPU time during sustained data transfer — starving the
    // monitor and making it miss/fail notifications.
    vTaskDelay(pdMS_TO_TICKS(1));
  }

cleanup:
  NOPORTS_LOGI(TAG, "Relay stopping session %s (R->L %lu, L->R %lu)",
               relay->config.session_id, total_rvd_to_local, total_local_to_rvd);

  sockA.stop();         _relay_pcb_count--;
  relay->rvd_client.stop(); _relay_pcb_count--;
  relay->local_client.stop(); _relay_pcb_count--;
  if (_relay_pcb_count < 0) _relay_pcb_count = 0;

  // Free control channel decrypters if still allocated (error path)
  if (ctrl_dec_A) {
    mbedtls_aes_free(&ctrl_dec_A->ctx);
    free(ctrl_dec_A);
  }
  if (ctrl_dec_B) {
    mbedtls_aes_free(&ctrl_dec_B->ctx);
    free(ctrl_dec_B);
  }
  if (relay->encrypter) {
    mbedtls_aes_free(&((aes_ctr_state *)relay->encrypter)->ctx);
    free(relay->encrypter);
    relay->encrypter = NULL;
  }
  if (relay->decrypter) {
    mbedtls_aes_free(&((aes_ctr_state *)relay->decrypter)->ctx);
    free(relay->decrypter);
    relay->decrypter = NULL;
  }

  // Free data channel encryption (from connect: message keys)
  if (data_enc) {
    mbedtls_aes_free(&data_enc->ctx);
    free(data_enc);
  }
  if (data_dec) {
    mbedtls_aes_free(&data_dec->ctx);
    free(data_dec);
  }

  free(buf);
  if (crypt_buf) free(crypt_buf);
  if (earlyA) free(earlyA);
  if (earlyB) free(earlyB);

  if (relay->config.rvd_auth_string) {
    free(relay->config.rvd_auth_string);
    relay->config.rvd_auth_string = NULL;
  }
  if (relay->config.rvd_host) {
    free((void *)relay->config.rvd_host);
    relay->config.rvd_host = NULL;
  }
  if (relay->config.local_host) {
    free((void *)relay->config.local_host);
    relay->config.local_host = NULL;
  }
  if (relay->config.session_aes_key) {
    free(relay->config.session_aes_key);
    relay->config.session_aes_key = NULL;
  }
  if (relay->config.session_iv) {
    free(relay->config.session_iv);
    relay->config.session_iv = NULL;
  }
  if (relay->config.session_aes_key_d2c) {
    free(relay->config.session_aes_key_d2c);
    relay->config.session_aes_key_d2c = NULL;
  }
  if (relay->config.session_iv_d2c) {
    free(relay->config.session_iv_d2c);
    relay->config.session_iv_d2c = NULL;
  }

  // Log stack high-water mark for diagnostics
  UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
  NOPORTS_LOGI(TAG, "Relay task stack HWM: %u words (%u bytes free)",
               (unsigned)hwm, (unsigned)(hwm * sizeof(StackType_t)));

  relay->state = RELAY_STOPPED;
  relay->task_handle = NULL;
  // Return from inner function — C++ destructors (sockA) run here.
  // Wrapper function calls vTaskDelete(NULL) after this.
}

// ==========================================================================
// Multi-session relay: one control channel + N data sub-connections.
//
// The Dart sshnpd sends each TCP session through the tunnel as a separate
// "connect:" message on the encrypted control channel.  This mirrors that
// protocol:
//   1. Open ONE connection to SRVD for the control channel
//   2. Listen for connect: messages (each carrying per-session AES keys)
//   3. For each connect: open NEW SRVD + local connections and bridge them
//   4. Relay data for all active sub-connections simultaneously
// ==========================================================================
static void _relay_task_inner_multi(NoPortsRelay *relay) {
  uint8_t *buf = (uint8_t *)malloc(RELAY_BUF_SIZE);
  uint8_t *crypt_buf = (uint8_t *)malloc(RELAY_BUF_SIZE);
  if (!buf || !crypt_buf) {
    NOPORTS_LOGE(TAG, "Multi: failed to allocate buffers");
    relay->state = RELAY_ERROR;
    if (buf) free(buf);
    if (crypt_buf) free(crypt_buf);
    return;
  }

  NOPORTS_LOGI(TAG, "Multi: relay task started (free heap: %u)",
               (unsigned)esp_get_free_heap_size());

  // Sub-connection tracking (stack-allocated; WiFiClient ctors run)
  RelaySub subs[MAX_RELAY_SUBS];
  for (int i = 0; i < MAX_RELAY_SUBS; i++) {
    subs[i].enc = NULL;
    subs[i].dec = NULL;
    subs[i].active = false;
    subs[i].encrypted = false;
  }
  relay->active_sessions = 0;

  // --- Declare ALL variables before any goto (C++ requirement) ---
  WiFiClient ctrl;
  aes_ctr_state *ctrl_dec = NULL;
  char ctrl_msg[384];
  int ctrl_msg_pos = 0;
  unsigned long idle_since = 0;
  unsigned long last_stats_time = 0;
  bool ctrl_lost = false;            // control channel lost, draining subs
  unsigned long ctrl_lost_since = 0; // when ctrl was lost
  const unsigned long DRAIN_TIMEOUT_MS = 15000UL; // max time to drain after ctrl lost
  int consecutive_connect_fails = 0;     // diagnostic tracking
  const unsigned long IDLE_TIMEOUT_MS =
      (relay->config.idle_timeout_ms > 0) ? relay->config.idle_timeout_ms : 60000UL;

  // Connect queue: when all subs are busy, queue connect: messages
  // and process them as soon as a slot frees up.
  PendingConnect connect_queue[CONNECT_QUEUE_SIZE];
  memset(connect_queue, 0, sizeof(connect_queue));
  int queued_connects = 0;

  // ==================================================================
  // PHASE 1: Open control connection to SRVD, authenticate
  // ==================================================================
  relay->state = RELAY_CONNECTING;

  NOPORTS_LOGI(TAG, "Multi: connecting control to SRVD %s:%d",
               relay->config.rvd_host, relay->config.rvd_port);
  if (!ctrl.connect(relay->config.rvd_host, relay->config.rvd_port)) {
    NOPORTS_LOGE(TAG, "Multi: failed to connect control channel");
    relay->state = RELAY_ERROR;
    goto cleanup;
  }
  _relay_pcb_count++;
  ctrl.setNoDelay(true);
  NOPORTS_LOGI(TAG, "Multi: control channel connected (pcbs=%d/%d)",
               _relay_pcb_count, MAX_RELAY_PCBS);

  if (relay->config.rv_auth && relay->config.rvd_auth_string) {
    relay->state = RELAY_AUTHENTICATING;
    ctrl.print(relay->config.rvd_auth_string);
    ctrl.print("\n");
    ctrl.flush();
    NOPORTS_LOGI(TAG, "Multi: control channel auth sent");
  }

  // Take ownership of control channel decrypter
  if (relay->decrypter) {
    ctrl_dec = (aes_ctr_state *)relay->decrypter;
    relay->decrypter = NULL;
  }
  // Free control-channel encrypter if set (daemon doesn't write to ctrl)
  if (relay->encrypter) {
    mbedtls_aes_free(&((aes_ctr_state *)relay->encrypter)->ctx);
    free(relay->encrypter);
    relay->encrypter = NULL;
  }

  relay->state = RELAY_RUNNING;
  relay->start_ms = millis();
  idle_since = millis();
  last_stats_time = millis();

  NOPORTS_LOGI(TAG, "Multi: relay running session %s (ctrl e2ee=%d)",
               relay->config.session_id, ctrl_dec != NULL);

  // ==================================================================
  // PHASE 2: Main loop - control messages + relay sub-connections
  // ==================================================================
  while (relay->should_run) {
    bool activity = false;

    // --- Read control channel, parse line-delimited messages ---
    // Use available() only — ctrl.connected() is unreliable on ESP32.
    // If the control channel is truly gone, _peer_closed() will catch
    // it in the ctrl_lost detection below.
    while (ctrl.available()) {
      uint8_t raw;
      if (ctrl.read(&raw, 1) != 1) break;

      uint8_t decoded = raw;
      if (ctrl_dec) {
        _aes_ctr_crypt(ctrl_dec, 1, &raw, &decoded);
      }

      if (decoded == '\n') {
        ctrl_msg[ctrl_msg_pos] = '\0';
        if (ctrl_msg_pos > 0) {
          if (strncmp(ctrl_msg, "connect:", 8) == 0) {
            NOPORTS_LOGI(TAG, "Multi: connect request received");
            int rc = _handle_connect_msg(relay, subs, ctrl_msg);
            if (rc != 0) {
              // Queue the connect for later — SRVD already created
              // the sub-channel, so dropping it would cause a client
              // timeout.  Process it as soon as a slot frees up.
              bool queued = false;
              for (int q = 0; q < CONNECT_QUEUE_SIZE; q++) {
                if (!connect_queue[q].pending) {
                  strncpy(connect_queue[q].msg, ctrl_msg, CONNECT_MSG_MAX - 1);
                  connect_queue[q].msg[CONNECT_MSG_MAX - 1] = '\0';
                  connect_queue[q].pending = true;
                  queued_connects++;
                  queued = true;
                  NOPORTS_LOGI(TAG, "Multi: connect queued (%d pending)",
                               queued_connects);
                  break;
                }
              }
              if (!queued) {
                consecutive_connect_fails++;
                NOPORTS_LOGW(TAG, "Multi: connect queue full (%d), dropping",
                             CONNECT_QUEUE_SIZE);
              }
            } else {
              consecutive_connect_fails = 0;
            }
            idle_since = millis();
            activity = true;
            // Break out of ctrl read loop so existing subs get relay
            // time before we process the next connect: message.
            ctrl_msg_pos = 0;
            break;
          } else if (strncmp(ctrl_msg, "heartbeat:", 10) == 0) {
            NOPORTS_LOGD(TAG, "Multi: heartbeat");
            idle_since = millis();
            activity = true;
          } else {
            NOPORTS_LOGW(TAG, "Multi: unknown ctrl msg: %s", ctrl_msg);
          }
        }
        ctrl_msg_pos = 0;
      } else if (ctrl_msg_pos < (int)sizeof(ctrl_msg) - 1) {
        ctrl_msg[ctrl_msg_pos++] = (char)decoded;
      }
    }

    // --- Relay data for all active sub-connections ---
    for (int i = 0; i < MAX_RELAY_SUBS; i++) {
      if (!subs[i].active) continue;

      // SRVD -> local (decrypt if needed)
      if (subs[i].rvd.available()) {
        int n = subs[i].rvd.read(buf, RELAY_BUF_SIZE);
        if (n > 0) {
          activity = true;
          idle_since = millis();
          subs[i].last_activity_ms = millis();
          relay->bytes_in += n;
          if (subs[i].encrypted && subs[i].dec) {
            _aes_ctr_crypt(subs[i].dec, n, buf, crypt_buf);
            if (!_write_all(&subs[i].local, crypt_buf, n)) {
              NOPORTS_LOGI(TAG, "Sub[%d] local write failed", i);
              _close_relay_sub(&subs[i], i);
              continue;
            }
          } else {
            if (!_write_all(&subs[i].local, buf, n)) {
              NOPORTS_LOGI(TAG, "Sub[%d] local write failed", i);
              _close_relay_sub(&subs[i], i);
              continue;
            }
          }
        }
      }

      if (!subs[i].active) continue;

      // local -> SRVD (encrypt if needed)
      if (subs[i].local.available()) {
        int n = subs[i].local.read(buf, RELAY_BUF_SIZE);
        if (n > 0) {
          activity = true;
          idle_since = millis();
          subs[i].last_activity_ms = millis();
          relay->bytes_out += n;
          if (subs[i].encrypted && subs[i].enc) {
            _aes_ctr_crypt(subs[i].enc, n, buf, crypt_buf);
            if (!_write_all(&subs[i].rvd, crypt_buf, n)) {
              NOPORTS_LOGI(TAG, "Sub[%d] rvd write failed", i);
              _close_relay_sub(&subs[i], i);
              continue;
            }
          } else {
            if (!_write_all(&subs[i].rvd, buf, n)) {
              NOPORTS_LOGI(TAG, "Sub[%d] rvd write failed", i);
              _close_relay_sub(&subs[i], i);
              continue;
            }
          }
        }
      }

      if (!subs[i].active) continue;

      // Peer-close detection using reliable recv(MSG_PEEK).
      // Only close when available()==0 so all buffered data is drained.
      {
        bool rvd_closed  = !subs[i].rvd.available()  && _peer_closed(subs[i].rvd);
        bool local_closed = !subs[i].local.available() && _peer_closed(subs[i].local);
        if (rvd_closed || local_closed) {
          NOPORTS_LOGI(TAG, "Sub[%d] peer closed (%s%s)", i,
                       rvd_closed ? "rvd" : "",
                       local_closed ? (rvd_closed ? "+local" : "local") : "");
          _close_relay_sub(&subs[i], i);
          continue;
        }
      }

      // Stall detection: close sub if no data in either direction for too long.
      // Catches cases where TCP keepalive hasn't fired but peer is gone.
      if ((millis() - subs[i].last_activity_ms) > SUB_STALL_TIMEOUT_MS) {
        NOPORTS_LOGW(TAG, "Sub[%d] stalled for %lus, closing",
                     i, (millis() - subs[i].last_activity_ms) / 1000UL);
        _close_relay_sub(&subs[i], i);
        continue;
      }
    }

    // --- Process queued connects if slots/PCBs freed up ---
    // Only try one per loop iteration so active subs keep getting
    // relay time between connect attempts.
    if (queued_connects > 0) {
      for (int q = 0; q < CONNECT_QUEUE_SIZE; q++) {
        if (!connect_queue[q].pending) continue;
        int rc = _handle_connect_msg(relay, subs, connect_queue[q].msg);
        if (rc == 0) {
          connect_queue[q].pending = false;
          queued_connects--;
          consecutive_connect_fails = 0;
          NOPORTS_LOGI(TAG, "Multi: queued connect processed (%d remaining)",
                       queued_connects);
        }
        // Whether it succeeded or failed (still no room), stop here.
        // The next loop iteration will try again if needed.
        break;
      }
    }

    // Update session count (visible to daemon/UI)
    _update_active_session_count(relay, subs);

    // --- Periodic stats ---
    if ((millis() - last_stats_time) > 10000) {
      NOPORTS_LOGI(TAG, "Multi: subs=%d pcbs=%d/%d in=%u out=%u heap=%u",
                   relay->active_sessions,
                   _relay_pcb_count, MAX_RELAY_PCBS,
                   (unsigned)relay->bytes_in,
                   (unsigned)relay->bytes_out,
                   (unsigned)esp_get_free_heap_size());
      last_stats_time = millis();
    }

    // --- Control channel lost ---
    if (!ctrl_lost && !ctrl.available() && _peer_closed(ctrl)) {
      ctrl_lost = true;
      ctrl_lost_since = millis();
      if (relay->active_sessions == 0) {
        NOPORTS_LOGI(TAG, "Multi: control lost + no active subs, exiting");
        break;
      }
      NOPORTS_LOGI(TAG, "Multi: control lost, draining %d subs (max %lums)",
                   relay->active_sessions, DRAIN_TIMEOUT_MS);
    }

    // --- Drain timeout: ctrl lost and subs still lingering ---
    if (ctrl_lost) {
      if (relay->active_sessions == 0) {
        NOPORTS_LOGI(TAG, "Multi: all subs drained after ctrl lost, exiting");
        break;
      }
      if ((millis() - ctrl_lost_since) > DRAIN_TIMEOUT_MS) {
        NOPORTS_LOGW(TAG, "Multi: drain timeout, force-closing %d subs",
                     relay->active_sessions);
        break;
      }
    }

    // --- Idle timeout ---
    if ((millis() - idle_since) > IDLE_TIMEOUT_MS) {
      NOPORTS_LOGI(TAG, "Multi: idle timeout (%lu ms)", IDLE_TIMEOUT_MS);
      break;
    }

    // Always yield at least 1 tick.  The relay task runs at priority 5
    // on Core 1; the Arduino loop (which drives the NoPorts monitor,
    // worker, UI, and touch) runs at priority 1.  taskYIELD() only
    // yields to tasks at the SAME priority, so it never gives the main
    // loop CPU time during sustained data transfer — starving the
    // monitor and making it miss/fail notifications.
    vTaskDelay(pdMS_TO_TICKS(1));
  }

cleanup:
  NOPORTS_LOGI(TAG, "Multi: stopping session %s (in=%u out=%u)",
               relay->config.session_id,
               (unsigned)relay->bytes_in,
               (unsigned)relay->bytes_out);

  // Close all active sub-connections
  for (int i = 0; i < MAX_RELAY_SUBS; i++) {
    if (subs[i].active) {
      _close_relay_sub(&subs[i], i);
    }
  }
  relay->active_sessions = 0;

  // Close control channel
  ctrl.stop();
  _relay_pcb_count--;
  if (_relay_pcb_count < 0) _relay_pcb_count = 0;
  NOPORTS_LOGI(TAG, "Multi: cleanup done (pcbs=%d)", _relay_pcb_count);
  if (ctrl_dec) {
    mbedtls_aes_free(&ctrl_dec->ctx);
    free(ctrl_dec);
  }

  // Free relay enc/dec if not already consumed
  if (relay->encrypter) {
    mbedtls_aes_free(&((aes_ctr_state *)relay->encrypter)->ctx);
    free(relay->encrypter);
    relay->encrypter = NULL;
  }
  if (relay->decrypter) {
    mbedtls_aes_free(&((aes_ctr_state *)relay->decrypter)->ctx);
    free(relay->decrypter);
    relay->decrypter = NULL;
  }

  free(buf);
  free(crypt_buf);

  if (relay->config.rvd_auth_string) {
    free(relay->config.rvd_auth_string);
    relay->config.rvd_auth_string = NULL;
  }
  if (relay->config.rvd_host) {
    free((void *)relay->config.rvd_host);
    relay->config.rvd_host = NULL;
  }
  if (relay->config.local_host) {
    free((void *)relay->config.local_host);
    relay->config.local_host = NULL;
  }
  if (relay->config.session_aes_key) {
    free(relay->config.session_aes_key);
    relay->config.session_aes_key = NULL;
  }
  if (relay->config.session_iv) {
    free(relay->config.session_iv);
    relay->config.session_iv = NULL;
  }
  if (relay->config.session_aes_key_d2c) {
    free(relay->config.session_aes_key_d2c);
    relay->config.session_aes_key_d2c = NULL;
  }
  if (relay->config.session_iv_d2c) {
    free(relay->config.session_iv_d2c);
    relay->config.session_iv_d2c = NULL;
  }

  UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
  NOPORTS_LOGI(TAG, "Multi: stack HWM: %u words (%u bytes free)",
               (unsigned)hwm, (unsigned)(hwm * sizeof(StackType_t)));

  relay->state = RELAY_STOPPED;
  relay->task_handle = NULL;
}

// FreeRTOS task entry point: calls inner function then deletes task.
// Split so that C++ stack objects (WiFiClient sockA) get their destructors
// called when the inner function returns, before the task stack is freed.
static void _relay_task(void *pvParameters) {
  NoPortsRelay *relay = (NoPortsRelay *)pvParameters;
  if (relay->config.multi) {
    _relay_task_inner_multi(relay);
  } else {
    _relay_task_inner(relay);
  }
  vTaskDelete(NULL);
}

void noports_relay_config_init(NoPortsRelayConfig *cfg) {
  memset(cfg, 0, sizeof(NoPortsRelayConfig));
  cfg->local_host = "127.0.0.1";
  cfg->local_port = 0;
  cfg->rv_auth = false;
  cfg->rv_e2ee = false;
  cfg->multi = false;
}

int noports_relay_start(NoPortsRelay *relay, const NoPortsRelayConfig *config) {
  if (!relay || !config) return -1;

  // Reset WiFiClient objects to clean state (important when reusing a relay slot)
  relay->rvd_client = WiFiClient();
  relay->local_client = WiFiClient();

  memcpy(&relay->config, config, sizeof(NoPortsRelayConfig));

  // Deep-copy string pointers so the relay owns them
  // (the originals may be freed by cJSON_Delete before the task uses them)
  if (config->rvd_host) relay->config.rvd_host = strdup(config->rvd_host);
  if (config->local_host) relay->config.local_host = strdup(config->local_host);

  relay->state = RELAY_IDLE;
  relay->should_run = true;
  relay->bytes_in = 0;
  relay->bytes_out = 0;
  relay->start_ms = 0;
  relay->encrypter = NULL;
  relay->decrypter = NULL;

  // Set up control channel decrypter from daemon-generated session keys.
  // This is used to decrypt the client's connect: message on the control channel.
  // The data channel uses separate keys from the connect: message itself.
  // Control channel uses C2D key for decrypting (client encrypts with C2D).
  if (config->rv_e2ee && config->session_aes_key && config->session_iv) {
    aes_ctr_state *dec = _create_aes_ctr_state(config->session_aes_key, config->session_iv);
    if (!dec) {
      NOPORTS_LOGE(TAG, "Failed to setup control channel decrypter");
      return -1;
    }
    relay->decrypter = dec;  // used to decrypt incoming connect: message
    relay->encrypter = NULL; // not needed for control channel
  }

  // Create FreeRTOS task (replaces fork() from C sshnpd)
  BaseType_t ret = xTaskCreatePinnedToCore(
    _relay_task,
    "np_relay",
    RELAY_TASK_STACK_SIZE,
    relay,
    5,                    // priority (higher = less starvation from other tasks)
    &relay->task_handle,
    1                     // core 1 (keep core 0 for WiFi)
  );

  if (ret != pdPASS) {
    NOPORTS_LOGE(TAG, "Failed to create relay task (stack=%d, free heap=%u)",
                 RELAY_TASK_STACK_SIZE, (unsigned)esp_get_free_heap_size());
    if (relay->encrypter) {
      mbedtls_aes_free(&((aes_ctr_state *)relay->encrypter)->ctx);
      free(relay->encrypter);
      relay->encrypter = NULL;
    }
    if (relay->decrypter) {
      mbedtls_aes_free(&((aes_ctr_state *)relay->decrypter)->ctx);
      free(relay->decrypter);
      relay->decrypter = NULL;
    }
    return -1;
  }

  return 0;
}

void noports_relay_stop(NoPortsRelay *relay) {
  if (!relay) return;
  relay->should_run = false;
  // The task will clean up and delete itself
}

bool noports_relay_is_running(const NoPortsRelay *relay) {
  if (!relay) return false;
  // If the task handle exists, verify the FreeRTOS task is actually alive
  if (relay->task_handle != NULL) {
    eTaskState ts = eTaskGetState(relay->task_handle);
    if (ts == eDeleted || ts == eInvalid) {
      // Task is gone but state wasn't updated — force cleanup
      ((NoPortsRelay *)relay)->state = RELAY_STOPPED;
      ((NoPortsRelay *)relay)->task_handle = NULL;
      return false;
    }
  }
  return relay->state == RELAY_RUNNING ||
         relay->state == RELAY_CONNECTING ||
         relay->state == RELAY_AUTHENTICATING;
}
