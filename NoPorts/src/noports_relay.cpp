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

#define TAG "noports_relay"

// Buffer size for relay forwarding
#define RELAY_BUF_SIZE 1024

// Buffer size for early data captured during Phase 2 polling
#define EARLY_BUF_SIZE 256

// Stack size for relay FreeRTOS task
// With all large buffers (earlyA/B, cmsgA/B, buf, crypt_buf) on the heap,
// actual stack usage is ~1200 bytes. 6KB provides comfortable headroom.
#define RELAY_TASK_STACK_SIZE 6144

// AES-CTR encryption state
struct aes_ctr_state {
  mbedtls_aes_context ctx;
  unsigned char nonce_counter[16];
  unsigned char stream_block[16];
  size_t nc_off;
};

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
    if (!client->connected()) return false;
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
  unsigned long relay_start_time = 0;
  const unsigned long GRACE_PERIOD_MS = 15000;
  unsigned long idle_since = 0;
  const unsigned long IDLE_TIMEOUT_MS = 60000;
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
  NOPORTS_LOGI(TAG, "Connected to local service");
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
  NOPORTS_LOGI(TAG, "Relay running for session %s (e2ee=%d) data=%s",
               relay->config.session_id, data_encrypted,
               (data == &sockA) ? "sockA" : "sockB");

  NOPORTS_LOGI(TAG, "Data: c=%d a=%d | Ctrl: c=%d a=%d",
               data->connected(), data->available(),
               ctrl->connected(), ctrl->available());

  relay_start_time = millis();
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

    // Periodic stats
    if ((millis() - last_stats_time) > 10000) {
      NOPORTS_LOGI(TAG, "Stats: R->L %lu, L->R %lu | data(c=%d) ctrl(c=%d) local(c=%d)",
                   total_rvd_to_local, total_local_to_rvd,
                   data->connected(), ctrl->connected(),
                   relay->local_client.connected());
      last_stats_time = millis();
    }

    // Disconnect checks after grace period
    if ((millis() - relay_start_time) > GRACE_PERIOD_MS) {
      if (!data->connected() && !data->available()) {
        NOPORTS_LOGI(TAG, "Data disconnected (R->L %lu, L->R %lu)",
                     total_rvd_to_local, total_local_to_rvd);
        break;
      }
      if (!relay->local_client.connected() && !relay->local_client.available()) {
        NOPORTS_LOGI(TAG, "Local disconnected (R->L %lu, L->R %lu)",
                     total_rvd_to_local, total_local_to_rvd);
        break;
      }
      if ((millis() - idle_since) > IDLE_TIMEOUT_MS) {
        NOPORTS_LOGI(TAG, "Idle timeout (R->L %lu, L->R %lu)",
                     total_rvd_to_local, total_local_to_rvd);
        break;
      }
    }

    if (!activity) {
      vTaskDelay(pdMS_TO_TICKS(10));
    }
  }

cleanup:
  NOPORTS_LOGI(TAG, "Relay stopping session %s (R->L %lu, L->R %lu)",
               relay->config.session_id, total_rvd_to_local, total_local_to_rvd);

  sockA.stop();
  relay->rvd_client.stop();
  relay->local_client.stop();

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

// FreeRTOS task entry point: calls inner function then deletes task.
// Split so that C++ stack objects (WiFiClient sockA) get their destructors
// called when the inner function returns, before the task stack is freed.
static void _relay_task(void *pvParameters) {
  NoPortsRelay *relay = (NoPortsRelay *)pvParameters;
  _relay_task_inner(relay);
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
    1,                    // priority
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
  return relay->state == RELAY_RUNNING ||
         relay->state == RELAY_CONNECTING ||
         relay->state == RELAY_AUTHENTICATING;
}
