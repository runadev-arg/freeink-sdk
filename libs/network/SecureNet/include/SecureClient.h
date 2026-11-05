#pragma once

// FreeInk SDK — TLS 1.3 secure client.
//
// WHY: the precompiled mbedTLS shipped in the ESP-IDF/pioarduino package has
// TLS 1.3 compiled out as empty stubs (PSA crypto prerequisites disabled), so
// WiFiClientSecure / esp_http_client cannot reach TLS-1.3-only servers
// (e.g. KOSync at kosync.ak-team.com:3042 — handshake fails with
// -0x7780 MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE). A -D Kconfig flag can't change a
// precompiled .a, and a custom_sdkconfig rebuild fails on managed-component
// dependencies. The only fix that doesn't rebuild ESP-IDF is to bring our own
// TLS stack compiled from source: wolfSSL, which supports TLS 1.3 + PSA.
//
// SecureClient is an Arduino Client wrapping a wolfSSL session over a plain
// WiFiClient transport, independent of system mbedTLS.
//
// OPT-IN: enable with -DFREEINK_NET_WOLFSSL=1 and add wolfSSL to lib_deps. With
// the flag off, this compiles to an inert no-op (connectSecure() returns false)
// so the rest of the SDK builds without the wolfSSL dependency present.

#include <Arduino.h>
#include <Client.h>
#include <WiFiClient.h>

#include <functional>
#include <utility>

namespace freeink {

class SecureClient : public Client {
 public:
  SecureClient() = default;
  ~SecureClient() override;

  // Return true to abandon an in-progress connect.
  using AbortCallback = std::function<bool()>;

  // Certificate / verification configuration (applied before connect()).
  void setCACert(const char* rootCA);
  void setInsecure();  // skip peer verification (testing only)

  // Opt-in strict mode, for callers that must not talk to an impostor. Peer
  // verification is mandatory, every anchor is loaded on its own and checked
  // (one PEM blob would hide a bad certificate: wolfSSL skips it and reports
  // success if any other parsed), the certificate name must match the host given
  // to connect(), and there is no TLS 1.2 retry, whose error would hide the real
  // one. A count of 0 trusts nothing, so it fails closed. The array and the
  // strings must outlive the client. Overrides setCACert() and setInsecure();
  // calling setInsecure() afterwards returns to the insecure path.
  void setTrustAnchors(const char* const* pemAnchors, size_t count) {
    _anchors = pemAnchors;
    _anchorCount = count;
    _strict = true;
    _insecure = false;
  }

  // Dial this address instead of resolving the host. SNI and the certificate
  // name keep using the host given to connect(). This also avoids
  // Network.hostByName(), whose dns_clear_cache() runs without the TCPIP lock.
  void setServerAddress(IPAddress ip) {
    _pinnedIp = ip;
    _pinned = true;
  }
  void clearServerAddress() { _pinned = false; }

  // TCP connect window; 0 (the default) uses the stream timeout, as before.
  void setConnectTimeout(uint32_t ms) { _connectTimeoutMs = ms; }

  // Why the last connect() returned 0. The code is wolfSSL's for Handshake and
  // TrustLoad, and the free heap for Alloc.
  enum class FailStage : uint8_t { None, Tcp, Alloc, TrustLoad, Handshake, Timeout, Aborted };
  FailStage lastFailStage() const { return _failStage; }
  int lastFailCode() const { return _failCode; }
  // The live WOLFSSL*, for diagnostics only. Null when not connected.
  void* nativeHandle() const { return _ssl; }

  // Polled during connect(): between the TCP connect and the handshake, on
  // every handshake round-trip, and between the two handshake attempts. A
  // caller that drives its own input loop can use this both to cancel and to
  // keep that loop running, the same way the read paths already do.
  //
  // It cannot interrupt the blocking TCP connect itself, so the longest
  // uninterruptible stretch is one setConnectionTimeout() window rather than
  // the four that a failing connect() can otherwise spend.
  void setAbortCallback(AbortCallback cb) { _shouldAbort = std::move(cb); }

  // True when the last connect() returned because the abort callback fired
  // rather than because the connection failed.
  bool aborted() const { return _aborted; }

  // Connect and perform a TLS 1.3 handshake to host:port (uses the SNI host).
  int connect(IPAddress ip, uint16_t port) override;
  int connect(const char* host, uint16_t port) override;

  size_t write(uint8_t b) override;
  size_t write(const uint8_t* buf, size_t size) override;
  int available() override;
  int read() override;
  int read(uint8_t* buf, size_t size) override;
  int peek() override;
  void flush() override;
  void stop() override;
  uint8_t connected() override;
  operator bool() override { return connected(); }

  // True if the library was built with wolfSSL TLS 1.3 support enabled.
  static bool tls13Available();

 private:
  int connectWithMethod(const char* host, uint16_t port, void* method, const char* label);

  // Polls _shouldAbort and latches _aborted so callers can tell a cancel from
  // a failure after connect() returns 0.
  bool abortRequested();
  void fail(FailStage stage, int code) {
    _failStage = stage;
    _failCode = code;
  }

  WiFiClient _transport;
  AbortCallback _shouldAbort;
  bool _aborted = false;
  const char* _rootCA = nullptr;
  bool _insecure = false;
  const char* const* _anchors = nullptr;
  size_t _anchorCount = 0;
  bool _strict = false;
  bool _pinned = false;
  IPAddress _pinnedIp;
  uint32_t _connectTimeoutMs = 0;
  FailStage _failStage = FailStage::None;
  int _failCode = 0;
  void* _ssl = nullptr;  // WOLFSSL* (opaque to keep wolfSSL headers out of here)
  void* _ctx = nullptr;  // WOLFSSL_CTX*
  bool _connected = false;
};

}  // namespace freeink
