#pragma once

#include <string>
#include <utility>
#include "core/net/Url.h"

namespace awtrix::script {

struct HttpTlsOptions {
  std::string pin, ca, servername;
  bool active() const { return !pin.empty() || !ca.empty() || !servername.empty(); }
};

// Normalize the two fingerprint forms printed by OpenSSL; reject ambiguous trust policies.
inline bool normalizeHttpTlsOptions(HttpTlsOptions& options, const std::string& url) {
  if (!options.active()) return true;
  const auto parsed = net::parseUrl(url);
  if (!parsed || !parsed->tls() || parsed->userinfo) return false;
  if (!options.pin.empty()) {
    if (!options.ca.empty() || !options.servername.empty()) return false;
    const bool separated = options.pin.size() == 95;
    if (!separated && options.pin.size() != 64) return false;
    std::string normalized;
    for (std::size_t i = 0; i < options.pin.size(); ++i) {
      char c = options.pin[i];
      if (separated && i % 3 == 2) {
        if (c != ':') return false;
        continue;
      }
      if (c >= 'A' && c <= 'F') c += 'a' - 'A';
      if (!((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'))) return false;
      normalized += c;
    }
    options.pin = std::move(normalized);
  }
  if (options.ca.size() > 65536 || options.ca.find('\0') != std::string::npos) return false;
  if (!options.servername.empty()) {
    const std::string address = "https://" + options.servername;
    const auto name = net::parseUrl(address);
    if (options.ca.empty() || !name || name->userinfo || !name->port.empty() ||
        !name->originOnly() || name->fragment) return false;
  }
  return true;
}

}
