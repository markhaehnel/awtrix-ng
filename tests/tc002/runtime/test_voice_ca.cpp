#include "../../support.h"
#include <unistd.h>
#include <chrono>
#include <thread>
#include "core/api/JsonWriter.h"
#include "platform/posix/Files.h"
#include "platform/linux/net/FileDownload.h"
#include "platform/linux/tls/TlsTrust.h"
#include "platform/tc002/voice/VoiceConfig.h"

using namespace awtrix;
using namespace awtrix::tc002::voice;
constexpr auto check = test::require;
int main(int argc, char** argv) {
  if (argc != 5) return 2;
  std::string ca, wrong, leaf;
  check(posix::readText(argv[1], ca) && posix::readText(argv[2], wrong) &&
        posix::readText(argv[3], leaf), "fixture certificates");
  const std::string origin = std::string("https://localhost:") + argv[4];
  tls::setPublicAnchors(tls::TrustAnchors::fromCaPem(wrong));
  char directory[] = "/tmp/awtrix-voice-ca-XXXXXX";
  check(::mkdtemp(directory) != nullptr, "temporary configuration");
  ConfigStore store(directory);
  ConfigStore::Rejection error;
  check(store.load(), "new config");
  const auto settings = [&](const std::string& pem) {
    std::string json;
    api::JsonWriter(json).beginObject().member("url", origin).member("token", "test-token")
        .member("ca", pem).member("enabled", true).endObject();
    return json;
  };
  check(store.update(settings(ca), error) && store.get().caTrust, "save valid private CA");
  check(store.publicJson().find("\"caSet\":true") != std::string::npos &&
        store.publicJson().find("BEGIN CERTIFICATE") == std::string::npos &&
        store.publicJson().find("test-token") == std::string::npos, "redacted status");
  for (const auto& pem : {std::string("bad"), ca + "trailing", ca + '\0', leaf,
                           ca + "-----BEGIN PRIVATE KEY-----", std::string(kMaxCaBytes + 1, 'x')}) {
    check(!store.update(settings(pem), error) && error.field == "ca" && store.get().ca == ca,
          "invalid CA leaves saved trust untouched");
  }
  check(!store.update(R"({"ca":false})", error) && error.field == "ca", "CA must be text");
  check(store.update(R"({"pipeline":"other"})", error) && store.get().ca == ca,
        "ordinary edits preserve CA");
  ConfigStore reloaded(directory);
  check(reloaded.load() && reloaded.get().ca == ca && reloaded.get().caTrust, "CA survives restart");

  net::FileDownload download("/tmp", "voice-ca-test", {1024, 3000, true, nullptr});
  const auto fetch = [&](const std::string& url, const char* path,
                         std::shared_ptr<const tls::TrustAnchors> anchors, bool success, int status) {
    const auto generation = download.start(url, path, std::move(anchors));
    net::FileDownload::Result result;
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool done = false;
    while (!(done = download.poll(result)) && std::chrono::steady_clock::now() < end)
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    check(done && result.generation == generation && result.success() == success && result.status == status,
          "download uses only the requested trust");
    if (success) {
      std::string body;
      check(posix::readText(result.path, body) && body == "voice-test", "TTS bytes exact");
      ::unlink(result.path.c_str());
    } else check(result.path.empty(), "failed download leaves no file");
  };
  fetch(origin, "/api/tts_proxy/ok", reloaded.get().caTrust, true, 200);
  fetch(origin, "/api/tts_proxy/default", {}, false, 0);
  fetch(std::string("https://127.0.0.1:") + argv[4], "/api/tts_proxy/wrong-name", reloaded.get().caTrust, false, 0);
  fetch(origin, "/api/tts_proxy/redirect", reloaded.get().caTrust, false, 302);
  fetch(std::string("http://localhost:") + argv[4], "/api/tts_proxy/plain", reloaded.get().caTrust, false, 0);
  check(store.update(R"({"ca":""})", error) && !store.get().caTrust, "clear CA");
  check(reloaded.load() && reloaded.get().ca.empty(), "removal survives restart");
  check(store.update(settings(ca), error), "restore CA");
  check(store.update(R"({"url":"https://other","token":"new-token"})", error) &&
        store.get().ca.empty() && !store.get().caTrust, "new origin clears retained CA");
  check(!store.update(R"({"url":"http://other","token":"new-token","ca":"bad"})", error), "bad trust rejected");
  check(store.erase() && reloaded.load() && reloaded.get().ca.empty(), "factory reset removes CA");
  ::rmdir(directory);
  std::puts("Voice CA: validation, persistence, removal, origin binding and scoped TTS downloads passed");
}
