#include <openssl/evp.h>
#include <openssl/rand.h>
#include "argon2_min.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <filesystem>
#include <chrono>
#include <thread>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cmath>
#include <climits>
#include <cstdio>
#include <random>
#include <csignal>
#include <cerrno>
#include <type_traits>
#include <memory>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#ifdef PWMGR_WITH_FIDO2
#include <fido.h>
#endif
#ifdef PWMGR_WITH_TPM
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#endif

namespace fs = std::filesystem;

// ============================================================================
// Build instructions
// ----------------------------------------------------------------------------
// Base build (password + optional keyfile second factor only), unchanged:
//   g++ -std=c++17 -O2 -o pwmgr main.cpp -lcrypto
//
// With FIDO2 hardware second-factor support: requires libfido2 (and its own
// dependency, libcbor) installed and discoverable via pkg-config.
//   Debian/Ubuntu:  sudo apt install libfido2-dev
//   Fedora/RHEL:    sudo dnf install libfido2-devel
//   macOS (brew):   brew install libfido2
// Then (one command, shown split across lines for readability - join them,
// or keep the shell line-continuation if pasting into a real shell):
//   g++ -std=c++17 -O2 -DPWMGR_WITH_FIDO2 $(pkg-config --cflags libfido2)
//       -o pwmgr main.cpp -lcrypto $(pkg-config --libs libfido2)
//
// With TPM2 hardware second-factor support: requires tpm2-tss's ESAPI
// library installed and discoverable via pkg-config as "tss2-esys".
//   Debian/Ubuntu:  sudo apt install libtss2-dev
//   Fedora/RHEL:    sudo dnf install tpm2-tss-devel
// A TPM must be reachable at runtime - either a hardware TPM (usually
// /dev/tpmrm0, needs tss group membership or equivalent udev rule) or
// tpm2-abrmd/the kernel resource manager already running; this program
// does not manage that setup, only talks to whatever tpm2-tss finds.
//   g++ -std=c++17 -O2 -DPWMGR_WITH_TPM $(pkg-config --cflags tss2-esys)
//       -o pwmgr main.cpp -lcrypto $(pkg-config --libs tss2-esys)
//
// Both together (a build can support FIDO2 and TPM at once; which one a
// given vault actually requires is still decided per-vault by which
// sidecar file exists, exactly as with the FIDO2/keyfile precedence rules
// above), again shown split for readability - join into one command:
//   g++ -std=c++17 -O2 -DPWMGR_WITH_FIDO2 -DPWMGR_WITH_TPM
//       $(pkg-config --cflags libfido2 tss2-esys)
//       -o pwmgr main.cpp -lcrypto $(pkg-config --libs libfido2 tss2-esys)
// ============================================================================

const char     VAULT_MAGIC[4]      = {'P','W','M','G'};
// v2: 64-byte Argon2 output, implicit KDF/cipher.
// v3: 32-byte Argon2 output, implicit KDF/cipher (this is the format that
//     "VAULT_VERSION == 3" always meant before this header revision).
// v4: same crypto as v3 (Argon2id -> AES-256-GCM, 32-byte output) but the
//     header now names the KDF and cipher explicitly via KDF_ID_*/CIPHER_ID_*
//     and reserves a flags word. This is infrastructure only: no new
//     algorithm is enabled by it. Adding one later (e.g. an
//     XChaCha20-Poly1305 CIPHER_ID, or a new KDF_ID) is then a matter of
//     defining the new constant and a load()/save() branch on it, not another
//     header redesign or version-number overload.
const uint32_t VAULT_VERSION              = 4;
const uint32_t VAULT_VERSION_LEGACY_KDF64 = 2; // v2 vaults derived a 64-byte Argon2 output;
                                                // Argon2's output length is part of its internal
                                                // hashing input, so this is NOT just "use the
                                                // first 32 bytes" - it must be re-derived with
                                                // the original 64-byte length to unlock correctly.
const uint32_t VAULT_VERSION_V3           = 3; // implicit KDF/cipher, no ids/flags in header
const uint32_t KDF_ID_ARGON2ID            = 1;
const uint32_t CIPHER_ID_AES_256_GCM      = 1;
const uint32_t VAULT_FLAGS_NONE           = 0; // reserved: must be 0 until a flag is defined
const std::string VAULT_FILENAME   = ".pwmgr_vault";
const std::string ATTEMPTS_FILE    = ".pwmgr_attempts";
const int GCM_NONCE_SIZE           = 12;
const int GCM_TAG_SIZE             = 16;
const int GCM_KEY_SIZE             = 32;
const int SALT_SIZE                = 32;
const int KDF_OUTPUT_SIZE          = 32; // == GCM_KEY_SIZE; nothing else consumes Argon2 output
const uint32_t ARGON2_T_COST       = 3;
const uint32_t ARGON2_M_COST       = 65536;
const uint32_t ARGON2_PARALLELISM  = 4;
const uint32_t MAX_VAULT_BYTES     = 64 * 1024 * 1024;
const uint32_t MAX_ENTRIES         = 10000;
const uint32_t MAX_FIELD_BYTES     = 65535;
const int CLIPBOARD_CLEAR_SECS    = 20;
const int SHELL_LOCK_SECS         = 300;
const int BASE_DELAY_MS           = 500;
const int MAX_DELAY_MS            = 30000;
const int MAX_FAILED_ATTEMPTS     = 10;

// Reduce the memory-scraping attack surface from other processes running as
// the same user (e.g. malware without root, or a crash handler):
//  - PR_SET_DUMPABLE=0 stops other same-user processes from ptrace-attaching
//    to us and stops the kernel from writing a core file if we crash.
//  - RLIMIT_CORE=0 is a second, redundant belt-and-suspenders guard against
//    a plaintext-laden core dump ever landing on disk.
// NOTE: none of this stops root, a kernel-level keylogger, or malware that
// already has ptrace/CAP_SYS_PTRACE. It only raises the bar for ordinary
// same-user malware and accidental crash dumps.
void harden_process() {
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
#endif
    struct rlimit rl{0, 0};
    setrlimit(RLIMIT_CORE, &rl);
    // copy_to_clipboard() below writes to a pipe to an external helper
    // (xclip/xsel). If that helper isn't installed, popen() still
    // succeeds (it only spawns /bin/sh), but the shell exits immediately
    // after failing to exec the missing binary, closing its end of the
    // pipe. Writing to a pipe with no reader raises SIGPIPE, and the
    // default action for SIGPIPE is to kill the process outright - with
    // no destructors run, no vault wipe, and (if this happens mid-'add')
    // the new entry silently lost before it was ever saved. Ignoring
    // SIGPIPE turns that write into an ordinary failed write (EPIPE)
    // that copy_to_clipboard() can detect and report instead.
    signal(SIGPIPE, SIG_IGN);
}

// Deliberately does nothing except record which signal fired. Doing real
// cleanup (zeroing vectors, calling destructors) inside a signal handler is
// not safe in general - if the signal lands while the program is mid-malloc,
// calling malloc/free again from the handler can deadlock. Instead, we rely
// on installing the handler *without* SA_RESTART: that alone is enough to
// make blocking calls like select()/read() return EINTR instead of quietly
// resuming, which causes the existing code paths (e.g. cmd_shell's idle-wait
// check) to fall through to their normal wipe-and-exit logic rather than the
// process being killed outright with plaintext still resident in memory.
volatile sig_atomic_t g_signal_received = 0;

extern "C" void on_termination_signal(int sig) {
    g_signal_received = sig;
}

void install_signal_handlers() {
    struct sigaction sa{};
    sa.sa_handler = on_termination_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // no SA_RESTART, intentionally
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
}

class CipherCtx {
    EVP_CIPHER_CTX* ctx_;
public:
    CipherCtx() : ctx_(EVP_CIPHER_CTX_new()) {
        if (!ctx_) throw std::runtime_error("Failed to allocate cipher context");
    }
    ~CipherCtx() { EVP_CIPHER_CTX_free(ctx_); }
    EVP_CIPHER_CTX* get() { return ctx_; }
    CipherCtx(const CipherCtx&) = delete;
    CipherCtx& operator=(const CipherCtx&) = delete;
};

void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i) p[i] = 0;
}
void secure_clear(std::string& s) {
    if (!s.empty()) { secure_zero(&s[0], s.size()); s.clear(); }
}
void secure_clear(std::vector<uint8_t>& v) {
    if (!v.empty()) { secure_zero(v.data(), v.size()); v.clear(); }
}

static bool g_mlock_warned = false;
void warn_mlock_failure() {
    if (g_mlock_warned) return;
    g_mlock_warned = true;
    std::cerr << "\nWarning: memory locking (mlock) unavailable or limited here\n"
                 "(commonly RLIMIT_MEMLOCK, cgroup limits, or missing capability).\n"
                 "Secrets in this session may be swapped to disk under memory\n"
                 "pressure. Consider: ulimit -l unlimited (root/CAP_IPC_LOCK may\n"
                 "be required), or enabling encrypted swap on this system.\n\n";
}
// ============================================================================
// SecureVector<T> / SecureString
// ----------------------------------------------------------------------------
// RAII wrappers for secret material (master passwords, entry passwords,
// derived keys, plaintext buffers). This replaces the previous pattern of
// "std::string/std::vector + remember to call lock_secret()/secure_clear()
// at every call site" (what LockedBuffer partly did for fixed-size buffers)
// with something that carries those guarantees on the type itself:
//
//   - Never uses small-string optimization. The backing store is *always*
//     a separate heap allocation, even for a 4-byte secret. This matters
//     because std::string's SSO buffer lives inline inside the object -
//     zeroing the object after the fact does nothing for a copy of it that
//     was itself stack- or heap-allocated elsewhere (a lambda capture, a
//     vector reallocation, a pass-by-value) and still holds the inline
//     bytes.
//   - mlock()'d for the lifetime of the buffer (best-effort - same
//     warn-once behavior as before via warn_mlock_failure()).
//   - secure_zero()'d before every reallocation and on destruction, so
//     growing, shrinking, or reassigning never leaves old contents sitting
//     in freed, unzeroed memory (the exact problem the read_password()
//     comment below used to call out as a reason NOT to use std::string).
//   - Copies deep-copy into their own locked buffer; moves are cheap
//     pointer swaps (and noexcept, so std::vector<PasswordEntry> reallocs
//     move rather than copy entries around).
//
// Not handled by this type, same caveats as before: it's still possible to
// leak a secret by explicitly converting it to a std::string (needed at a
// few call sites - see reveal() below) or by handing it to code that makes
// its own copy. This closes off the *accidental* leaks from string growth
// and forgetting a manual clear/lock call; it doesn't stop a deliberate one.
// ============================================================================
template <typename T>
class SecureVector {
    static_assert(std::is_trivially_copyable<T>::value, "SecureVector<T> requires a trivially copyable T");
    T*     data_;
    size_t size_;
    size_t capacity_;
    bool   locked_;

    void lock_current() {
        locked_ = false;
        if (capacity_ > 0) {
            if (mlock(data_, capacity_ * sizeof(T)) == 0) locked_ = true;
            else warn_mlock_failure();
        }
    }
    void release() {
        if (data_) {
            secure_zero(data_, capacity_ * sizeof(T));
            if (locked_) munlock(data_, capacity_ * sizeof(T));
            delete[] data_;
        }
        data_ = nullptr; size_ = 0; capacity_ = 0; locked_ = false;
    }
public:
    SecureVector() : data_(nullptr), size_(0), capacity_(0), locked_(false) {}
    explicit SecureVector(size_t n) : SecureVector() { resize(n); }
    SecureVector(const T* p, size_t n) : SecureVector() { assign(p, n); }
    SecureVector(const SecureVector& o) : SecureVector() { assign(o.data_, o.size_); }
    SecureVector(SecureVector&& o) noexcept
        : data_(o.data_), size_(o.size_), capacity_(o.capacity_), locked_(o.locked_) {
        o.data_ = nullptr; o.size_ = 0; o.capacity_ = 0; o.locked_ = false;
    }
    SecureVector& operator=(const SecureVector& o) { if (this != &o) assign(o.data_, o.size_); return *this; }
    SecureVector& operator=(SecureVector&& o) noexcept {
        if (this != &o) {
            release();
            data_ = o.data_; size_ = o.size_; capacity_ = o.capacity_; locked_ = o.locked_;
            o.data_ = nullptr; o.size_ = 0; o.capacity_ = 0; o.locked_ = false;
        }
        return *this;
    }
    ~SecureVector() { release(); }

    // Always allocates a fresh buffer and zeroes+frees the old one, rather
    // than realloc()-ing in place, so old contents never linger unzeroed.
    void assign(const T* p, size_t n) {
        release();
        if (n > 0) { data_ = new T[n]; if (p) std::memcpy(data_, p, n * sizeof(T)); }
        size_ = capacity_ = n;
        lock_current();
    }
    void resize(size_t n) {
        T* nd = n > 0 ? new T[n]() : nullptr;
        size_t copy_n = std::min(n, size_);
        if (nd && data_ && copy_n) std::memcpy(nd, data_, copy_n * sizeof(T));
        release();
        data_ = nd; size_ = capacity_ = n;
        lock_current();
    }
    void push_back(const T& v) {
        size_t ns = size_ + 1;
        T* nd = new T[ns]();
        if (data_) std::memcpy(nd, data_, size_ * sizeof(T));
        nd[size_] = v;
        release();
        data_ = nd; size_ = capacity_ = ns;
        lock_current();
    }
    void clear() { if (data_) secure_zero(data_, capacity_ * sizeof(T)); size_ = 0; }

    T*       data()       { return data_; }
    const T* data() const { return data_; }
    size_t   size() const { return size_; }
    bool     empty() const { return size_ == 0; }
    T&       operator[](size_t i)       { return data_[i]; }
    const T& operator[](size_t i) const { return data_[i]; }
};

// SecureString: a SecureVector<char> plus the small amount of string-flavored
// convenience the rest of this file needs. Every OpenSSL/Argon2 call in this
// file already takes an explicit pointer+length (password.c_str(), size()),
// so there's never a need for a null terminator here.
class SecureString {
    SecureVector<char> buf_;
public:
    SecureString() = default;
    SecureString(const char* s) { if (s) buf_.assign(s, std::strlen(s)); }
    SecureString(const std::string& s) { buf_.assign(s.data(), s.size()); }
    SecureString(const SecureString&) = default;
    SecureString(SecureString&&) = default;
    SecureString& operator=(const SecureString&) = default;
    SecureString& operator=(SecureString&&) = default;

    size_t size() const { return buf_.size(); }
    bool empty() const { return buf_.empty(); }
    const char* data() const { return buf_.data(); }
    char* data() { return buf_.data(); }
    char operator[](size_t i) const { return buf_[i]; }

    void assign(const char* p, size_t n) { buf_.assign(p, n); }
    void push_back(char c) { buf_.push_back(c); }
    void append(const char* p, size_t n) {
        SecureVector<char> nb(buf_.size() + n);
        if (buf_.size()) std::memcpy(nb.data(), buf_.data(), buf_.size());
        if (n) std::memcpy(nb.data() + (nb.size() - n), p, n);
        buf_ = std::move(nb);
    }
    void clear() { buf_.clear(); }

    // Not a hardened constant-time compare (this guards master-password
    // confirmation re-entry and the "passwords match" check, not a
    // network-facing auth boundary) but costs nothing to do the
    // OR-accumulate way rather than short-circuiting on the first byte.
    bool operator==(const SecureString& o) const {
        if (size() != o.size()) return false;
        unsigned char diff = 0;
        for (size_t i = 0; i < size(); ++i) diff |= (unsigned char)(data()[i] ^ o.data()[i]);
        return diff == 0;
    }
    bool operator!=(const SecureString& o) const { return !(*this == o); }
};

void secure_clear(SecureString& s) { s.clear(); }
template <typename T> void secure_clear(SecureVector<T>& v) { v.clear(); }

// Deliberately the ONLY way a SecureString's contents become a plain
// std::string in this file - used at the couple of call sites (showing a
// freshly generated/revealed password on screen) that genuinely need to
// print it. Because there's no SecureString::operator<<, every other call
// site has to say "yes, I mean to expose this" explicitly instead of it
// happening for free via std::cout << some_secure_string.
static std::string reveal(const SecureString& s) { return std::string(s.data(), s.size()); }

SecureString read_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    struct termios old_tty, new_tty;
    bool tty = isatty(STDIN_FILENO);
    if (tty) {
        tcgetattr(STDIN_FILENO, &old_tty);
        new_tty = old_tty;
        new_tty.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &new_tty);
    }
    // Read into a fixed, mlock'd buffer from the first byte onward. A plain
    // std::string built via getline reallocates its backing store as it
    // grows, and each reallocation can leave a copy of the password-so-far
    // sitting in freed, unzeroed heap memory. Reading into a buffer that's
    // already locked and sized up front avoids that; the result is then
    // copied once into the SecureString we return (itself never SSO'd).
    constexpr size_t MAX_PW_LEN = 1024;
    SecureVector<uint8_t> buf(MAX_PW_LEN);
    size_t len = 0;
    int c;
    while ((c = std::cin.get()) != EOF && c != '\n' && len < MAX_PW_LEN) {
        buf.data()[len++] = static_cast<uint8_t>(c);
    }
    SecureString pw;
    pw.assign(reinterpret_cast<char*>(buf.data()), len);
    if (tty) { tcsetattr(STDIN_FILENO, TCSANOW, &old_tty); std::cout << "\n"; }
    return pw;
}

bool stdin_ready(int timeout_secs) {
    fd_set fds; FD_ZERO(&fds); FD_SET(STDIN_FILENO, &fds);
    struct timeval tv = { timeout_secs, 0 };
    return select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) > 0;
}

std::vector<uint8_t> random_bytes(int n) {
    std::vector<uint8_t> buf(n);
    if (RAND_bytes(buf.data(), n) != 1) throw std::runtime_error("RAND_bytes failed");
    return buf;
}

// ---------------------------------------------------------------------------
// Second-factor providers
//
// A provider's only job is to answer "what extra secret bytes, if any, get
// mixed into the master password before Argon2id?" Everything downstream -
// the KDF, the vault format, save()/load() - only ever sees the combined
// SecureString that comes out of combined_secret() below, so a provider can
// be swapped for another without touching the encryption path at all.
//
// This keeps the same threat model the keyfile already had: it's a second
// factor that raises the bar (attacker needs the master password AND
// whatever the provider holds), not a replacement for the master password
// itself, and not something that survives an attacker who's present at
// unlock time with access to both.
// ---------------------------------------------------------------------------
class SecondFactorProvider {
public:
    virtual ~SecondFactorProvider() = default;
    virtual std::string name() const = 0;
    // False means "selected but not usable in this build/environment"
    // (no libfido2 linked in, no /dev/tpmrm0, etc.) - callers must fail
    // loudly rather than silently falling back to password-only, since a
    // silent fallback would quietly downgrade the vault's protection.
    virtual bool available() const = 0;
    // Extra secret material to mix in. An empty SecureString is valid and
    // means "no second factor" (PasswordOnlyProvider).
    virtual SecureString factor_material() const = 0;
    // Registers a brand-new credential/sealed-object and persists whatever
    // *public* metadata is needed to find it again at unlock time, next to
    // vault_path. Providers that don't have a registration step of their
    // own (PasswordOnlyProvider; KeyfileProvider, whose "enrollment" is
    // `pwmgr genkeyfile` writing random bytes to removable media, a step
    // that predates and is independent of this interface) keep the
    // default, which refuses cleanly rather than silently no-op'ing.
    virtual void enroll(const std::string& /*vault_path*/) {
        throw std::runtime_error(name() + " does not support enrollment.");
    }
};

// Sidecar metadata files live at <vault_path><suffix> (".fido2", ".tpm").
// They hold only public, non-secret state (a FIDO2 credential ID + RP id +
// hmac-secret salt; a TPM-sealed public/private blob pair that only that
// TPM can unseal) - never anything that needs mlock/secure_zero treatment,
// and never anything that touches VAULT_MAGIC/VAULT_VERSION or the AEAD
// format. Kept as a free function (not a provider method) since selecting
// a provider needs to check for these files' existence before a provider
// object exists yet.
static std::string provider_metadata_path(const std::string& vault_path, const char* suffix) {
    return vault_path + suffix;
}

// Defined after write_file_atomic() further down (metadata writes reuse it
// for the same atomic-write/0600 guarantees the vault file itself gets).
// Forward-declared here so FIDO2Provider/TPMProvider::enroll() below can
// call them without reordering the provider classes.
static void write_metadata_file(const std::string& path, const std::vector<std::vector<uint8_t>>& fields);
static std::vector<std::vector<uint8_t>> read_metadata_file(const std::string& path);

class PasswordOnlyProvider : public SecondFactorProvider {
public:
    std::string name() const override { return "password"; }
    bool available() const override { return true; }
    SecureString factor_material() const override { return SecureString(); }
};

// Refactor of the original keyfile logic from combined_secret(), unchanged
// in behavior: reads the whole file, treats its raw bytes as the factor
// material, and wipes its own std::string copy before returning.
class KeyfileProvider : public SecondFactorProvider {
    std::string path_;
public:
    explicit KeyfileProvider(std::string path) : path_(std::move(path)) {}
    std::string name() const override { return "keyfile"; }
    bool available() const override { return !path_.empty(); }
    SecureString factor_material() const override {
        std::ifstream f(path_, std::ios::binary);
        if (!f) throw std::runtime_error("Cannot read keyfile: " + path_);
        std::ostringstream ss; ss << f.rdbuf();
        std::string data = ss.str();
        if (data.empty()) throw std::runtime_error("Keyfile is empty: " + path_);
        SecureString out; out.append(data.data(), data.size());
        secure_clear(data);
        return out;
    }
};

// --- Hardware-backed: FIDO2 --------------------------------------------
// libfido2 support (step 3: device discovery + credential enrollment).
// factor_material() (assertion + hmac-secret retrieval at unlock time) is
// still a stub - that's step 4. Everything here is compiled only under
// PWMGR_WITH_FIDO2; a build without it behaves exactly as before.
#ifdef PWMGR_WITH_FIDO2

// RP id is a fixed, non-secret string identifying "this application" to the
// authenticator - analogous to a WebAuthn relying party id, but there's no
// real origin/domain here since this isn't a browser. Any authenticator
// that already holds an unrelated "pwmgr" credential from a different
// vault would collide on RP id alone; the credential ID stored in each
// vault's own sidecar file is what disambiguates between vaults sharing
// one physical key.
static const char* const FIDO2_RP_ID   = "pwmgr";
static const char* const FIDO2_RP_NAME = "pwmgr password manager";
static const size_t FIDO2_SALT_SIZE    = 32; // CTAP2 hmac-secret salt size, fixed by spec

struct FidoDevDeleter    { void operator()(fido_dev_t* d) const    { if (d) { fido_dev_close(d); fido_dev_free(&d); } } };
struct FidoCredDeleter   { void operator()(fido_cred_t* c) const   { if (c) fido_cred_free(&c); } };
struct FidoAssertDeleter { void operator()(fido_assert_t* a) const { if (a) fido_assert_free(&a); } };
struct FidoCborInfoDeleter { void operator()(fido_cbor_info_t* i) const { if (i) fido_cbor_info_free(&i); } };
using FidoDevPtr      = std::unique_ptr<fido_dev_t, FidoDevDeleter>;
using FidoCredPtr     = std::unique_ptr<fido_cred_t, FidoCredDeleter>;
using FidoAssertPtr   = std::unique_ptr<fido_assert_t, FidoAssertDeleter>;
using FidoCborInfoPtr = std::unique_ptr<fido_cbor_info_t, FidoCborInfoDeleter>;

// Enumerates connected FIDO2 authenticators and opens the sole one found.
// Deliberately refuses to guess when zero or several are present, rather
// than silently picking "the first one" - with several plugged in, a user
// could easily touch the wrong key and bind (or unlock) against a device
// they didn't mean to use.
static FidoDevPtr open_sole_fido2_device() {
    const size_t MAX_DEVS = 64;
    fido_dev_info_t* list = fido_dev_info_new(MAX_DEVS);
    if (!list) throw std::runtime_error("fido_dev_info_new failed (out of memory)");
    size_t n = 0;
    int r = fido_dev_info_manifest(list, MAX_DEVS, &n);
    if (r != FIDO_OK) {
        fido_dev_info_free(&list, MAX_DEVS);
        throw std::runtime_error(std::string("FIDO2 device enumeration failed: ") + fido_strerr(r));
    }
    if (n == 0) {
        fido_dev_info_free(&list, MAX_DEVS);
        throw std::runtime_error("No FIDO2 authenticator detected - plug one in and try again.");
    }
    if (n > 1) {
        fido_dev_info_free(&list, MAX_DEVS);
        throw std::runtime_error(
            "More than one FIDO2 authenticator is connected - unplug all but "
            "the one you want to use, so there's no ambiguity about which "
            "device this vault binds to.");
    }
    const fido_dev_info_t* di = fido_dev_info_ptr(list, 0);
    std::string path = fido_dev_info_path(di) ? fido_dev_info_path(di) : "";
    fido_dev_info_free(&list, MAX_DEVS);
    if (path.empty()) throw std::runtime_error("Could not determine FIDO2 device path");

    FidoDevPtr dev(fido_dev_new());
    if (!dev) throw std::runtime_error("fido_dev_new failed (out of memory)");
    r = fido_dev_open(dev.get(), path.c_str());
    if (r != FIDO_OK) throw std::runtime_error(std::string("Could not open FIDO2 device: ") + fido_strerr(r));
    return dev;
}

// Queries the authenticator's own advertised extension list (via the CTAP2
// getInfo command) rather than just requesting hmac-secret and hoping -
// this is the correct place to check "if available" per the requirement,
// and lets enroll() fail with a clear, specific message on hardware that
// can't do this instead of silently falling back to something weaker (a
// device serial number or public key), which is explicitly not acceptable
// factor material.
static bool device_supports_hmac_secret(fido_dev_t* dev) {
    FidoCborInfoPtr info(fido_cbor_info_new());
    if (!info) throw std::runtime_error("fido_cbor_info_new failed (out of memory)");
    int r = fido_dev_get_cbor_info(dev, info.get());
    if (r != FIDO_OK)
        throw std::runtime_error(std::string("Could not query authenticator capabilities: ") + fido_strerr(r));
    char* const* exts = fido_cbor_info_extensions_ptr(info.get());
    size_t nexts = fido_cbor_info_extensions_len(info.get());
    for (size_t i = 0; i < nexts; ++i)
        if (exts[i] && std::strcmp(exts[i], "hmac-secret") == 0) return true;
    return false;
}

// CTAP2 requires a 32-byte "client data hash" on every credential/assertion
// operation. In WebAuthn proper this binds a browser-supplied challenge and
// origin so a relying party's server can detect replay/phishing; there is
// no such remote verifier here; pwmgr is both "client" and sole relying
// party, talking to the device directly over USB/NFC. So this hash only
// needs to be present and correctly sized, not secret or session-unique.
static std::vector<uint8_t> fido2_client_data_hash() {
    static const char ctx[] = "pwmgr-fido2-v1";
    std::vector<uint8_t> hash(32);
    unsigned int len = 0;
    if (EVP_Digest(ctx, sizeof(ctx) - 1, hash.data(), &len, EVP_sha256(), nullptr) != 1 || len != 32)
        throw std::runtime_error("SHA-256 for FIDO2 client data hash failed");
    return hash;
}
#endif // PWMGR_WITH_FIDO2

// --- Provider classes ---------------------------------------------------
// Both FIDO2Provider (above the TPM helpers, below) and TPMProvider are now
// fully implemented behind their respective compile guards. Either can be
// built without the other; which one a given vault actually requires is
// decided per-vault by which sidecar file exists (see select_provider()).
class FIDO2Provider : public SecondFactorProvider {
    // Source of truth for *where* this provider's metadata lives, rather
    // than the metadata path itself. This lets the same object be used for
    // both call shapes the codebase needs:
    //   - select_provider() constructs one for an *existing* sidecar file
    //     (vault_path known, metadata already on disk).
    //   - cmd_genfido2's rebind step constructs one, calls enroll() to
    //     create the sidecar file, then immediately calls factor_material()
    //     on that same instance for vault.save(master, provider) - with no
    //     re-construction/re-guessing step in between.
    // metadata_path() is always provider_metadata_path(vault_path_, ".fido2"),
    // computed fresh each time rather than cached, so enroll() and
    // factor_material() can never disagree about where to look.
    std::string vault_path_;
public:
    explicit FIDO2Provider(std::string vault_path = "") : vault_path_(std::move(vault_path)) {}
    std::string metadata_path() const { return provider_metadata_path(vault_path_, ".fido2"); }
    std::string name() const override { return "fido2"; }
    bool available() const override {
#ifdef PWMGR_WITH_FIDO2
        // Compiled with libfido2 support. Deliberately NOT also checking
        // "is a device plugged in right now" here - that check belongs in
        // enroll()/factor_material(), which can give a specific, actionable
        // error ("no key plugged in") instead of the generic "this build
        // has no FIDO2 support" message select_provider() gives when this
        // returns false.
        return true;
#else
        return false;
#endif
    }
    SecureString factor_material() const override {
#ifdef PWMGR_WITH_FIDO2
        auto fields = read_metadata_file(metadata_path());
        if (fields.size() != 3)
            throw std::runtime_error("Malformed FIDO2 metadata: " + metadata_path());
        const std::vector<uint8_t>& rp_id_bytes = fields[0];
        const std::vector<uint8_t>& cred_id     = fields[1];
        const std::vector<uint8_t>& salt        = fields[2];
        std::string rp_id(rp_id_bytes.begin(), rp_id_bytes.end());

        fido_init(0);
        FidoDevPtr dev = open_sole_fido2_device();

        FidoAssertPtr assertion(fido_assert_new());
        if (!assertion) throw std::runtime_error("fido_assert_new failed (out of memory)");

        auto cdh = fido2_client_data_hash();
        int r;
        if ((r = fido_assert_set_rp(assertion.get(), rp_id.c_str())) != FIDO_OK ||
            (r = fido_assert_set_clientdata_hash(assertion.get(), cdh.data(), cdh.size())) != FIDO_OK ||
            (r = fido_assert_allow_cred(assertion.get(), cred_id.data(), cred_id.size())) != FIDO_OK ||
            (r = fido_assert_set_extensions(assertion.get(), FIDO_EXT_HMAC_SECRET)) != FIDO_OK ||
            (r = fido_assert_set_hmac_salt(assertion.get(), salt.data(), salt.size())) != FIDO_OK)
            throw std::runtime_error(std::string("Setting up FIDO2 assertion parameters failed: ") + fido_strerr(r));

        r = fido_dev_get_assert(dev.get(), assertion.get(), nullptr);
        if (r == FIDO_ERR_PIN_REQUIRED) {
            SecureString pin = read_password("Authenticator PIN: ");
            r = fido_dev_get_assert(dev.get(), assertion.get(), pin.data());
            secure_clear(pin);
        }
        if (r != FIDO_OK)
            throw std::runtime_error(std::string(
                "FIDO2 unlock failed (wrong authenticator for this vault, or not "
                "touched in time): ") + fido_strerr(r));

        if (fido_assert_count(assertion.get()) < 1)
            throw std::runtime_error("Authenticator returned no assertions");

        const unsigned char* secret = fido_assert_hmac_secret_ptr(assertion.get(), 0);
        size_t secret_len = fido_assert_hmac_secret_len(assertion.get(), 0);
        if (!secret || secret_len == 0)
            throw std::runtime_error(
                "Authenticator did not return an hmac-secret value for this "
                "credential - wrong device, or hmac-secret support changed "
                "since enrollment.");

        // secret/secret_len point into memory owned by `assertion` (libfido2's
        // own allocation - freed, but not guaranteed zeroed, by
        // fido_assert_free() when FidoAssertPtr goes out of scope). Copying
        // into a SecureString immediately keeps that as the one place in this
        // codepath we don't control clearing the same way we control every
        // other buffer in this file.
        SecureString out;
        out.assign(reinterpret_cast<const char*>(secret), secret_len);
        return out;
#else
        throw std::runtime_error(
            "FIDO2 second factor requested, but this build was compiled "
            "without PWMGR_WITH_FIDO2 / libfido2 support.");
#endif
    }
    void enroll(const std::string& vault_path) override {
        vault_path_ = vault_path;
#ifdef PWMGR_WITH_FIDO2
        fido_init(0);
        FidoDevPtr dev = open_sole_fido2_device();

        if (!device_supports_hmac_secret(dev.get()))
            throw std::runtime_error(
                "This authenticator does not advertise the hmac-secret "
                "extension, so it cannot produce the unpredictable per-vault "
                "secret this feature requires. Refusing to enroll rather than "
                "falling back to a device serial number or public key, which "
                "would not be acceptable factor material.");

        FidoCredPtr cred(fido_cred_new());
        if (!cred) throw std::runtime_error("fido_cred_new failed (out of memory)");

        auto cdh = fido2_client_data_hash();
        // Not secret - just distinguishes this vault's "user" entry from any
        // other pwmgr vault enrolled on the same physical key.
        auto user_id = random_bytes(32);

        int r;
        if ((r = fido_cred_set_type(cred.get(), COSE_ES256)) != FIDO_OK ||
            (r = fido_cred_set_clientdata_hash(cred.get(), cdh.data(), cdh.size())) != FIDO_OK ||
            (r = fido_cred_set_rp(cred.get(), FIDO2_RP_ID, FIDO2_RP_NAME)) != FIDO_OK ||
            (r = fido_cred_set_user(cred.get(), user_id.data(), user_id.size(),
                                     "pwmgr", "pwmgr vault", nullptr)) != FIDO_OK ||
            (r = fido_cred_set_extensions(cred.get(), FIDO_EXT_HMAC_SECRET)) != FIDO_OK ||
            // Non-resident: see the design writeup - the credential ID
            // (a device-wrapped handle, not raw key material) is stored in
            // our own sidecar file, so the authenticator doesn't need to
            // remember it in its own limited discoverable-credential slots.
            (r = fido_cred_set_rk(cred.get(), FIDO_OPT_FALSE)) != FIDO_OK)
            throw std::runtime_error(std::string("Setting up FIDO2 credential parameters failed: ") + fido_strerr(r));

        r = fido_dev_make_cred(dev.get(), cred.get(), nullptr);
        if (r == FIDO_ERR_PIN_REQUIRED) {
            SecureString pin = read_password("Authenticator PIN: ");
            r = fido_dev_make_cred(dev.get(), cred.get(), pin.data());
            secure_clear(pin);
        }
        if (r != FIDO_OK)
            throw std::runtime_error(std::string("FIDO2 credential creation failed (was the "
                "authenticator touched in time?): ") + fido_strerr(r));

        const unsigned char* cred_id = fido_cred_id_ptr(cred.get());
        size_t cred_id_len = fido_cred_id_len(cred.get());
        if (!cred_id || cred_id_len == 0)
            throw std::runtime_error("Authenticator returned no credential ID");

        // Caller-chosen selector fed into every future hmac-secret request
        // against this credential - not device output, and not secret
        // itself (it's stored alongside the credential ID); what makes the
        // resulting secret unpredictable is that only the physical
        // authenticator, holding its own internal key, can turn (this
        // credential, this salt) into the actual hmac-secret output.
        auto salt = random_bytes((int)FIDO2_SALT_SIZE);

        std::vector<uint8_t> rp_id_bytes(FIDO2_RP_ID, FIDO2_RP_ID + std::strlen(FIDO2_RP_ID));
        std::vector<uint8_t> cred_id_bytes(cred_id, cred_id + cred_id_len);
        write_metadata_file(metadata_path(), { rp_id_bytes, cred_id_bytes, salt });

        std::cout << "FIDO2 credential enrolled (RP id \"" << FIDO2_RP_ID
                  << "\", non-resident, hmac-secret confirmed).\n";
#else
        throw std::runtime_error(
            "FIDO2 enrollment requested, but this build was compiled "
            "without PWMGR_WITH_FIDO2 / libfido2 support.");
#endif
    }
};

// --- Hardware-backed: TPM2 ----------------------------------------------
// tpm2-tss ESAPI support. Compiled only under PWMGR_WITH_TPM; a build
// without it behaves exactly as before.
#ifdef PWMGR_WITH_TPM

static std::string tpm_rc_str(TSS2_RC rc) {
    const char* s = Tss2_RC_Decode(rc);
    return s ? s : "unknown TPM error";
}

struct EsysCtxDeleter {
    void operator()(ESYS_CONTEXT* c) const { if (c) Esys_Finalize(&c); }
};
using EsysCtxPtr = std::unique_ptr<ESYS_CONTEXT, EsysCtxDeleter>;

// Flushes a transient ESAPI object handle (primary key, loaded sealed
// object, or policy session) when it goes out of scope. Errors from
// Esys_FlushContext are ignored here deliberately - we're almost always
// unwinding from a different error already, and a failed-to-flush handle is
// a session leak, not a security issue (it disappears when the connection/
// process ends either way).
struct TpmHandleGuard {
    ESYS_CONTEXT* ctx;
    ESYS_TR handle;
    TpmHandleGuard(ESYS_CONTEXT* c, ESYS_TR h) : ctx(c), handle(h) {}
    ~TpmHandleGuard() { if (ctx && handle != ESYS_TR_NONE) Esys_FlushContext(ctx, handle); }
    TpmHandleGuard(const TpmHandleGuard&) = delete;
    TpmHandleGuard& operator=(const TpmHandleGuard&) = delete;
};

static EsysCtxPtr tpm_connect() {
    ESYS_CONTEXT* ctx = nullptr;
    // NULL TCTI = tpm2-tss's own default resolution (usually tabrmd if
    // running, else /dev/tpmrm0/tpm0 directly) - same as tpm2-tools' default
    // behavior, not something this program should second-guess.
    TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS)
        throw std::runtime_error("Could not connect to a TPM: " + tpm_rc_str(rc));
    return EsysCtxPtr(ctx);
}

// Deterministic storage-hierarchy primary key: the well-known "RSA2048 SRK"
// template (TCG TPM2.0 provisioning guidance / what `tpm2_createprimary -G
// rsa2048` produces). Given the same physical TPM and the same template,
// Esys_CreatePrimary reproduces the identical key from the TPM's own
// storage-hierarchy seed every time - so nothing about this primary needs
// to be persisted or remembered; enroll() and factor_material() each
// recreate it fresh from scratch.
static TPM2B_PUBLIC tpm_primary_template() {
    TPM2B_PUBLIC t = {};
    t.publicArea.type = TPM2_ALG_RSA;
    t.publicArea.nameAlg = TPM2_ALG_SHA256;
    t.publicArea.objectAttributes =
        TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
        TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH;
    t.publicArea.authPolicy.size = 0;
    t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    t.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    t.publicArea.parameters.rsaDetail.keyBits = 2048;
    t.publicArea.parameters.rsaDetail.exponent = 0;
    t.publicArea.unique.rsa.size = 0;
    return t;
}

static ESYS_TR tpm_load_primary(ESYS_CONTEXT* ctx) {
    TPM2B_PUBLIC pub_template = tpm_primary_template();
    TPM2B_SENSITIVE_CREATE in_sensitive = {};
    TPM2B_DATA outside_info = {};
    TPML_PCR_SELECTION creation_pcr = {};
    ESYS_TR handle = ESYS_TR_NONE;
    TPM2B_PUBLIC* out_public = nullptr;
    TPM2B_CREATION_DATA* creation_data = nullptr;
    TPM2B_DIGEST* creation_hash = nullptr;
    TPMT_TK_CREATION* creation_ticket = nullptr;

    TSS2_RC rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &in_sensitive, &pub_template, &outside_info, &creation_pcr,
        &handle, &out_public, &creation_data, &creation_hash, &creation_ticket);
    if (out_public) Esys_Free(out_public);
    if (creation_data) Esys_Free(creation_data);
    if (creation_hash) Esys_Free(creation_hash);
    if (creation_ticket) Esys_Free(creation_ticket);
    if (rc != TSS2_RC_SUCCESS)
        throw std::runtime_error("Could not create/load the TPM storage primary: " + tpm_rc_str(rc));
    return handle;
}

// Parses PWMGR_TPM_PCR ("7" or "0,7,14" - SHA-256 bank) into a selection.
// Returns an empty (unset) selection when the env var isn't set - the
// default, unbound-to-boot-state path.
static bool tpm_parse_pcr_env(TPML_PCR_SELECTION& sel) {
    const char* env = getenv("PWMGR_TPM_PCR");
    if (!env || !*env) return false;
    sel = {};
    sel.count = 1;
    sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
    sel.pcrSelections[0].sizeofSelect = 3; // 24 PCRs / 8 bits per byte
    std::string s(env);
    std::stringstream ss(s);
    std::string tok;
    bool any = false;
    while (std::getline(ss, tok, ',')) {
        if (tok.empty()) continue;
        int idx = std::atoi(tok.c_str());
        if (idx < 0 || idx >= 24)
            throw std::runtime_error("PWMGR_TPM_PCR: PCR index out of range (0-23): " + tok);
        sel.pcrSelections[0].pcrSelect[idx / 8] |= (1 << (idx % 8));
        any = true;
    }
    if (!any) throw std::runtime_error("PWMGR_TPM_PCR is set but empty/unparseable");
    return true;
}

// Builds the policy digest a PCR-bound sealed object's authPolicy must
// equal, by running Esys_PolicyPCR against a TRIAL session (this asks the
// TPM "what would the resulting policy digest be", without needing the
// current PCR values to already match anything - appropriate at enroll
// time, where we're defining the policy, not satisfying it).
static TPM2B_DIGEST tpm_trial_pcr_policy(ESYS_CONTEXT* ctx, const TPML_PCR_SELECTION& sel) {
    TPMT_SYM_DEF symmetric = { TPM2_ALG_NULL };
    ESYS_TR session = ESYS_TR_NONE;
    TSS2_RC rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        nullptr, TPM2_SE_TRIAL, &symmetric, TPM2_ALG_SHA256, &session);
    if (rc != TSS2_RC_SUCCESS)
        throw std::runtime_error("Could not start TPM trial policy session: " + tpm_rc_str(rc));
    TpmHandleGuard guard(ctx, session);

    rc = Esys_PolicyPCR(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nullptr, &sel);
    if (rc != TSS2_RC_SUCCESS)
        throw std::runtime_error("Esys_PolicyPCR (trial) failed: " + tpm_rc_str(rc));

    TPM2B_DIGEST* digest = nullptr;
    rc = Esys_PolicyGetDigest(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &digest);
    if (rc != TSS2_RC_SUCCESS)
        throw std::runtime_error("Esys_PolicyGetDigest failed: " + tpm_rc_str(rc));
    TPM2B_DIGEST out = *digest;
    Esys_Free(digest);
    return out;
}

static std::vector<uint8_t> tpm_marshal_public(const TPM2B_PUBLIC& pub) {
    std::vector<uint8_t> buf(2048);
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Marshal(&pub, buf.data(), buf.size(), &offset);
    if (rc != TSS2_RC_SUCCESS) throw std::runtime_error("Marshaling TPM public blob failed: " + tpm_rc_str(rc));
    buf.resize(offset);
    return buf;
}
static std::vector<uint8_t> tpm_marshal_private(const TPM2B_PRIVATE& priv) {
    std::vector<uint8_t> buf(2048);
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PRIVATE_Marshal(&priv, buf.data(), buf.size(), &offset);
    if (rc != TSS2_RC_SUCCESS) throw std::runtime_error("Marshaling TPM private blob failed: " + tpm_rc_str(rc));
    buf.resize(offset);
    return buf;
}
static TPM2B_PUBLIC tpm_unmarshal_public(const std::vector<uint8_t>& buf) {
    TPM2B_PUBLIC pub = {};
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(buf.data(), buf.size(), &offset, &pub);
    if (rc != TSS2_RC_SUCCESS) throw std::runtime_error("Unmarshaling TPM public blob failed (corrupt sidecar file?): " + tpm_rc_str(rc));
    return pub;
}
static TPM2B_PRIVATE tpm_unmarshal_private(const std::vector<uint8_t>& buf) {
    TPM2B_PRIVATE priv = {};
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(buf.data(), buf.size(), &offset, &priv);
    if (rc != TSS2_RC_SUCCESS) throw std::runtime_error("Unmarshaling TPM private blob failed (corrupt sidecar file?): " + tpm_rc_str(rc));
    return priv;
}
#endif // PWMGR_WITH_TPM

class TPMProvider : public SecondFactorProvider {
    std::string vault_path_; // see FIDO2Provider's comment above - same reasoning
public:
    explicit TPMProvider(std::string vault_path = "") : vault_path_(std::move(vault_path)) {}
    std::string metadata_path() const { return provider_metadata_path(vault_path_, ".tpm"); }
    std::string name() const override { return "tpm"; }
    bool available() const override {
#ifdef PWMGR_WITH_TPM
        // Compiled with tpm2-tss support. As with FIDO2Provider::available(),
        // deliberately not also checking "can we reach a TPM right now" here -
        // enroll()/factor_material() give a specific error for that instead
        // of the generic "this build has no TPM support" select_provider()
        // gives when this returns false.
        return true;
#else
        return false;
#endif
    }
    SecureString factor_material() const override {
#ifdef PWMGR_WITH_TPM
        auto fields = read_metadata_file(metadata_path());
        if (fields.size() != 3)
            throw std::runtime_error("Malformed TPM metadata: " + metadata_path());
        TPM2B_PUBLIC pub = tpm_unmarshal_public(fields[0]);
        TPM2B_PRIVATE priv = tpm_unmarshal_private(fields[1]);
        const std::vector<uint8_t>& pcr_bytes = fields[2]; // empty = no PCR policy was used

        EsysCtxPtr ctx = tpm_connect();
        ESYS_TR primary = tpm_load_primary(ctx.get());
        TpmHandleGuard primary_guard(ctx.get(), primary);

        ESYS_TR obj = ESYS_TR_NONE;
        TSS2_RC rc = Esys_Load(ctx.get(), primary, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                &priv, &pub, &obj);
        if (rc != TSS2_RC_SUCCESS)
            throw std::runtime_error(
                "Could not load the sealed secret into this TPM - this almost "
                "always means the TPM was replaced/reset since enrollment, "
                "which is unrecoverable by design (see the design notes for "
                "'gentpm'): " + tpm_rc_str(rc));
        TpmHandleGuard obj_guard(ctx.get(), obj);

        ESYS_TR auth_session = ESYS_TR_PASSWORD; // plain empty-password auth by default
        std::unique_ptr<TpmHandleGuard> pcr_session_guard;
        if (!pcr_bytes.empty()) {
            // PCR-bound path (opt-in, advanced): reconstruct the same PCR
            // selection used at enroll time and satisfy the object's policy
            // with a REAL (not trial) session against the TPM's *current*
            // PCR values. If those values have changed since enrollment
            // (firmware/kernel/bootloader update, etc.) this legitimately
            // fails - that is the feature working as designed, not a bug,
            // but it is the sharp edge PCR binding trades in for the extra
            // boot-state guarantee. This path is less exercised than the
            // default no-PCR path; test carefully against real hardware
            // before relying on it.
            TPML_PCR_SELECTION sel = {};
            size_t off = 0;
            uint8_t count = pcr_bytes.size() > 0 ? pcr_bytes[0] : 0;
            // pcr_bytes layout: [count][sizeofSelect][pcrSelect bytes...] per
            // selection, matching TPML_PCR_SELECTION's own shape - written by
            // enroll() below via the same marshal/unmarshal helpers, not
            // hand-rolled here, to avoid two independent encodings drifting.
            (void)count; (void)off; // pcr_bytes is itself Tss2_MU-marshaled; see enroll()
            TSS2_RC mrc = Tss2_MU_TPML_PCR_SELECTION_Unmarshal(pcr_bytes.data(), pcr_bytes.size(), &off, &sel);
            if (mrc != TSS2_RC_SUCCESS)
                throw std::runtime_error("Malformed PCR selection in TPM metadata: " + tpm_rc_str(mrc));

            TPMT_SYM_DEF symmetric = { TPM2_ALG_NULL };
            ESYS_TR session = ESYS_TR_NONE;
            rc = Esys_StartAuthSession(ctx.get(), ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                nullptr, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, &session);
            if (rc != TSS2_RC_SUCCESS)
                throw std::runtime_error("Could not start TPM policy session: " + tpm_rc_str(rc));
            pcr_session_guard = std::make_unique<TpmHandleGuard>(ctx.get(), session);

            rc = Esys_PolicyPCR(ctx.get(), session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nullptr, &sel);
            if (rc != TSS2_RC_SUCCESS)
                throw std::runtime_error(
                    "PCR policy not satisfied - current boot state doesn't match "
                    "what this vault was enrolled against: " + tpm_rc_str(rc));
            auth_session = session;
        }

        TPM2B_SENSITIVE_DATA* out_data = nullptr;
        rc = Esys_Unseal(ctx.get(), obj, auth_session, ESYS_TR_NONE, ESYS_TR_NONE, &out_data);
        if (rc != TSS2_RC_SUCCESS)
            throw std::runtime_error("TPM unseal failed: " + tpm_rc_str(rc));

        SecureString out;
        out.assign(reinterpret_cast<const char*>(out_data->buffer), out_data->size);
        // out_data is ESAPI-owned memory (Esys_Free'd, not necessarily
        // zeroed) - same caveat as FIDO2Provider::factor_material()'s
        // hmac-secret buffer: this copy is the one spot in this path we
        // don't control clearing the way we do the rest of this file.
        Esys_Free(out_data);
        return out;
#else
        throw std::runtime_error(
            "TPM second factor requested, but this build was compiled "
            "without PWMGR_WITH_TPM / tpm2-tss support.");
#endif
    }
    void enroll(const std::string& vault_path) override {
        vault_path_ = vault_path;
#ifdef PWMGR_WITH_TPM
        EsysCtxPtr ctx = tpm_connect();
        ESYS_TR primary = tpm_load_primary(ctx.get());
        TpmHandleGuard primary_guard(ctx.get(), primary);

        // The secret itself: generated locally with the same RNG used for
        // keyfiles, not derived from or by the TPM. The TPM's only job is to
        // refuse to ever hand these bytes back to anything other than
        // itself (plus, optionally, the right boot state).
        auto secret = random_bytes(32);

        TPM2B_PUBLIC seal_template = {};
        seal_template.publicArea.type = TPM2_ALG_KEYEDHASH;
        seal_template.publicArea.nameAlg = TPM2_ALG_SHA256;
        seal_template.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
        seal_template.publicArea.unique.keyedHash.size = 0;

        TPML_PCR_SELECTION pcr_sel = {};
        bool use_pcr = tpm_parse_pcr_env(pcr_sel);
        if (use_pcr) {
            // Policy-only auth: no password fallback once PCR binding is on,
            // otherwise the password path would defeat the point of it.
            seal_template.publicArea.objectAttributes =
                TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT;
            seal_template.publicArea.authPolicy = tpm_trial_pcr_policy(ctx.get(), pcr_sel);
        } else {
            seal_template.publicArea.objectAttributes =
                TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_USERWITHAUTH;
            seal_template.publicArea.authPolicy.size = 0;
        }

        TPM2B_SENSITIVE_CREATE in_sensitive = {};
        in_sensitive.sensitive.userAuth.size = 0; // empty password auth (or none, if policy-only)
        in_sensitive.sensitive.data.size = (UINT16)secret.size();
        std::memcpy(in_sensitive.sensitive.data.buffer, secret.data(), secret.size());

        TPM2B_DATA outside_info = {};
        TPML_PCR_SELECTION creation_pcr = {};
        TPM2B_PRIVATE* out_private = nullptr;
        TPM2B_PUBLIC* out_public = nullptr;
        TPM2B_CREATION_DATA* creation_data = nullptr;
        TPM2B_DIGEST* creation_hash = nullptr;
        TPMT_TK_CREATION* creation_ticket = nullptr;

        TSS2_RC rc = Esys_Create(ctx.get(), primary, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &in_sensitive, &seal_template, &outside_info, &creation_pcr,
            &out_private, &out_public, &creation_data, &creation_hash, &creation_ticket);

        secure_clear(secret); // handed to the TPM; no longer needed here

        if (creation_data) Esys_Free(creation_data);
        if (creation_hash) Esys_Free(creation_hash);
        if (creation_ticket) Esys_Free(creation_ticket);
        if (rc != TSS2_RC_SUCCESS) {
            if (out_private) Esys_Free(out_private);
            if (out_public) Esys_Free(out_public);
            throw std::runtime_error("Sealing secret to TPM failed: " + tpm_rc_str(rc));
        }

        auto pub_bytes = tpm_marshal_public(*out_public);
        auto priv_bytes = tpm_marshal_private(*out_private);
        Esys_Free(out_private);
        Esys_Free(out_public);

        std::vector<uint8_t> pcr_bytes;
        if (use_pcr) {
            pcr_bytes.resize(512);
            size_t off = 0;
            TSS2_RC mrc = Tss2_MU_TPML_PCR_SELECTION_Marshal(&pcr_sel, pcr_bytes.data(), pcr_bytes.size(), &off);
            if (mrc != TSS2_RC_SUCCESS)
                throw std::runtime_error("Marshaling PCR selection failed: " + tpm_rc_str(mrc));
            pcr_bytes.resize(off);
        }

        write_metadata_file(metadata_path(), { pub_bytes, priv_bytes, pcr_bytes });

        std::cout << "TPM-sealed credential enrolled"
                  << (use_pcr ? " (PCR-bound - see help before relying on this).\n"
                              : " (no PCR binding - unlocks regardless of boot state).\n");
#else
        throw std::runtime_error(
            "TPM enrollment requested, but this build was compiled "
            "without PWMGR_WITH_TPM / tpm2-tss support.");
#endif
    }
};

// Picks a provider for a given vault. Sidecar-metadata presence is now the
// source of truth for FIDO2/TPM - once a vault is enrolled (step 2/3), it's
// found automatically without relying on the caller's environment matching
// what save() used. Precedence: explicit keyfile argument > enrolled FIDO2
// sidecar > enrolled TPM sidecar > PWMGR_FIDO2/PWMGR_TPM (manual override,
// only meaningful before a sidecar exists, e.g. immediately after enroll()
// but before the first save()) > PWMGR_KEYFILE > none. An explicit request
// for a provider that isn't available() fails loudly instead of silently
// degrading to password-only.
static std::unique_ptr<SecondFactorProvider> select_provider(const std::string& explicit_keyfile,
                                                               const std::string& vault_path) {
    if (!explicit_keyfile.empty())
        return std::make_unique<KeyfileProvider>(explicit_keyfile);

    std::string fido2_meta = provider_metadata_path(vault_path, ".fido2");
    std::string tpm_meta   = provider_metadata_path(vault_path, ".tpm");
    bool has_fido2_meta = fs::exists(fido2_meta);
    bool has_tpm_meta   = fs::exists(tpm_meta);
    if (has_fido2_meta && has_tpm_meta)
        throw std::runtime_error(
            "Both FIDO2 and TPM metadata exist for this vault - set "
            "PWMGR_FIDO2=1 or PWMGR_TPM=1 to say which one to use.");

    if (has_fido2_meta || getenv("PWMGR_FIDO2")) {
        auto p = std::make_unique<FIDO2Provider>(vault_path);
        if (!p->available())
            throw std::runtime_error("This vault requires FIDO2 to unlock, but this build has no FIDO2 support.");
        if (!has_fido2_meta)
            throw std::runtime_error("PWMGR_FIDO2 is set, but no FIDO2 credential is enrolled for this vault yet - run 'genfido2' first.");
        return p;
    }
    if (has_tpm_meta || getenv("PWMGR_TPM")) {
        auto p = std::make_unique<TPMProvider>(vault_path);
        if (!p->available())
            throw std::runtime_error("This vault requires a TPM to unlock, but this build has no TPM support.");
        if (!has_tpm_meta)
            throw std::runtime_error("PWMGR_TPM is set, but no TPM credential is enrolled for this vault yet - run 'gentpm' first.");
        return p;
    }
    const char* kf = getenv("PWMGR_KEYFILE");
    if (kf && *kf) return std::make_unique<KeyfileProvider>(kf);
    return std::make_unique<PasswordOnlyProvider>();
}

// Mixes whatever the given provider returns into the master password. This
// is the primitive both call sites funnel through: Vault::save/load's
// string/vault_path overload just resolves a provider via select_provider()
// first and delegates here; a caller that already has a specific provider
// in hand (e.g. cmd_genfido2's rebind step, right after enroll()) can call
// this overload directly instead of going through env-var/sidecar guessing.
static SecureString combined_secret(const SecureString& master, SecondFactorProvider& provider) {
    SecureString material = provider.factor_material();
    if (material.empty()) return master;
    SecureString combined = master;
    combined.push_back('\x1f');
    combined.append(material.data(), material.size());
    secure_clear(material);
    return combined;
}

static SecureString combined_secret(const SecureString& master, const std::string& explicit_keyfile,
                                     const std::string& vault_path) {
    auto provider = select_provider(explicit_keyfile, vault_path);
    return combined_secret(master, *provider);
}

SecureVector<uint8_t> derive_keys(const SecureString& password, const uint8_t* salt,
                         uint32_t t, uint32_t m, uint32_t p,
                         size_t out_len = KDF_OUTPUT_SIZE) {
    SecureVector<uint8_t> out(out_len);
    int rc = argon2id_hash_raw(t, m, p,
        password.data(), password.size(),
        salt, SALT_SIZE, out.data(), out_len);
    if (rc != ARGON2_OK)
        throw std::runtime_error(std::string("Argon2id: ") + argon2_error_message(rc));
    return out;
}

struct GcmResult { std::vector<uint8_t> ciphertext, tag; };

GcmResult gcm_encrypt(const uint8_t* pt, size_t pt_len, const uint8_t* key,
                      const uint8_t* nonce, const uint8_t* aad, size_t aad_len) {
    CipherCtx ctx; int len = 0;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, nonce) != 1)
        throw std::runtime_error("GCM encrypt init failed");
    if (aad_len > 0 && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad, (int)aad_len) != 1)
        throw std::runtime_error("GCM AAD failed");
    std::vector<uint8_t> ct(pt_len); int tot = 0;
    if (EVP_EncryptUpdate(ctx.get(), ct.data(), &len, pt, (int)pt_len) != 1)
        throw std::runtime_error("GCM encrypt failed");
    tot = len;
    if (EVP_EncryptFinal_ex(ctx.get(), ct.data() + tot, &len) != 1)
        throw std::runtime_error("GCM final failed");
    ct.resize(tot + len);
    std::vector<uint8_t> tag(GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data()) != 1)
        throw std::runtime_error("GCM get tag failed");
    return {ct, tag};
}

std::vector<uint8_t> gcm_decrypt(const uint8_t* ct, size_t ct_len, const uint8_t* key,
                                  const uint8_t* nonce, const uint8_t* tag,
                                  const uint8_t* aad, size_t aad_len) {
    CipherCtx ctx; int len = 0;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, nonce) != 1)
        throw std::runtime_error("GCM decrypt init failed");
    if (aad_len > 0 && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad, (int)aad_len) != 1)
        throw std::runtime_error("GCM AAD failed");
    std::vector<uint8_t> pt(ct_len); int tot = 0;
    if (EVP_DecryptUpdate(ctx.get(), pt.data(), &len, ct, (int)ct_len) != 1)
        throw std::runtime_error("GCM decrypt failed");
    tot = len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
                             const_cast<uint8_t*>(tag)) != 1)
        throw std::runtime_error("GCM set tag failed");
    if (EVP_DecryptFinal_ex(ctx.get(), pt.data() + tot, &len) <= 0)
        throw std::runtime_error("Authentication failed - wrong password or tampered vault");
    pt.resize(tot + len);
    return pt;
}

static void write_u16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back((v>>8)&0xFF); b.push_back(v&0xFF);
}
static void write_u32(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back((v>>24)&0xFF); b.push_back((v>>16)&0xFF);
    b.push_back((v>>8)&0xFF);  b.push_back(v&0xFF);
}
static void write_field(std::vector<uint8_t>& b, const std::string& s) {
    if (s.size() > MAX_FIELD_BYTES) throw std::runtime_error("Field too large");
    write_u16(b, (uint16_t)s.size());
    b.insert(b.end(), s.begin(), s.end());
}
static void write_field(std::vector<uint8_t>& b, const SecureString& s) {
    if (s.size() > MAX_FIELD_BYTES) throw std::runtime_error("Field too large");
    write_u16(b, (uint16_t)s.size());
    b.insert(b.end(), s.data(), s.data() + s.size());
}
static uint16_t read_u16(const uint8_t* p) { return (uint16_t)(((uint16_t)p[0]<<8)|p[1]); }
static uint32_t read_u32(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];
}

struct PasswordEntry {
    std::string name, username, url, notes, created, modified;
    SecureString password;
};

static std::string current_timestamp() {
    time_t now = time(nullptr); char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return buf;
}

std::vector<uint8_t> serialize(const std::vector<PasswordEntry>& entries) {
    std::vector<uint8_t> b;
    write_u32(b, (uint32_t)entries.size());
    for (const auto& e : entries) {
        write_field(b, e.name);   write_field(b, e.username);
        write_field(b, e.password); write_field(b, e.url);
        write_field(b, e.notes);  write_field(b, e.created);
        write_field(b, e.modified);
    }
    return b;
}

std::vector<PasswordEntry> deserialize(const std::vector<uint8_t>& buf) {
    if (buf.size() < 4) throw std::runtime_error("Vault data too short");
    uint32_t count = read_u32(buf.data());
    if (count > MAX_ENTRIES) throw std::runtime_error("Entry count exceeds limit");
    std::vector<PasswordEntry> entries;
    size_t pos = 4;
    auto rf = [&](std::string& out) {
        if (pos + 2 > buf.size()) throw std::runtime_error("Truncated vault");
        uint16_t len = read_u16(buf.data() + pos); pos += 2;
        if (pos + len > buf.size()) throw std::runtime_error("Truncated field");
        out.assign(reinterpret_cast<const char*>(buf.data() + pos), len);
        pos += len;
    };
    auto rf_secure = [&](SecureString& out) {
        if (pos + 2 > buf.size()) throw std::runtime_error("Truncated vault");
        uint16_t len = read_u16(buf.data() + pos); pos += 2;
        if (pos + len > buf.size()) throw std::runtime_error("Truncated field");
        out.assign(reinterpret_cast<const char*>(buf.data() + pos), len);
        pos += len;
    };
    for (uint32_t i = 0; i < count; ++i) {
        PasswordEntry e;
        rf(e.name); rf(e.username); rf_secure(e.password);
        rf(e.url);  rf(e.notes);    rf(e.created); rf(e.modified);
        entries.push_back(std::move(e));
    }
    return entries;
}

// Writes `data` to `path` atomically and with 0600 permissions set at
// creation time (not chmod'd afterward, which leaves a brief window where
// the file is readable per the process umask). Uses write-to-temp +
// fsync + rename so a crash or power loss mid-write can't corrupt or
// truncate the existing vault - you either get the old file or the new
// one, never a half-written one.
static void write_file_atomic(const std::string& path, const uint8_t* data, size_t len) {
    auto rnd = random_bytes(4);
    uint32_t suffix = (rnd[0] << 24) | (rnd[1] << 16) | (rnd[2] << 8) | rnd[3];
    std::string tmp = path + ".tmp." + std::to_string(getpid()) + "." + std::to_string(suffix);
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) throw std::runtime_error("Cannot create temp file for write: " + tmp);
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);
        if (n < 0) { close(fd); unlink(tmp.c_str()); throw std::runtime_error("Write failed: " + path); }
        written += (size_t)n;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmp.c_str()); throw std::runtime_error("fsync failed: " + path); }
    close(fd);
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        throw std::runtime_error("Rename failed: " + path);
    }
    // fsync(temp) above guarantees the file's *contents* survive a crash.
    // The rename() itself is a directory-metadata change, and on many
    // filesystems that update can still be lost on power loss unless the
    // containing directory is fsync'd too. Best-effort: some filesystems
    // don't support fsync on a directory fd, so failures here are ignored
    // rather than treated as fatal - the file itself is still intact.
    std::string dir = fs::path(path).parent_path().string();
    if (dir.empty()) dir = ".";
    int dfd = open(dir.c_str(), O_RDONLY);
    if (dfd >= 0) { fsync(dfd); close(dfd); }
}

// ---------------------------------------------------------------------------
// Provider metadata file format
//
// A tiny reusable length-prefixed container for the *public* metadata a
// hardware-backed provider needs to find/use its credential again later:
//   FIDO2: RP id, credential id, hmac-secret salt, (optional AAGUID label)
//   TPM:   TPM2B_PUBLIC blob, TPM2B_PRIVATE blob, (optional PCR selection)
// Reuses the same write_u32/write_u16 primitives the vault's own entry
// serialization already uses, rather than each provider inventing its own
// file layout, and the same write_file_atomic() the vault file itself uses
// (temp+fsync+rename, 0600 at creation) so a crash mid-enroll can't leave a
// half-written or world-readable sidecar file.
//
// Every field stored here is meaningless to an attacker who doesn't also
// have the physical authenticator/TPM - none of it needs mlock/secure_zero
// treatment, same as the vault header's salt/nonce.
// ---------------------------------------------------------------------------
static void write_metadata_file(const std::string& path, const std::vector<std::vector<uint8_t>>& fields) {
    std::vector<uint8_t> b;
    write_u32(b, (uint32_t)fields.size());
    for (const auto& f : fields) {
        if (f.size() > MAX_FIELD_BYTES) throw std::runtime_error("Metadata field too large: " + path);
        write_u16(b, (uint16_t)f.size());
        b.insert(b.end(), f.begin(), f.end());
    }
    write_file_atomic(path, b.data(), b.size());
}

static std::vector<std::vector<uint8_t>> read_metadata_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot read metadata file: " + path);
    std::ostringstream ss; ss << f.rdbuf();
    std::string raw = ss.str();
    const uint8_t* buf = reinterpret_cast<const uint8_t*>(raw.data());
    size_t len = raw.size();
    if (len < 4) throw std::runtime_error("Truncated metadata file: " + path);
    uint32_t count = read_u32(buf);
    std::vector<std::vector<uint8_t>> fields;
    size_t pos = 4;
    for (uint32_t i = 0; i < count; ++i) {
        if (pos + 2 > len) throw std::runtime_error("Truncated metadata field: " + path);
        uint16_t flen = read_u16(buf + pos); pos += 2;
        if (pos + flen > len) throw std::runtime_error("Truncated metadata field: " + path);
        fields.emplace_back(buf + pos, buf + pos + flen);
        pos += flen;
    }
    return fields;
}

static std::string attempts_path() {
    const char* h = getenv("HOME");
    return std::string(h ? h : ".") + "/" + ATTEMPTS_FILE;
}
static int read_attempts() {
    std::ifstream f(attempts_path()); int n = 0; f >> n;
    return std::min(n, MAX_FAILED_ATTEMPTS);
}
static void write_attempts(int n) {
    std::string s = std::to_string(n);
    write_file_atomic(attempts_path(), reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
static void on_failed_unlock() {
    int a = read_attempts() + 1; write_attempts(a);
    int ms = std::min(BASE_DELAY_MS * (1 << std::min(a-1, 6)), MAX_DELAY_MS);
    std::cerr << "   (Waiting " << ms << "ms - attempt " << a << ")\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}
static void on_success() { write_attempts(0); }

class Vault {
public:
    std::string vault_path;
    std::vector<PasswordEntry> entries;

    Vault() {
        const char* h = getenv("HOME");
        vault_path = std::string(h ? h : ".") + "/" + VAULT_FILENAME;
    }
    bool exists() const { return fs::exists(vault_path); }

    // Several command handlers below call load() and then return early on
    // a validation failure (name not found, confirmation declined, etc.)
    // without explicitly calling wipe() first, which left decrypted
    // plaintext entries sitting in `entries` instead of being zeroed. This
    // destructor is the safety net: however a Vault leaves scope - normal
    // return, early return, or an exception unwinding through it - the
    // plaintext gets wiped. It doesn't replace the explicit wipe() calls
    // already in the success paths (those clear things immediately rather
    // than waiting for the object to go out of scope).
    ~Vault() { wipe(); }

    void wipe() {
        for (auto& e : entries) { secure_clear(e.password); secure_clear(e.name); secure_clear(e.username); }
        entries.clear();
    }

    // Resolves a provider from the keyfile arg / sidecar metadata / env vars
    // (see select_provider()) and delegates. This is the overload every
    // existing call site already uses and keeps using unchanged.
    void save(const SecureString& master, const std::string& keyfile_path = "") {
        auto provider = select_provider(keyfile_path, vault_path);
        save(master, *provider);
    }

    // Takes an already-resolved provider directly - used when a caller
    // (e.g. cmd_genfido2's rebind step) needs to bind to a *specific*
    // provider instance right after enroll(), rather than have it
    // re-guessed from env vars/sidecar files a moment later.
    void save(const SecureString& master, SecondFactorProvider& provider) {
        auto salt  = random_bytes(SALT_SIZE);
        auto nonce = random_bytes(GCM_NONCE_SIZE);
        auto plain = serialize(entries);
        if (mlock(plain.data(), plain.size()) != 0) warn_mlock_failure();
        SecureString secret = combined_secret(master, provider);
        auto keys = derive_keys(secret, salt.data(), ARGON2_T_COST, ARGON2_M_COST, ARGON2_PARALLELISM);
        secure_clear(secret);

        std::vector<uint8_t> hdr;
        hdr.insert(hdr.end(), VAULT_MAGIC, VAULT_MAGIC+4);
        write_u32(hdr, VAULT_VERSION);
        write_u32(hdr, KDF_ID_ARGON2ID);
        write_u32(hdr, CIPHER_ID_AES_256_GCM);
        write_u32(hdr, VAULT_FLAGS_NONE);
        hdr.insert(hdr.end(), salt.begin(), salt.end());
        write_u32(hdr, ARGON2_T_COST); write_u32(hdr, ARGON2_M_COST); write_u32(hdr, ARGON2_PARALLELISM);
        hdr.insert(hdr.end(), nonce.begin(), nonce.end());

        auto res = gcm_encrypt(plain.data(), plain.size(), keys.data(),
                               nonce.data(), hdr.data(), hdr.size());
        secure_zero(plain.data(), plain.size()); munlock(plain.data(), plain.size());

        std::vector<uint8_t> out;
        out.insert(out.end(), hdr.begin(), hdr.end());
        out.insert(out.end(), res.tag.begin(), res.tag.end());
        const uint8_t csz[4] = {
            (uint8_t)(res.ciphertext.size()>>24),(uint8_t)(res.ciphertext.size()>>16),
            (uint8_t)(res.ciphertext.size()>>8), (uint8_t)(res.ciphertext.size())
        };
        out.insert(out.end(), csz, csz+4);
        out.insert(out.end(), res.ciphertext.begin(), res.ciphertext.end());
        // Atomic write with 0600 set at creation time: either the old vault
        // survives untouched or the new one lands in full - never a
        // half-written or momentarily world-readable file.
        write_file_atomic(vault_path, out.data(), out.size());
        secure_zero(out.data(), out.size());
    }

    void load(const SecureString& master, const std::string& keyfile_path = "") {
        auto provider = select_provider(keyfile_path, vault_path);
        load(master, *provider);
    }

    void load(const SecureString& master, SecondFactorProvider& provider) {
        // O_NOFOLLOW makes the kernel itself refuse to open the path if it's
        // a symlink, atomically - no separate lstat-then-open race for an
        // attacker (e.g. another local user, or malware) to win by swapping
        // ~/.pwmgr_vault for a symlink to a file of their choosing between
        // our check and our open.
        int fd = open(vault_path.c_str(), O_RDONLY | O_NOFOLLOW);
        if (fd < 0) {
            if (errno == ELOOP)
                throw std::runtime_error("Refusing to open '" + vault_path +
                    "': it is a symlink, not a regular file. This can be used to "
                    "trick the program into reading a different file - remove it "
                    "and restore the real vault from backup.");
            throw std::runtime_error("Vault not found. Run 'init' first.");
        }
        struct stat st{};
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            close(fd);
            throw std::runtime_error("Refusing to open '" + vault_path + "': not a regular file.");
        }
        if (st.st_uid != geteuid()) {
            close(fd);
            throw std::runtime_error("Refusing to open '" + vault_path +
                "': not owned by the current user.");
        }
        if (st.st_mode & (S_IRWXG | S_IRWXO)) {
            close(fd);
            throw std::runtime_error("Refusing to open '" + vault_path +
                "': permissions are too open (expected 0600). Run: chmod 600 '" + vault_path + "'");
        }
        auto cr = [&](void* dst, size_t n, const char* fld) {
            size_t got = 0;
            while (got < n) {
                ssize_t r = read(fd, reinterpret_cast<uint8_t*>(dst) + got, n - got);
                if (r <= 0) { close(fd); throw std::runtime_error(std::string("Truncated vault: ") + fld); }
                got += (size_t)r;
            }
        };
        char magic[4]; cr(magic, 4, "magic");
        if (memcmp(magic, VAULT_MAGIC, 4) != 0) { close(fd); throw std::runtime_error("Not a vault file"); }
        uint8_t ver[4]; cr(ver, 4, "version");
        uint32_t ver_num = read_u32(ver);
        if (ver_num != VAULT_VERSION && ver_num != VAULT_VERSION_V3 && ver_num != VAULT_VERSION_LEGACY_KDF64) {
            close(fd); throw std::runtime_error("Unsupported version");
        }
        // v2/v3 vaults have no explicit ids in the header - both always meant
        // Argon2id -> AES-256-GCM, so that's what we assume for them. v4+
        // vaults name the KDF/cipher explicitly; a future vault that names an
        // id this binary doesn't recognize fails closed here rather than
        // being silently (mis)decrypted as if it were Argon2id/AES-GCM.
        uint32_t kdf_id = KDF_ID_ARGON2ID, cipher_id = CIPHER_ID_AES_256_GCM, flags = VAULT_FLAGS_NONE;
        uint8_t idbuf[12];
        bool has_explicit_ids = (ver_num == VAULT_VERSION);
        if (has_explicit_ids) {
            cr(idbuf, 12, "crypto ids");
            kdf_id    = read_u32(idbuf);
            cipher_id = read_u32(idbuf+4);
            flags     = read_u32(idbuf+8);
            if (kdf_id != KDF_ID_ARGON2ID) {
                close(fd); throw std::runtime_error("Unsupported KDF id in vault header - this vault needs a newer build.");
            }
            if (cipher_id != CIPHER_ID_AES_256_GCM) {
                close(fd); throw std::runtime_error("Unsupported cipher id in vault header - this vault needs a newer build.");
            }
            if (flags != VAULT_FLAGS_NONE) {
                close(fd); throw std::runtime_error("Unrecognized vault flags - this vault needs a newer build.");
            }
        }
        uint8_t salt[SALT_SIZE]; cr(salt, SALT_SIZE, "salt");
        uint8_t params[12]; cr(params, 12, "params");
        uint32_t t=read_u32(params), m=read_u32(params+4), p=read_u32(params+8);
        uint8_t nonce[GCM_NONCE_SIZE]; cr(nonce, GCM_NONCE_SIZE, "nonce");
        uint8_t tag[GCM_TAG_SIZE]; cr(tag, GCM_TAG_SIZE, "tag");
        uint8_t csz[4]; cr(csz, 4, "ct size");
        uint32_t ct_size = read_u32(csz);
        if (ct_size == 0 || ct_size > MAX_VAULT_BYTES) { close(fd); throw std::runtime_error("Invalid ciphertext size"); }
        std::vector<uint8_t> ct(ct_size); cr(ct.data(), ct_size, "ciphertext");
        close(fd); // done with the file; don't hold it open through key derivation/decryption

        // v2 vaults derived a 64-byte Argon2 output; that length is baked into
        // Argon2's internal hashing, so we must re-request the same length or
        // the derived key won't match, even with the right password.
        size_t kdf_out_len = (ver_num == VAULT_VERSION_LEGACY_KDF64) ? 64 : KDF_OUTPUT_SIZE;
        SecureString secret = combined_secret(master, provider);
        auto keys = derive_keys(secret, salt, t, m, p, kdf_out_len);
        secure_clear(secret);
        std::vector<uint8_t> aad;
        aad.insert(aad.end(), VAULT_MAGIC, VAULT_MAGIC+4);
        aad.insert(aad.end(), ver, ver+4);
        if (has_explicit_ids) aad.insert(aad.end(), idbuf, idbuf+12);
        aad.insert(aad.end(), salt, salt+SALT_SIZE);
        aad.insert(aad.end(), params, params+12);
        aad.insert(aad.end(), nonce, nonce+GCM_NONCE_SIZE);

        std::vector<uint8_t> plain;
        try {
            plain = gcm_decrypt(ct.data(), ct_size, keys.data(), nonce, tag, aad.data(), aad.size());
        } catch (...) { on_failed_unlock(); throw; }
        on_success();
        entries = deserialize(plain);
        secure_zero(plain.data(), plain.size());
    }

    PasswordEntry* find(const std::string& name) {
        auto lo = low(name);
        for (auto& e : entries) if (low(e.name) == lo) return &e;
        return nullptr;
    }

    std::vector<std::pair<int,PasswordEntry*>> search_fuzzy(const std::string& term) {
        std::vector<std::pair<int,PasswordEntry*>> r;
        std::string lo = low(term);
        for (auto& e : entries) {
            int d = lev(lo, low(e.name));
            if (d <= 3 || low(e.name).find(lo)!=std::string::npos ||
                low(e.username).find(lo)!=std::string::npos ||
                low(e.url).find(lo)!=std::string::npos ||
                low(e.notes).find(lo)!=std::string::npos)
                r.push_back({d, &e});
        }
        std::sort(r.begin(), r.end(), [](const auto& a, const auto& b){ return a.first < b.first; });
        return r;
    }

private:
    static std::string low(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower); return s;
    }
    static int lev(const std::string& a, const std::string& b) {
        size_t m=a.size(), n=b.size();
        std::vector<std::vector<int>> dp(m+1, std::vector<int>(n+1));
        for (size_t i=0;i<=m;++i) dp[i][0]=(int)i;
        for (size_t j=0;j<=n;++j) dp[0][j]=(int)j;
        for (size_t i=1;i<=m;++i)
            for (size_t j=1;j<=n;++j) {
                int c=(a[i-1]==b[j-1])?0:1;
                dp[i][j]=std::min({dp[i-1][j]+1,dp[i][j-1]+1,dp[i-1][j-1]+c});
            }
        return dp[m][n];
    }
};

// Returns SecureString rather than std::string. The character set itself
// (cs) isn't sensitive - it's the same 90-odd printable characters for
// everyone - but the candidate password built up char-by-char is exactly
// the kind of value this file otherwise never lets touch a plain
// std::string: every SecureString::push_back() below reallocates via
// SecureVector, which zeroes the previous backing buffer on release()
// instead of leaving grown-past copies sitting unzeroed on the heap the
// way std::string's reallocation would.
SecureString generate_password(int length = 20, bool symbols = true) {
    std::string cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (symbols) cs += "!@#$%^&*()_+-=[]{}|;:,.<>?";
    int sz = (int)cs.size(), rng = (256/sz)*sz;
    SecureString pw;
    while ((int)pw.size() < length) {
        auto batch = random_bytes(length*2);
        for (uint8_t b : batch) { if ((int)pw.size()>=length) break; if (b<rng) pw.push_back(cs[b%sz]); }
    }
    return pw;
}

// popen() only fails here if /bin/sh itself can't be spawned - it succeeds
// even when the tool the shell command names (xclip/xsel) doesn't exist,
// since that failure happens later, inside the child shell. So "popen
// returned non-null" is NOT the same as "the clipboard tool ran". The
// only reliable signal is the exit status pclose() hands back once the
// child (and the tool it tried to exec) has finished.
static bool run_clipboard_cmd(const std::string& shell_cmd, const char* data, size_t len) {
    FILE* pipe = popen(shell_cmd.c_str(), "w");
    if (!pipe) return false;
    if (len > 0) fwrite(data, 1, len, pipe);
    int status = pclose(pipe);
    return status == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// Takes the secret by SecureString rather than std::string so the clipboard
// path never makes its own unlocked, unzeroed copy of the password just to
// hand it to popen() - it's written straight out of the locked buffer.
void copy_to_clipboard(const SecureString& text) {
    bool ok = run_clipboard_cmd("xclip -selection clipboard 2>/dev/null", text.data(), text.size()) ||
              run_clipboard_cmd("xsel --clipboard --input 2>/dev/null", text.data(), text.size());
    if (!ok) { std::cout << "   (Clipboard unavailable - install xclip or xsel)\n"; return; }
    pid_t pid = fork();
    if (pid == 0) {
        sleep(CLIPBOARD_CLEAR_SECS);
        run_clipboard_cmd("xclip -selection clipboard 2>/dev/null", nullptr, 0) ||
            run_clipboard_cmd("xsel --clipboard --input 2>/dev/null", nullptr, 0);
        _exit(0);
    }
    std::cout << "   Copied to clipboard (clears in " << CLIPBOARD_CLEAR_SECS << "s)\n";
}

void print_header() {
    std::cout << "\n╔══════════════════════════════════════╗\n";
    std::cout << "║     🔐  Encrypted Password Manager   ║\n";
    std::cout << "╚══════════════════════════════════════╝\n\n";
}

void print_entry(const PasswordEntry& e, bool show_pw = false) {
    std::cout << "┌─────────────────────────────────────────\n";
    std::cout << "│  Name:     " << e.name << "\n";
    std::cout << "│  Username: " << e.username << "\n";
    if (show_pw) std::cout << "│  Password: " << reveal(e.password) << "\n";
    else         std::cout << "│  Password: " << std::string(e.password.size(),'*') << "\n";
    if (!e.url.empty())   std::cout << "│  URL:      " << e.url   << "\n";
    if (!e.notes.empty()) std::cout << "│  Notes:    " << e.notes << "\n";
    std::cout << "│  Created:  " << e.created  << "\n";
    std::cout << "│  Modified: " << e.modified << "\n";
    std::cout << "└─────────────────────────────────────────\n";
}

std::string prompt(const std::string& label, bool opt = false) {
    std::cout << "   " << label; if (opt) std::cout << " (optional)"; std::cout << ": ";
    std::string v; std::getline(std::cin, v); return v;
}

void cmd_init(Vault& vault) {
    if (vault.exists()) {
        std::cout << "Vault exists. Overwrite? (yes/no): ";
        std::string c; std::getline(std::cin,c);
        if (c != "yes") { std::cout << "Aborted.\n"; return; }
    }
    std::cout << "\nMaster password cannot be recovered if lost.\n\n";
    SecureString p1 = read_password("   Master password: ");
    if (p1.size() < 8) { std::cout << "Minimum 8 characters.\n"; return; }
    SecureString p2 = read_password("   Confirm: ");
    if (p1 != p2) { secure_clear(p1); secure_clear(p2); std::cout << "Mismatch.\n"; return; }
    secure_clear(p2);
    std::cout << "\nDeriving key with Argon2id...\n";
    vault.entries.clear(); vault.save(p1); secure_clear(p1);
    std::cout << "Vault created: " << vault.vault_path << "\n";
    std::cout << "KDF: Argon2id (t=" << ARGON2_T_COST << ", m=" << ARGON2_M_COST/1024
              << "MB, p=" << ARGON2_PARALLELISM << ")  Cipher: AES-256-GCM\n\n";
}

void cmd_add(Vault& vault) {
    SecureString master = read_password("Master password: ");
    std::cout << "Unlocking...\n";
    vault.load(master);
    std::string name = prompt("Name");
    if (name.empty()) { secure_clear(master); vault.wipe(); std::cout << "Name required.\n"; return; }
    if (vault.find(name)) { secure_clear(master); vault.wipe(); std::cout << "Entry exists. Use 'update'.\n"; return; }
    std::string username = prompt("Username/Email");
    std::cout << "   Generate password? (y/n): "; std::string gc; std::getline(std::cin,gc);
    SecureString pw;
    if (gc=="y"||gc=="Y") {
        std::cout << "   Length (default 20): "; std::string ls; std::getline(std::cin,ls);
        std::cout << "   Symbols? (y/n, default y): "; std::string ss; std::getline(std::cin,ss);
        pw = generate_password(ls.empty()?20:std::stoi(ls), !(ss=="n"||ss=="N"));
        std::cout << "   Generated: " << reveal(pw) << "\n"; copy_to_clipboard(pw);
    } else { pw = read_password("   Password: "); }
    std::string url=prompt("URL",true), notes=prompt("Notes",true);
    PasswordEntry e;
    e.name=name; e.username=username; e.password=pw;
    e.url=url; e.notes=notes; e.created=e.modified=current_timestamp();
    vault.entries.push_back(e); secure_clear(pw);
    std::cout << "Saving...\n"; vault.save(master); secure_clear(master); vault.wipe();
    std::cout << "Entry '" << name << "' saved.\n\n";
}

void cmd_list(Vault& vault) {
    SecureString master = read_password("Master password: ");
    std::cout << "Unlocking...\n";
    vault.load(master); secure_clear(master);
    if (vault.entries.empty()) { std::cout << "\nVault is empty.\n\n"; return; }
    auto sorted = vault.entries;
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b){ return a.name<b.name; });
    std::cout << "\n" << sorted.size() << " entries:\n\n";
    for (size_t i=0;i<sorted.size();++i) {
        std::cout << "  " << std::setw(3) << (i+1) << ".  " << sorted[i].name;
        if (!sorted[i].username.empty()) std::cout << "  -  " << sorted[i].username;
        std::cout << "\n";
    }
    std::cout << "\n"; vault.wipe();
}

void cmd_get(Vault& vault, const std::string& name) {
    SecureString master = read_password("Master password: ");
    std::cout << "Unlocking...\n";
    vault.load(master); secure_clear(master);
    PasswordEntry* e = vault.find(name);
    if (!e) { vault.wipe(); std::cout << "Not found: " << name << "\n"; return; }
    std::cout << "\n"; print_entry(*e, true);
    std::cout << "\n   Copy to clipboard? (y/n): "; std::string c; std::getline(std::cin,c);
    if (c=="y"||c=="Y") copy_to_clipboard(e->password);
    std::cout << "\n"; vault.wipe();
}

void cmd_delete(Vault& vault, const std::string& name) {
    SecureString master = read_password("Master password: ");
    std::cout << "Unlocking...\n";
    vault.load(master);
    auto it = std::find_if(vault.entries.begin(), vault.entries.end(), [&](const PasswordEntry& e) {
        std::string a=e.name,b=name;
        std::transform(a.begin(),a.end(),a.begin(),::tolower);
        std::transform(b.begin(),b.end(),b.begin(),::tolower); return a==b; });
    if (it==vault.entries.end()) { secure_clear(master); vault.wipe(); std::cout << "Not found: " << name << "\n"; return; }
    std::cout << "Delete '" << it->name << "'? (yes/no): "; std::string c; std::getline(std::cin,c);
    if (c!="yes") { secure_clear(master); vault.wipe(); std::cout << "Aborted.\n"; return; }
    vault.entries.erase(it); vault.save(master); secure_clear(master); vault.wipe();
    std::cout << "Deleted '" << name << "'.\n\n";
}

void cmd_update(Vault& vault, const std::string& name) {
    SecureString master = read_password("Master password: ");
    std::cout << "Unlocking...\n";
    vault.load(master);
    PasswordEntry* e = vault.find(name);
    if (!e) { secure_clear(master); vault.wipe(); std::cout << "Not found: " << name << "\n"; return; }
    std::cout << "\nUpdating '" << name << "' (Enter = keep)\n\n";
    auto upd = [](const std::string& lbl, std::string& fld) {
        std::cout << "   " << lbl << " [" << fld << "]: ";
        std::string v; std::getline(std::cin,v); if (!v.empty()) fld=v;
    };
    upd("Username", e->username);
    std::cout << "   Regenerate password? (y/n): "; std::string g; std::getline(std::cin,g);
    if (g=="y"||g=="Y") {
        SecureString np = generate_password(20,true);
        std::cout << "   Generated: " << reveal(np) << "\n"; copy_to_clipboard(np);
        e->password=np; secure_clear(np);
    }
    else { SecureString np=read_password("   New password (blank=keep): "); if (!np.empty()) { e->password=np; secure_clear(np); } }
    upd("URL",e->url); upd("Notes",e->notes); e->modified=current_timestamp();
    vault.save(master); secure_clear(master); vault.wipe();
    std::cout << "\nUpdated.\n\n";
}

void cmd_search(Vault& vault, const std::string& term) {
    SecureString master = read_password("Master password: ");
    std::cout << "Unlocking...\n";
    vault.load(master); secure_clear(master);
    auto results = vault.search_fuzzy(term);
    if (results.empty()) { std::cout << "No results for '" << term << "'.\n\n"; return; }
    std::cout << "\n" << results.size() << " result(s) for '" << term << "':\n\n";
    for (auto& [dist,e] : results) { std::cout << "[dist=" << dist << "] "; print_entry(*e,false); }
    std::cout << "\n"; vault.wipe();
}

void cmd_generate(int length, bool symbols) {
    SecureString pw = generate_password(length, symbols);
    int cs = 26+26+10+(symbols?26:0);
    int bits = (int)(length*(log(cs)/log(2)));
    std::cout << "\nGenerated (" << length << " chars, ~" << bits << " bits):\n\n   " << reveal(pw) << "\n\n";
    copy_to_clipboard(pw); secure_clear(pw);
}

// Best-effort scan of common Linux/macOS removable-media mount points.
// This is a convenience for listing likely candidates - it is not a
// security boundary. The user always confirms/chooses the final path,
// and we separately warn (not block) if the chosen path turns out to
// share a filesystem with $HOME.
std::vector<std::string> detect_removable_media() {
    std::vector<std::string> bases;
    const char* user = getenv("USER");
    if (user && *user) {
        bases.push_back("/media/" + std::string(user));
        bases.push_back("/run/media/" + std::string(user));
    }
    bases.push_back("/media");
    bases.push_back("/Volumes");

    std::vector<std::string> found;
    for (auto& b : bases) {
        std::error_code ec;
        if (!fs::exists(b, ec) || !fs::is_directory(b, ec)) continue;
        for (auto& entry : fs::directory_iterator(b, ec)) {
            if (ec) break;
            if (!entry.is_directory()) continue;
            std::string p = entry.path().string();
            if (p == "/Volumes/Macintosh HD") continue; // macOS boot volume, not removable
            if (access(p.c_str(), W_OK) == 0) found.push_back(p);
        }
    }
    std::sort(found.begin(), found.end());
    found.erase(std::unique(found.begin(), found.end()), found.end());
    return found;
}

// Returns true if `path`'s filesystem is the same device as $HOME's -
// i.e. the keyfile would NOT actually be off this machine, defeating the
// point of a second factor.
bool same_device_as_home(const std::string& path) {
    const char* h = getenv("HOME");
    if (!h) return false;
    struct stat hst{}, dst{};
    if (stat(h, &hst) != 0) return false;
    if (stat(path.c_str(), &dst) != 0) return false;
    return hst.st_dev == dst.st_dev;
}

void cmd_genkeyfile(Vault& vault) {
    std::cout << "\nThis generates a random keyfile used as a second unlock factor\n";
    std::cout << "alongside your master password. It should live on removable media\n";
    std::cout << "(USB/SD), not on this computer's disk.\n\n";

    auto drives = detect_removable_media();
    std::string dest_dir;
    if (!drives.empty()) {
        std::cout << "Detected writable removable/external media:\n";
        for (size_t i=0;i<drives.size();++i) std::cout << "  " << (i+1) << ". " << drives[i] << "\n";
        std::cout << "  " << (drives.size()+1) << ". Enter a path manually\n";
        std::cout << "  0. Cancel\n\n";
        std::cout << "If your device isn't listed, insert it now, then choose: ";
        std::string sel; std::getline(std::cin, sel);
        if (sel.empty() || sel == "0") { std::cout << "Cancelled.\n\n"; return; }
        int idx = -1; try { idx = std::stoi(sel); } catch (...) {}
        if (idx >= 1 && idx <= (int)drives.size()) dest_dir = drives[idx-1];
        else { std::cout << "Path: "; std::getline(std::cin, dest_dir); }
    } else {
        std::cout << "No removable media auto-detected (insert a USB/SD card, or your\n";
        std::cout << "system may mount it somewhere this scan doesn't check).\n";
        std::cout << "Enter destination directory or full file path (blank = cancel): ";
        std::getline(std::cin, dest_dir);
    }
    if (dest_dir.empty()) { std::cout << "Cancelled.\n\n"; return; }

    struct stat st{};
    std::string dest_path = dest_dir;
    if (stat(dest_dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        dest_path = dest_dir + (dest_dir.back()=='/' ? "" : "/") + "pwmgr.keyfile";
    }

    if (fs::exists(dest_path)) {
        std::cout << "\nA file already exists at " << dest_path << ".\n";
        std::cout << "Overwrite it? This cannot be undone. (yes/no): ";
        std::string c; std::getline(std::cin, c);
        if (c != "yes") { std::cout << "Cancelled.\n\n"; return; }
    }

    if (same_device_as_home(fs::path(dest_path).parent_path().string())) {
        std::cout << "\nWARNING: that location appears to be on the SAME disk as your\n";
        std::cout << "home directory, not separate removable media. Keeping the keyfile\n";
        std::cout << "here defeats the purpose of a second factor - anyone who compromises\n";
        std::cout << "this machine gets both parts at once.\n";
        std::cout << "Continue anyway? (yes/no): ";
        std::string c; std::getline(std::cin, c);
        if (c != "yes") { std::cout << "Cancelled.\n\n"; return; }
    }

    std::cout << "\nGenerating 64 random bytes...\n";
    SecureVector<uint8_t> key(64);
    if (RAND_bytes(key.data(), (int)key.size()) != 1) throw std::runtime_error("RAND_bytes failed");

    write_file_atomic(dest_path, key.data(), key.size());
    sync(); // flush to physical media - safe to eject right after this returns
    secure_zero(key.data(), key.size());

    std::cout << "Keyfile written to: " << dest_path << "\n";
    std::cout << "It's safe to eject the device now.\n";

    if (vault.exists()) {
        std::cout << "\nAn existing vault was found. Bind this keyfile to it now?\n";
        std::cout << "You'll need your current master password. (y/n): ";
        std::string c; std::getline(std::cin, c);
        if (c=="y"||c=="Y") {
            SecureString master = read_password("Current master password: ");
            std::cout << "Unlocking...\n";
            try {
                vault.load(master);              // existing vault has no keyfile yet
                vault.save(master, dest_path);    // re-encrypt, now bound to this keyfile
                std::cout << "Vault re-encrypted. It now requires this keyfile to unlock.\n";
            } catch (...) { secure_clear(master); vault.wipe(); throw; }
            secure_clear(master); vault.wipe();
        } else {
            std::cout << "Skipped - your existing vault still opens with just the password.\n";
        }
    }

    std::cout << "\nTo unlock with this keyfile from now on, set PWMGR_KEYFILE, e.g.:\n";
    std::cout << "  PWMGR_KEYFILE=" << dest_path << " ./pwmgr shell\n\n";
    std::cout << "Back this file up now (e.g. a second USB kept somewhere else).\n";
    std::cout << "If a vault is bound to it, losing this file means losing the vault -\n";
    std::cout << "same as losing the master password. There is no recovery.\n\n";
}

void cmd_genfido2(Vault& vault) {
    std::cout << "\nThis registers a FIDO2 security key (e.g. a YubiKey or SoloKey) as\n";
    std::cout << "a second unlock factor alongside your master password, using its\n";
    std::cout << "hmac-secret extension to produce unpredictable secret material -\n";
    std::cout << "never just a serial number or public key.\n\n";
#ifndef PWMGR_WITH_FIDO2
    std::cout << "This build was compiled without PWMGR_WITH_FIDO2 / libfido2 support.\n";
    std::cout << "See the build instructions near the top of main.cpp.\n\n";
    return;
#else
    if (!vault.exists()) {
        std::cout << "No vault found - run 'init' first. A FIDO2 credential is only\n";
        std::cout << "useful bound to a vault, unlike a keyfile there's nothing\n";
        std::cout << "meaningful to generate standalone.\n\n";
        return;
    }

    std::cout << "Insert exactly one FIDO2 authenticator, then press Enter\n";
    std::cout << "(unplug any others first - see 'help' for why): ";
    std::string dummy; std::getline(std::cin, dummy);

    SecureString master = read_password("Current master password: ");
    std::cout << "Unlocking with your vault's current settings...\n";
    try {
        vault.load(master); // must succeed under whatever currently protects it
    } catch (...) { secure_clear(master); vault.wipe(); throw; }

    FIDO2Provider provider;
    std::cout << "\nTouch your authenticator now to register it...\n";
    try {
        provider.enroll(vault.vault_path);
    } catch (...) { secure_clear(master); vault.wipe(); throw; }

    std::cout << "\nRe-encrypting vault to require this FIDO2 key...\n";
    try {
        vault.save(master, provider);
    } catch (...) { secure_clear(master); vault.wipe(); throw; }
    secure_clear(master); vault.wipe();

    std::cout << "Vault re-encrypted. It now requires this FIDO2 key (plus your\n";
    std::cout << "master password) to unlock - just the password is no longer enough.\n\n";
    std::cout << "There is no recovery if this key is lost or damaged; it is not\n";
    std::cout << "backed up anywhere by this program. This build enrolls one\n";
    std::cout << "credential per vault - keep this key safe.\n\n";
#endif
}

void cmd_gentpm(Vault& vault) {
    std::cout << "\nThis seals a randomly-generated secret to this machine's TPM,\n";
    std::cout << "and requires that exact TPM to be present to unlock the vault -\n";
    std::cout << "in addition to your master password.\n\n";
#ifndef PWMGR_WITH_TPM
    std::cout << "This build was compiled without PWMGR_WITH_TPM / tpm2-tss support.\n";
    std::cout << "See the build instructions near the top of main.cpp.\n\n";
    return;
#else
    if (!vault.exists()) {
        std::cout << "No vault found - run 'init' first.\n\n";
        return;
    }

    const char* pcr_env = getenv("PWMGR_TPM_PCR");
    if (pcr_env && *pcr_env) {
        std::cout << "PWMGR_TPM_PCR=" << pcr_env << " is set - binding to this boot state\n";
        std::cout << "(PCR values). This is an advanced option: routine firmware, kernel,\n";
        std::cout << "or bootloader updates can change these values and lock you out with\n";
        std::cout << "no diagnostic beyond 'unseal failed'. Off (the default) is right for\n";
        std::cout << "most people; only proceed if you specifically understand this tradeoff.\n\n";
    }

    SecureString master = read_password("Current master password: ");
    std::cout << "Unlocking with your vault's current settings...\n";
    try {
        vault.load(master); // must succeed under whatever currently protects it
    } catch (...) { secure_clear(master); vault.wipe(); throw; }

    TPMProvider provider;
    std::cout << "\nSealing a new secret to this TPM...\n";
    try {
        provider.enroll(vault.vault_path);
    } catch (...) { secure_clear(master); vault.wipe(); throw; }

    std::cout << "\nRe-encrypting vault to require this TPM...\n";
    try {
        vault.save(master, provider);
    } catch (...) { secure_clear(master); vault.wipe(); throw; }
    secure_clear(master); vault.wipe();

    std::cout << "Vault re-encrypted. It now requires this TPM (plus your master\n";
    std::cout << "password) to unlock - just the password is no longer enough.\n\n";
    std::cout << "If this TPM is ever replaced, reset, or the motherboard changes,\n";
    std::cout << "the sealed secret becomes permanently unusable - there is no\n";
    std::cout << "recovery, by design (that's what makes it a hardware factor).\n";
    std::cout << "Before decommissioning this machine, disenroll or re-provision\n";
    std::cout << "under the new TPM while this one is still available.\n\n";
#endif
}

void cmd_passwd(Vault& vault) {
    SecureString op = read_password("Current master password: ");
    std::cout << "Unlocking...\n";
    vault.load(op); secure_clear(op);
    SecureString n1 = read_password("New master password: ");
    if (n1.size() < 8) { secure_clear(n1); vault.wipe(); std::cout << "Minimum 8 chars.\n"; return; }
    SecureString n2 = read_password("Confirm: ");
    if (n1 != n2) { secure_clear(n1); secure_clear(n2); vault.wipe(); std::cout << "Mismatch.\n"; return; }
    secure_clear(n2); std::cout << "Re-encrypting...\n";
    vault.save(n1); secure_clear(n1); vault.wipe();
    std::cout << "Password changed.\n\n";
}

void cmd_export(Vault& vault) {
    std::cout << "WARNING: displays all passwords in plaintext. Continue? (yes/no): ";
    std::string c; std::getline(std::cin,c); if (c!="yes") { std::cout << "Aborted.\n"; return; }
    SecureString master = read_password("Master password: ");
    std::cout << "Unlocking...\n";
    vault.load(master); secure_clear(master);
    std::cout << "\nPLAINTEXT EXPORT\n================\n\n";
    for (const auto& e : vault.entries) print_entry(e, true);
    std::cout << "\nEnd of export.\n\n"; vault.wipe();
}

void run_shell_cmd(Vault& vault, const SecureString& master, const std::string& line) {
    std::istringstream iss(line); std::string cmd; iss >> cmd;
    std::string arg; std::getline(iss >> std::ws, arg);

    if (cmd=="list") {
        auto sorted=vault.entries;
        std::sort(sorted.begin(),sorted.end(),[](const auto& a,const auto& b){return a.name<b.name;});
        std::cout << "\n" << sorted.size() << " entries:\n";
        for (size_t i=0;i<sorted.size();++i) {
            std::cout << "  " << std::setw(3) << i+1 << ".  " << sorted[i].name;
            if (!sorted[i].username.empty()) std::cout << "  -  " << sorted[i].username;
            std::cout << "\n";
        }
        std::cout << "\n";
    } else if (cmd=="get") {
        if (arg.empty()) { std::cout << "Usage: get <n>\n"; return; }
        PasswordEntry* e=vault.find(arg); if (!e) { std::cout << "Not found.\n"; return; }
        print_entry(*e,true);
        std::cout << "   Copy to clipboard? (y/n): "; std::string c; std::getline(std::cin,c);
        if (c=="y"||c=="Y") copy_to_clipboard(e->password);
    } else if (cmd=="search") {
        if (arg.empty()) { std::cout << "Usage: search <term>\n"; return; }
        auto r=vault.search_fuzzy(arg);
        if (r.empty()) { std::cout << "No results.\n"; return; }
        for (auto& [d,e]:r) { std::cout << "[" << d << "] "; print_entry(*e,false); }
    } else if (cmd=="add") {
        std::string name=prompt("Name"); if (name.empty()) return;
        if (vault.find(name)) { std::cout << "Exists.\n"; return; }
        std::string username=prompt("Username");
        std::cout << "   Generate? (y/n): "; std::string g; std::getline(std::cin,g);
        SecureString pw;
        if (g=="y"||g=="Y") { pw=generate_password(); std::cout << "   " << reveal(pw) << "\n"; copy_to_clipboard(pw); }
        else { pw=read_password("   Password: "); }
        std::string url=prompt("URL",true), notes=prompt("Notes",true);
        PasswordEntry e; e.name=name; e.username=username; e.password=pw; e.url=url; e.notes=notes;
        e.created=e.modified=current_timestamp(); vault.entries.push_back(e); secure_clear(pw);
        vault.save(master); std::cout << "Added.\n";
    } else if (cmd=="delete"||cmd=="rm") {
        if (arg.empty()) { std::cout << "Usage: delete <n>\n"; return; }
        auto it=std::find_if(vault.entries.begin(),vault.entries.end(),[&](const PasswordEntry& e){
            std::string a=e.name,b=arg;
            std::transform(a.begin(),a.end(),a.begin(),::tolower);
            std::transform(b.begin(),b.end(),b.begin(),::tolower); return a==b; });
        if (it==vault.entries.end()) { std::cout << "Not found.\n"; return; }
        std::cout << "Delete '" << it->name << "'? (yes/no): "; std::string c; std::getline(std::cin,c);
        if (c!="yes") return;
        vault.entries.erase(it); vault.save(master); std::cout << "Deleted.\n";
    } else if (cmd=="generate") {
        int len=arg.empty()?20:std::stoi(arg);
        SecureString pw=generate_password(len,true);
        std::cout << "   " << reveal(pw) << "\n"; copy_to_clipboard(pw); secure_clear(pw);
    } else if (cmd=="help") {
        std::cout << "  list / get <n> / add / delete <n> / search <t> / generate [n] / lock\n";
    } else { std::cout << "Unknown. Type 'help'.\n"; }
}

void cmd_shell(Vault& vault) {
    SecureString master = read_password("Master password: ");
    std::cout << "Unlocking...\n";
    vault.load(master);
    std::cout << "\nVault unlocked. Auto-locks after " << SHELL_LOCK_SECS << "s idle. Type 'help'.\n\n";
    while (true) {
        std::cout << "pwmgr> " << std::flush;
        if (!stdin_ready(SHELL_LOCK_SECS)) {
            vault.wipe(); secure_clear(master);
            if (g_signal_received) std::cout << "\nInterrupted - vault wiped, exiting.\n\n";
            else std::cout << "\nAuto-locked.\n\n";
            return;
        }
        std::string line; if (!std::getline(std::cin,line)) break;
        if (line.empty()) continue;
        if (line=="exit"||line=="quit"||line=="lock") break;
        try { run_shell_cmd(vault, master, line); }
        catch (const std::exception& ex) { std::cerr << "Error: " << ex.what() << "\n"; }
    }
    vault.wipe(); secure_clear(master); std::cout << "Vault locked.\n\n";
}

void print_help(const std::string& prog) {
    std::cout << "Usage: " << prog << " <command> [args]\n\n";
    std::cout << "  init                  Create new vault\n";
    std::cout << "  add                   Add entry\n";
    std::cout << "  list                  List all entries\n";
    std::cout << "  get <n>            Show entry + clipboard\n";
    std::cout << "  delete <n>         Delete entry\n";
    std::cout << "  update <n>         Update entry\n";
    std::cout << "  search <term>         Fuzzy search (Levenshtein)\n";
    std::cout << "  generate [len] [-n]   Generate password (-n = no symbols)\n";
    std::cout << "  passwd                Change master password\n";
    std::cout << "  genkeyfile            Generate a USB/SD second-factor keyfile\n";
    std::cout << "  genfido2              Register a FIDO2 security key as a second factor\n";
    std::cout << "  gentpm                Seal a secret to this machine's TPM as a second factor\n";
    std::cout << "  export                Plaintext dump\n";
    std::cout << "  shell                 Interactive shell (auto-locks after "
              << SHELL_LOCK_SECS << "s)\n\n";
    std::cout << "Security stack:\n";
    std::cout << "  KDF    Argon2id  t=" << ARGON2_T_COST << " m=" << ARGON2_M_COST/1024
              << "MB p=" << ARGON2_PARALLELISM << "  (64-byte output, first 32=AES key)\n";
    std::cout << "  Cipher AES-256-GCM  (authenticated encryption, replaces CBC+HMAC)\n";
    std::cout << "  AAD    Header bytes bound into GCM tag (detects header tampering)\n";
    std::cout << "  Memory SecureString/SecureVector<T> RAII: no SSO, mlock'd,\n";
    std::cout << "         secure_zero'd on every grow/reassign/destroy\n";
    std::cout << "  IO     Binary length-prefixed format (injection-proof)\n";
    std::cout << "  IO     Atomic writes (temp+fsync+rename), 0600 perms set at creation\n";
    std::cout << "  Brute  Exponential backoff on failed unlock\n";
    std::cout << "  Proc   No core dumps, ptrace-attach blocked for same-user processes\n";
    std::cout << "  2FA    Optional: set PWMGR_KEYFILE=<path> to require a keyfile\n";
    std::cout << "         in addition to the master password. Or run 'genfido2' to\n";
    std::cout << "         require a FIDO2 security key instead (hmac-secret extension,\n";
    std::cout << "         non-resident credential; needs a PWMGR_WITH_FIDO2 build).\n";
    std::cout << "         Exactly one authenticator must be connected at a time -\n";
    std::cout << "         with several plugged in there's no way to tell which one\n";
    std::cout << "         you meant to touch, so it refuses to guess.\n";
    std::cout << "         Or run 'gentpm' to require this machine's TPM instead (needs\n";
    std::cout << "         a PWMGR_WITH_TPM build). Set PWMGR_TPM_PCR=7 or =0,7,14\n";
    std::cout << "         before 'gentpm' to also bind to current boot-state PCR\n";
    std::cout << "         values (advanced, off by default - see 'gentpm').\n\n";
    std::cout << "Not protected against (no userspace app can defend these - use\n";
    std::cout << "full-disk encryption, a clean OS, and no untrusted software):\n";
    std::cout << "  Keyloggers, root/kernel compromise, active malware with ptrace\n";
    std::cout << "  or CAP_SYS_PTRACE, clipboard managers during the copy window.\n\n";
}

int main(int argc, char* argv[]) {
    harden_process();
    install_signal_handlers();
    print_header();
    if (argc < 2) { print_help(argv[0]); return 0; }
    std::string cmd = argv[1];
    Vault vault;
    try {
        if (cmd=="help"||cmd=="-h"||cmd=="--help") { print_help(argv[0]); }
        else if (cmd=="init")    { cmd_init(vault); }
        else if (cmd=="add")     { if (!vault.exists()){std::cout<<"No vault. Run 'init'.\n";return 1;} cmd_add(vault); }
        else if (cmd=="list")    { if (!vault.exists()){std::cout<<"No vault. Run 'init'.\n";return 1;} cmd_list(vault); }
        else if (cmd=="get")     { if (argc<3){std::cout<<"Usage: get <n>\n";return 1;} cmd_get(vault,argv[2]); }
        else if (cmd=="delete"||cmd=="rm") { if (argc<3){std::cout<<"Usage: delete <n>\n";return 1;} cmd_delete(vault,argv[2]); }
        else if (cmd=="update")  { if (argc<3){std::cout<<"Usage: update <n>\n";return 1;} cmd_update(vault,argv[2]); }
        else if (cmd=="search")  { if (argc<3){std::cout<<"Usage: search <term>\n";return 1;} cmd_search(vault,argv[2]); }
        else if (cmd=="generate") {
            int length=20; bool symbols=true;
            if (argc>=3) { try { length=std::stoi(argv[2]); } catch(...){} }
            for (int i=2;i<argc;++i) if (std::string(argv[i])=="-n") symbols=false;
            if (length<4||length>256) { std::cout<<"Length must be 4-256.\n"; return 1; }
            cmd_generate(length, symbols);
        }
        else if (cmd=="passwd")  { if (!vault.exists()){std::cout<<"No vault. Run 'init'.\n";return 1;} cmd_passwd(vault); }
        else if (cmd=="genkeyfile") { cmd_genkeyfile(vault); }
        else if (cmd=="genfido2") { cmd_genfido2(vault); }
        else if (cmd=="gentpm") { cmd_gentpm(vault); }
        else if (cmd=="export")  { if (!vault.exists()){std::cout<<"No vault. Run 'init'.\n";return 1;} cmd_export(vault); }
        else if (cmd=="shell")   { if (!vault.exists()){std::cout<<"No vault. Run 'init'.\n";return 1;} cmd_shell(vault); }
        else { std::cout << "Unknown command: " << cmd << "\n"; print_help(argv[0]); return 1; }
    } catch (const std::exception& ex) {
        std::cerr << "\nError: " << ex.what() << "\n\n"; return 1;
    }
    return 0;
}
