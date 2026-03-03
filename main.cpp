#include <openssl/evp.h>
#include <openssl/rand.h>
#include "argon2_min.h"

#include <iostream>
#include <fstream>
#include <sstream>
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
#include <cmath>
#include <climits>

namespace fs = std::filesystem;

const char     VAULT_MAGIC[4]      = {'P','W','M','G'};
const uint32_t VAULT_VERSION       = 2;
const std::string VAULT_FILENAME   = ".pwmgr_vault";
const std::string ATTEMPTS_FILE    = ".pwmgr_attempts";
const int GCM_NONCE_SIZE           = 12;
const int GCM_TAG_SIZE             = 16;
const int GCM_KEY_SIZE             = 32;
const int SALT_SIZE                = 32;
const int KDF_OUTPUT_SIZE          = 64;
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

class LockedBuffer {
    uint8_t* data_;
    size_t   size_;
    bool     locked_;
public:
    explicit LockedBuffer(size_t n) : size_(n), locked_(false) {
        data_ = new uint8_t[n]();
        if (mlock(data_, n) == 0) locked_ = true;
    }
    ~LockedBuffer() {
        secure_zero(data_, size_);
        if (locked_) munlock(data_, size_);
        delete[] data_;
    }
    uint8_t* data()       { return data_; }
    const uint8_t* data() const { return data_; }
    size_t   size() const { return size_; }
    LockedBuffer(const LockedBuffer&) = delete;
    LockedBuffer(LockedBuffer&& o) : data_(o.data_), size_(o.size_), locked_(o.locked_) { o.data_=nullptr; o.size_=0; o.locked_=false; }
    LockedBuffer& operator=(const LockedBuffer&) = delete;
};

std::string read_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    struct termios old_tty, new_tty;
    bool tty = isatty(STDIN_FILENO);
    if (tty) {
        tcgetattr(STDIN_FILENO, &old_tty);
        new_tty = old_tty;
        new_tty.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &new_tty);
    }
    std::string pw;
    std::getline(std::cin, pw);
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

LockedBuffer derive_keys(const std::string& password, const uint8_t* salt,
                         uint32_t t, uint32_t m, uint32_t p) {
    LockedBuffer out(KDF_OUTPUT_SIZE);
    int rc = argon2id_hash_raw(t, m, p,
        password.c_str(), password.size(),
        salt, SALT_SIZE, out.data(), KDF_OUTPUT_SIZE);
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
static uint16_t read_u16(const uint8_t* p) { return (uint16_t)(((uint16_t)p[0]<<8)|p[1]); }
static uint32_t read_u32(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];
}

struct PasswordEntry {
    std::string name, username, password, url, notes, created, modified;
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
    for (uint32_t i = 0; i < count; ++i) {
        PasswordEntry e;
        rf(e.name); rf(e.username); rf(e.password);
        rf(e.url);  rf(e.notes);    rf(e.created); rf(e.modified);
        entries.push_back(std::move(e));
    }
    return entries;
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
    std::ofstream f(attempts_path()); f << n;
    chmod(attempts_path().c_str(), S_IRUSR | S_IWUSR);
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

    void wipe() {
        for (auto& e : entries) { secure_clear(e.password); secure_clear(e.name); secure_clear(e.username); }
        entries.clear();
    }

    void save(const std::string& master) {
        auto salt  = random_bytes(SALT_SIZE);
        auto nonce = random_bytes(GCM_NONCE_SIZE);
        auto plain = serialize(entries);
        mlock(plain.data(), plain.size());
        auto keys = derive_keys(master, salt.data(), ARGON2_T_COST, ARGON2_M_COST, ARGON2_PARALLELISM);

        std::vector<uint8_t> hdr;
        hdr.insert(hdr.end(), VAULT_MAGIC, VAULT_MAGIC+4);
        write_u32(hdr, VAULT_VERSION);
        hdr.insert(hdr.end(), salt.begin(), salt.end());
        write_u32(hdr, ARGON2_T_COST); write_u32(hdr, ARGON2_M_COST); write_u32(hdr, ARGON2_PARALLELISM);
        hdr.insert(hdr.end(), nonce.begin(), nonce.end());

        auto res = gcm_encrypt(plain.data(), plain.size(), keys.data(),
                               nonce.data(), hdr.data(), hdr.size());
        secure_zero(plain.data(), plain.size()); munlock(plain.data(), plain.size());

        std::ofstream f(vault_path, std::ios::binary | std::ios::trunc);
        if (!f) throw std::runtime_error("Cannot write vault");
        f.write(reinterpret_cast<const char*>(hdr.data()), hdr.size());
        f.write(reinterpret_cast<const char*>(res.tag.data()), GCM_TAG_SIZE);
        const uint8_t csz[4] = {
            (uint8_t)(res.ciphertext.size()>>24),(uint8_t)(res.ciphertext.size()>>16),
            (uint8_t)(res.ciphertext.size()>>8), (uint8_t)(res.ciphertext.size())
        };
        f.write(reinterpret_cast<const char*>(csz), 4);
        f.write(reinterpret_cast<const char*>(res.ciphertext.data()), res.ciphertext.size());
        f.close();
        chmod(vault_path.c_str(), S_IRUSR | S_IWUSR);
    }

    void load(const std::string& master) {
        std::ifstream f(vault_path, std::ios::binary);
        if (!f) throw std::runtime_error("Vault not found. Run 'init' first.");
        auto cr = [&](void* dst, size_t n, const char* fld) {
            if (!f.read(reinterpret_cast<char*>(dst), n))
                throw std::runtime_error(std::string("Truncated vault: ") + fld);
        };
        char magic[4]; cr(magic, 4, "magic");
        if (memcmp(magic, VAULT_MAGIC, 4) != 0) throw std::runtime_error("Not a vault file");
        uint8_t ver[4]; cr(ver, 4, "version");
        if (read_u32(ver) != VAULT_VERSION) throw std::runtime_error("Unsupported version");
        uint8_t salt[SALT_SIZE]; cr(salt, SALT_SIZE, "salt");
        uint8_t params[12]; cr(params, 12, "params");
        uint32_t t=read_u32(params), m=read_u32(params+4), p=read_u32(params+8);
        uint8_t nonce[GCM_NONCE_SIZE]; cr(nonce, GCM_NONCE_SIZE, "nonce");
        uint8_t tag[GCM_TAG_SIZE]; cr(tag, GCM_TAG_SIZE, "tag");
        uint8_t csz[4]; cr(csz, 4, "ct size");
        uint32_t ct_size = read_u32(csz);
        if (ct_size == 0 || ct_size > MAX_VAULT_BYTES) throw std::runtime_error("Invalid ciphertext size");
        std::vector<uint8_t> ct(ct_size); cr(ct.data(), ct_size, "ciphertext");

        auto keys = derive_keys(master, salt, t, m, p);
        std::vector<uint8_t> aad;
        aad.insert(aad.end(), VAULT_MAGIC, VAULT_MAGIC+4);
        aad.insert(aad.end(), ver, ver+4);
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

std::string generate_password(int length = 20, bool symbols = true) {
    std::string cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (symbols) cs += "!@#$%^&*()_+-=[]{}|;:,.<>?";
    int sz = (int)cs.size(), rng = (256/sz)*sz;
    std::string pw; pw.reserve(length);
    while ((int)pw.size() < length) {
        auto batch = random_bytes(length*2);
        for (uint8_t b : batch) { if ((int)pw.size()>=length) break; if (b<rng) pw+=cs[b%sz]; }
    }
    return pw;
}

void copy_to_clipboard(const std::string& text) {
    FILE* pipe = popen("xclip -selection clipboard 2>/dev/null", "w");
    if (!pipe) pipe = popen("xsel --clipboard --input 2>/dev/null", "w");
    if (!pipe) { std::cout << "   (Clipboard unavailable)\n"; return; }
    fwrite(text.c_str(), 1, text.size(), pipe);
    pclose(pipe);
    pid_t pid = fork();
    if (pid == 0) {
        sleep(CLIPBOARD_CLEAR_SECS);
        FILE* c = popen("printf '' | xclip -selection clipboard 2>/dev/null", "w");
        if (!c) c = popen("printf '' | xsel --clipboard --input 2>/dev/null", "w");
        if (c) pclose(c);
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
    if (show_pw) std::cout << "│  Password: " << e.password << "\n";
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
    std::string p1 = read_password("   Master password: ");
    mlock(p1.data(), p1.size());
    if (p1.size() < 8) { std::cout << "Minimum 8 characters.\n"; return; }
    std::string p2 = read_password("   Confirm: ");
    if (p1 != p2) { secure_clear(p1); secure_clear(p2); std::cout << "Mismatch.\n"; return; }
    secure_clear(p2);
    std::cout << "\nDeriving key with Argon2id...\n";
    vault.entries.clear(); vault.save(p1); secure_clear(p1);
    std::cout << "Vault created: " << vault.vault_path << "\n";
    std::cout << "KDF: Argon2id (t=" << ARGON2_T_COST << ", m=" << ARGON2_M_COST/1024
              << "MB, p=" << ARGON2_PARALLELISM << ")  Cipher: AES-256-GCM\n\n";
}

void cmd_add(Vault& vault) {
    std::string master = read_password("Master password: ");
    mlock(master.data(), master.size());
    std::cout << "Unlocking...\n";
    vault.load(master);
    std::string name = prompt("Name");
    if (name.empty()) { std::cout << "Name required.\n"; return; }
    if (vault.find(name)) { std::cout << "Entry exists. Use 'update'.\n"; return; }
    std::string username = prompt("Username/Email");
    std::cout << "   Generate password? (y/n): "; std::string gc; std::getline(std::cin,gc);
    std::string pw;
    if (gc=="y"||gc=="Y") {
        std::cout << "   Length (default 20): "; std::string ls; std::getline(std::cin,ls);
        std::cout << "   Symbols? (y/n, default y): "; std::string ss; std::getline(std::cin,ss);
        pw = generate_password(ls.empty()?20:std::stoi(ls), !(ss=="n"||ss=="N"));
        std::cout << "   Generated: " << pw << "\n"; copy_to_clipboard(pw);
    } else { pw = read_password("   Password: "); mlock(pw.data(),pw.size()); }
    std::string url=prompt("URL",true), notes=prompt("Notes",true);
    PasswordEntry e;
    e.name=name; e.username=username; e.password=pw;
    e.url=url; e.notes=notes; e.created=e.modified=current_timestamp();
    vault.entries.push_back(e); secure_clear(pw);
    std::cout << "Saving...\n"; vault.save(master); secure_clear(master); vault.wipe();
    std::cout << "Entry '" << name << "' saved.\n\n";
}

void cmd_list(Vault& vault) {
    std::string master = read_password("Master password: ");
    mlock(master.data(), master.size()); std::cout << "Unlocking...\n";
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
    std::string master = read_password("Master password: ");
    mlock(master.data(), master.size()); std::cout << "Unlocking...\n";
    vault.load(master); secure_clear(master);
    PasswordEntry* e = vault.find(name);
    if (!e) { std::cout << "Not found: " << name << "\n"; return; }
    std::cout << "\n"; print_entry(*e, true);
    std::cout << "\n   Copy to clipboard? (y/n): "; std::string c; std::getline(std::cin,c);
    if (c=="y"||c=="Y") copy_to_clipboard(e->password);
    std::cout << "\n"; vault.wipe();
}

void cmd_delete(Vault& vault, const std::string& name) {
    std::string master = read_password("Master password: ");
    mlock(master.data(), master.size()); std::cout << "Unlocking...\n";
    vault.load(master);
    auto it = std::find_if(vault.entries.begin(), vault.entries.end(), [&](const PasswordEntry& e) {
        std::string a=e.name,b=name;
        std::transform(a.begin(),a.end(),a.begin(),::tolower);
        std::transform(b.begin(),b.end(),b.begin(),::tolower); return a==b; });
    if (it==vault.entries.end()) { std::cout << "Not found: " << name << "\n"; return; }
    std::cout << "Delete '" << it->name << "'? (yes/no): "; std::string c; std::getline(std::cin,c);
    if (c!="yes") { std::cout << "Aborted.\n"; return; }
    vault.entries.erase(it); vault.save(master); secure_clear(master); vault.wipe();
    std::cout << "Deleted '" << name << "'.\n\n";
}

void cmd_update(Vault& vault, const std::string& name) {
    std::string master = read_password("Master password: ");
    mlock(master.data(), master.size()); std::cout << "Unlocking...\n";
    vault.load(master);
    PasswordEntry* e = vault.find(name);
    if (!e) { std::cout << "Not found: " << name << "\n"; return; }
    std::cout << "\nUpdating '" << name << "' (Enter = keep)\n\n";
    auto upd = [](const std::string& lbl, std::string& fld) {
        std::cout << "   " << lbl << " [" << fld << "]: ";
        std::string v; std::getline(std::cin,v); if (!v.empty()) fld=v;
    };
    upd("Username", e->username);
    std::cout << "   Regenerate password? (y/n): "; std::string g; std::getline(std::cin,g);
    if (g=="y"||g=="Y") { std::string np=generate_password(20,true); std::cout << "   Generated: " << np << "\n"; copy_to_clipboard(np); e->password=np; }
    else { std::string np=read_password("   New password (blank=keep): "); if (!np.empty()) { e->password=np; secure_clear(np); } }
    upd("URL",e->url); upd("Notes",e->notes); e->modified=current_timestamp();
    vault.save(master); secure_clear(master); vault.wipe();
    std::cout << "\nUpdated.\n\n";
}

void cmd_search(Vault& vault, const std::string& term) {
    std::string master = read_password("Master password: ");
    mlock(master.data(), master.size()); std::cout << "Unlocking...\n";
    vault.load(master); secure_clear(master);
    auto results = vault.search_fuzzy(term);
    if (results.empty()) { std::cout << "No results for '" << term << "'.\n\n"; return; }
    std::cout << "\n" << results.size() << " result(s) for '" << term << "':\n\n";
    for (auto& [dist,e] : results) { std::cout << "[dist=" << dist << "] "; print_entry(*e,false); }
    std::cout << "\n"; vault.wipe();
}

void cmd_generate(int length, bool symbols) {
    std::string pw = generate_password(length, symbols);
    int cs = 26+26+10+(symbols?26:0);
    int bits = (int)(length*(log(cs)/log(2)));
    std::cout << "\nGenerated (" << length << " chars, ~" << bits << " bits):\n\n   " << pw << "\n\n";
    copy_to_clipboard(pw); secure_zero(&pw[0], pw.size());
}

void cmd_passwd(Vault& vault) {
    std::string op = read_password("Current master password: ");
    mlock(op.data(), op.size()); std::cout << "Unlocking...\n";
    vault.load(op); secure_clear(op);
    std::string n1 = read_password("New master password: ");
    mlock(n1.data(), n1.size());
    if (n1.size() < 8) { std::cout << "Minimum 8 chars.\n"; return; }
    std::string n2 = read_password("Confirm: ");
    if (n1 != n2) { secure_clear(n1); secure_clear(n2); std::cout << "Mismatch.\n"; return; }
    secure_clear(n2); std::cout << "Re-encrypting...\n";
    vault.save(n1); secure_clear(n1); vault.wipe();
    std::cout << "Password changed.\n\n";
}

void cmd_export(Vault& vault) {
    std::cout << "WARNING: displays all passwords in plaintext. Continue? (yes/no): ";
    std::string c; std::getline(std::cin,c); if (c!="yes") { std::cout << "Aborted.\n"; return; }
    std::string master = read_password("Master password: ");
    mlock(master.data(), master.size()); std::cout << "Unlocking...\n";
    vault.load(master); secure_clear(master);
    std::cout << "\nPLAINTEXT EXPORT\n================\n\n";
    for (const auto& e : vault.entries) print_entry(e, true);
    std::cout << "\nEnd of export.\n\n"; vault.wipe();
}

void run_shell_cmd(Vault& vault, const std::string& master, const std::string& line) {
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
        std::string pw;
        if (g=="y"||g=="Y") { pw=generate_password(); std::cout << "   " << pw << "\n"; copy_to_clipboard(pw); }
        else { pw=read_password("   Password: "); mlock(pw.data(),pw.size()); }
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
        std::string pw=generate_password(len,true);
        std::cout << "   " << pw << "\n"; copy_to_clipboard(pw); secure_zero(&pw[0],pw.size());
    } else if (cmd=="help") {
        std::cout << "  list / get <n> / add / delete <n> / search <t> / generate [n] / lock\n";
    } else { std::cout << "Unknown. Type 'help'.\n"; }
}

void cmd_shell(Vault& vault) {
    std::string master = read_password("Master password: ");
    mlock(master.data(), master.size()); std::cout << "Unlocking...\n";
    vault.load(master);
    std::cout << "\nVault unlocked. Auto-locks after " << SHELL_LOCK_SECS << "s idle. Type 'help'.\n\n";
    while (true) {
        std::cout << "pwmgr> " << std::flush;
        if (!stdin_ready(SHELL_LOCK_SECS)) {
            vault.wipe(); secure_clear(master);
            std::cout << "\nAuto-locked.\n\n"; return;
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
    std::cout << "  export                Plaintext dump\n";
    std::cout << "  shell                 Interactive shell (auto-locks after "
              << SHELL_LOCK_SECS << "s)\n\n";
    std::cout << "Security stack:\n";
    std::cout << "  KDF    Argon2id  t=" << ARGON2_T_COST << " m=" << ARGON2_M_COST/1024
              << "MB p=" << ARGON2_PARALLELISM << "  (64-byte output, first 32=AES key)\n";
    std::cout << "  Cipher AES-256-GCM  (authenticated encryption, replaces CBC+HMAC)\n";
    std::cout << "  AAD    Header bytes bound into GCM tag (detects header tampering)\n";
    std::cout << "  Memory mlock + secure_zero on keys, passwords, plaintext\n";
    std::cout << "  IO     Binary length-prefixed format (injection-proof)\n";
    std::cout << "  Brute  Exponential backoff on failed unlock\n\n";
}

int main(int argc, char* argv[]) {
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
        else if (cmd=="export")  { if (!vault.exists()){std::cout<<"No vault. Run 'init'.\n";return 1;} cmd_export(vault); }
        else if (cmd=="shell")   { if (!vault.exists()){std::cout<<"No vault. Run 'init'.\n";return 1;} cmd_shell(vault); }
        else { std::cout << "Unknown command: " << cmd << "\n"; print_help(argv[0]); return 1; }
    } catch (const std::exception& ex) {
        std::cerr << "\nError: " << ex.what() << "\n\n"; return 1;
    }
    return 0;
}
