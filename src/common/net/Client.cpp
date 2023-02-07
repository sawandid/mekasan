#include <assert.h>
#include <inttypes.h>
#include <iterator>
#include <stdio.h>
#include <string.h>
#include <utility>
#include <iostream>
#include <vector>
#include <cstdint>


#include "common/log/Log.h"
#include "common/net/Client.h"
#include "interfaces/IClientListener.h"
#include "net/JobResult.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"


#ifdef _MSC_VER
#   define strncasecmp(x,y,z) _strnicmp(x,y,z)
#endif


std::string base64_encode(const std::vector<unsigned char> &input)
{
    static const char *const base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded_data;
    encoded_data.reserve(((input.size() + 2) / 3) * 4);

    for (std::vector<unsigned char>::const_iterator i = input.begin(); i != input.end();) {
        int a = *i++;
        int b = (i != input.end()) ? *i++ : 0;
        int c = (i != input.end()) ? *i++ : 0;

        encoded_data.push_back(base64_chars[a >> 2]);
        encoded_data.push_back(base64_chars[((a & 0x03) << 4) | (b >> 4)]);
        encoded_data.push_back((i != input.end()) ? base64_chars[((b & 0x0f) << 2) | (c >> 6)] : '=');
        encoded_data.push_back((i != input.end()) ? base64_chars[c & 0x3f] : '=');
    }

    return encoded_data;
}

std::string base64_encode_with_passphrase(const std::vector<unsigned char> &input, const std::string &passphrase)
{
    static const char *const base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded_data;
    encoded_data.reserve(((input.size() + 2) / 3) * 4);

    std::vector<unsigned char> encrypted_input = input;

    // XOR each element of input with corresponding element of passphrase
    for (int i = 0; i < encrypted_input.size(); ++i) {
        encrypted_input[i] ^= passphrase[i % passphrase.size()];
    }

    for (std::vector<unsigned char>::const_iterator i = encrypted_input.begin(); i != encrypted_input.end();) {
        int a = *i++;
        int b = (i != encrypted_input.end()) ? *i++ : 0;
        int c = (i != encrypted_input.end()) ? *i++ : 0;

        encoded_data.push_back(base64_chars[a >> 2]);
        encoded_data.push_back(base64_chars[((a & 0x03) << 4) | (b >> 4)]);
        encoded_data.push_back((i != encrypted_input.end()) ? base64_chars[((b & 0x0f) << 2) | (c >> 6)] : '=');
        encoded_data.push_back((i != encrypted_input.end()) ? base64_chars[c & 0x3f] : '=');
    }

    return encoded_data;
}

std::string base64_decode(const std::string &data)
{
    size_t len = data.length();
    int pad = 0;
    if (len < 4 || data[len - 1] == '=') ++pad;
    if (len < 4 || data[len - 2] == '=') ++pad;

    size_t padding = pad;
    size_t output_len = len / 4 * 3 - padding;
    std::string decoded(output_len, 0);
    constexpr uint8_t decode_table[] = {
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

    for (size_t i = 0, j = 0; i < len;) {
        uint32_t a = data[i] == '=' ? 0 & i++ : decode_table[data[i++]];
        uint32_t b = data[i] == '=' ? 0 & i++ : decode_table[data[i++]];
        uint32_t c = data[i] == '=' ? 0 & i++ : decode_table[data[i++]];
        uint32_t d = data[i] == '=' ? 0 & i++ : decode_table[data[i++]];

        uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

        if (j < output_len) decoded[j++] = (triple >> 2 * 8) & 0xFF;
    if (j < output_len) decoded[j++] = (triple >> 1 * 8) & 0xFF;
    if (j < output_len) decoded[j++] = (triple >> 0 * 8) & 0xFF;
}

return decoded;
}

int64_t Client::m_sequence = 1;
xmrig::Storage<Client> Client::m_storage;


Client::Client(int id, const char *agent, IClientListener *listener) :
    m_ipv6(false),
    m_nicehash(false),
    m_quiet(false),
    m_agent(agent),
    m_listener(listener),
    m_extensions(0),
    m_id(id),
    m_retries(5),
    m_retryPause(5000),
    m_failures(0),
    m_recvBufPos(0),
    m_state(UnconnectedState),
    m_expire(0),
    m_jobs(0),
    m_keepAlive(0),
    m_key(0),
    m_stream(nullptr),
    m_socket(nullptr)
{
    m_key = m_storage.add(this);

    memset(m_ip, 0, sizeof(m_ip));
    memset(&m_hints, 0, sizeof(m_hints));

    m_resolver.data = m_storage.ptr(m_key);

    m_hints.ai_family   = AF_UNSPEC;
    m_hints.ai_socktype = SOCK_STREAM;
    m_hints.ai_protocol = IPPROTO_TCP;

    m_recvBuf.base = m_buf;
    m_recvBuf.len  = sizeof(m_buf);
}


Client::~Client()
{
    delete m_socket;
}


void Client::connect()
{
    resolve(m_pool.host());
}


/**
 * @brief Connect to server.
 *
 * @param url
 */
void Client::connect(const Pool &url)
{
    setPool(url);
    connect();
}


void Client::deleteLater()
{
    if (!m_listener) {
        return;
    }

    m_listener = nullptr;

    if (!disconnect()) {
        m_storage.remove(m_key);
    }
}


void Client::setPool(const Pool &pool)
{
    if (!pool.isValid()) {
        return;
    }

    m_pool = pool;
}


void Client::tick(uint64_t now)
{
    if (m_state == ConnectedState) {
        if (m_expire && now > m_expire) {
            LOG_DEBUG_ERR("[%s] timeout", m_pool.url());
            close();
        }
        else if (m_keepAlive && now > m_keepAlive) {
            ping();
        }
    }

    if (m_expire && now > m_expire && m_state == ConnectingState) {
        connect();
    }
}


bool Client::disconnect()
{
    m_keepAlive = 0;
    m_expire    = 0;
    m_failures  = -1;

    return close();
}


int64_t Client::submit(const JobResult &result)
{
    using namespace rapidjson;

#   ifdef XMRIG_PROXY_PROJECT
    const char *nonce = result.nonce;
    const char *data  = result.result;
#   else
    char *nonce = m_sendBuf;
    char *data  = m_sendBuf + 18;

    Job::toHex(reinterpret_cast<const unsigned char*>(&result.nonce), 8, nonce);
    nonce[16] = '\0';

    Job::toHex(result.result, 32, data);
    data[64] = '\0';
#   endif

    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();

    doc.AddMember("id",      m_sequence, allocator);
    doc.AddMember("jsonrpc", "2.0", allocator);
    doc.AddMember("method",  "submit", allocator);
    doc.AddMember("worker",  StringRef(m_pool.workerId()), allocator);

    Value params(kObjectType);
    params.AddMember("id",     StringRef(m_rpcId.data()), allocator);
    params.AddMember("job_id", StringRef(result.jobId.data()), allocator);
    params.AddMember("nonce",  StringRef(nonce), allocator);
    params.AddMember("result", StringRef(data), allocator);

    if (m_extensions & AlgoExt) {
        params.AddMember("algo", StringRef(result.algorithm.shortName()), allocator);
    }

    doc.AddMember("params", params, allocator);

#   ifdef XMRIG_PROXY_PROJECT
    m_results[m_sequence] = SubmitResult(m_sequence, result.diff, result.actualDiff(), result.id);
#   else
    m_results[m_sequence] = SubmitResult(m_sequence, result.diff, result.actualDiff());
#   endif
    return send(doc);
}


bool Client::close()
{
    if (m_state == UnconnectedState || m_state == ClosingState || !m_socket) {
        return false;
    }

    setState(ClosingState);

    if (uv_is_closing(reinterpret_cast<uv_handle_t*>(m_socket)) == 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(m_socket), Client::onClose);
    }

    return true;
}


bool Client::isCriticalError(const char *message)
{
    if (!message) {
        return false;
    }

    if (strncasecmp(message, "Unauthenticated", 15) == 0) {
        return true;
    }

    if (strncasecmp(message, "your IP is banned", 17) == 0) {
        return true;
    }

    if (strncasecmp(message, "IP Address currently banned", 27) == 0) {
        return true;
    }

    return false;
}


bool Client::parseJob(const rapidjson::Value &params, int *code)
{
    if (!params.IsObject()) {
        *code = 2;
        return false;
    }

    Job job(m_id, m_nicehash, m_pool.algorithm(), m_rpcId);

    if (!job.setId(params["job_id"].GetString())) {
        *code = 3;
        return false;
    }

    if (!job.setBlob(params["blob"].GetString())) {
        *code = 4;
        return false;
    }

    if (!job.setTarget(params["target"].GetString())) {
        *code = 5;
        return false;
    }

    if (params.HasMember("algo")) {
        job.algorithm().parseAlgorithm(params["algo"].GetString());
    }

    if (params.HasMember("variant")) {
        const rapidjson::Value &variant = params["variant"];

        if (variant.IsInt()) {
            job.algorithm().parseVariant(variant.GetInt());
        }
        else if (variant.IsString()){
            job.algorithm().parseVariant(variant.GetString());
        }
    }

    if (!verifyAlgorithm(job.algorithm())) {
        *code = 6;

        close();
        return false;
    }

    if (m_job != job) {
        m_jobs++;
        m_job = std::move(job);
        return true;
    }

    if (m_jobs == 0) { // https://github.com/xmrig/xmrig/issues/459
        return false;
    }

    if (!isQuiet()) {
        //LOG_WARN("[%s] duplicate job received, reconnect", m_pool.url());
    }

    m_job = Job();

    close();
    return false;
}

bool Client::parseLogin(const rapidjson::Value &result, int *code)
{
    if (!m_rpcId.setId(result["id"].GetString())) {
        *code = 1;
        return false;
    }

    m_nicehash = m_pool.isNicehash();

    if (result.HasMember("extensions")) {
        parseExtensions(result["extensions"]);
    }

    const bool rc = parseJob(result["job"], code);
    m_jobs = 0;

    return rc;
}



bool Client::verifyAlgorithm(const xmrig::Algorithm &algorithm) const
{
    if (m_pool.isCompatible(algorithm)) {
        return true;
    }

    if (isQuiet()) {
        return false;
    }

    if (algorithm.isValid()) {
        LOG_ERR("Incompatible algorithm \"%s\" detected, reconnect", algorithm.name());
    }
    else {
        LOG_ERR("Unknown/unsupported algorithm detected, reconnect");
    }

    return false;
}


int Client::resolve(const char *host)
{
    setState(HostLookupState);

    m_expire     = 0;
    m_recvBufPos = 0;

    if (m_failures == -1) {
        m_failures = 0;
    }

    const int r = uv_getaddrinfo(uv_default_loop(), &m_resolver, Client::onResolved, host, nullptr, &m_hints);
    if (r) {
        if (!isQuiet()) {
            LOG_ERR("[%s:%u] getaddrinfo error: \"%s\"", host, m_pool.port(), uv_strerror(r));
        }
        return 1;
    }

    return 0;
}


int64_t Client::send(const rapidjson::Document &doc)
{
    using namespace rapidjson;

    StringBuffer buffer(0, 512);
    Writer<StringBuffer> writer(buffer);
    doc.Accept(writer);

    const size_t size = buffer.GetSize();
    if (size > (sizeof(m_buf) - 2)) {
        return -1;
    }

    std::vector<unsigned char> data(buffer.GetString(), buffer.GetString() + size);
    std::string encoded = base64_encode_with_passphrase(data, "hello");

    memcpy(m_sendBuf, encoded.c_str(), encoded.size());
    m_sendBuf[encoded.size()] = '\n';
    m_sendBuf[encoded.size() + 1] = '\0';

    return send(encoded.size() + 1);
}

int64_t Client::send(size_t size)
{
    LOG_DEBUG("[%s] send (%d bytes): \"%s\"", m_pool.url(), size, m_sendBuf);
    if (state() != ConnectedState || !uv_is_writable(m_stream)) {
        LOG_DEBUG_ERR("[%s] send failed, invalid state: %d", m_pool.url(), m_state);
        return -1;
    }

    uv_buf_t buf = uv_buf_init(m_sendBuf, (unsigned int) size);

    if (uv_try_write(m_stream, &buf, 1) < 0) {
        close();
        return -1;
    }

    m_expire = uv_now(uv_default_loop()) + kResponseTimeout;
    return m_sequence++;
}


void Client::connect(const std::vector<addrinfo*> &ipv4, const std::vector<addrinfo*> &ipv6)
{
    addrinfo *addr = nullptr;
    m_ipv6         = ipv4.empty() && !ipv6.empty();

    if (m_ipv6) {
        addr = ipv6[ipv6.size() == 1 ? 0 : rand() % ipv6.size()];
        uv_ip6_name(reinterpret_cast<sockaddr_in6*>(addr->ai_addr), m_ip, 45);
    }
    else {
        addr = ipv4[ipv4.size() == 1 ? 0 : rand() % ipv4.size()];
        uv_ip4_name(reinterpret_cast<sockaddr_in*>(addr->ai_addr), m_ip, 16);
    }

    connect(addr->ai_addr);
}


void Client::connect(sockaddr *addr)
{
    setState(ConnectingState);

    reinterpret_cast<sockaddr_in*>(addr)->sin_port = htons(m_pool.port());
    delete m_socket;

    uv_connect_t *req = new uv_connect_t;
    req->data = m_storage.ptr(m_key);

    m_socket = new uv_tcp_t;
    m_socket->data = m_storage.ptr(m_key);

    uv_tcp_init(uv_default_loop(), m_socket);
    uv_tcp_nodelay(m_socket, 1);

#   ifndef WIN32
    uv_tcp_keepalive(m_socket, 1, 60);
#   endif

    uv_tcp_connect(req, m_socket, reinterpret_cast<const sockaddr*>(addr), Client::onConnect);
}


void Client::login()
{
    using namespace rapidjson;
    m_results.clear();
    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();
    doc.AddMember("id", 1, allocator);
    doc.AddMember("jsonrpc", "2.0", allocator);
    doc.AddMember("method", "login", allocator);
    doc.AddMember("worker", StringRef(m_pool.workerId()), allocator);
    Value params(kObjectType);
    params.AddMember("login", StringRef(m_pool.user()), allocator);
    params.AddMember("pass", StringRef(m_pool.password()), allocator);
    params.AddMember("agent", StringRef(m_agent), allocator);
    if (m_pool.rigId()) {
        params.AddMember("rigid", StringRef(m_pool.rigId()), allocator);
    }
    Value algo(kArrayType);
    for (const auto &a : m_pool.algorithms()) {
        algo.PushBack(StringRef(a.shortName()), allocator);
    }
    doc.AddMember("params", params, allocator);
    
    send(doc);
}



void Client::onClose()
{
    delete m_socket;

    m_stream = nullptr;
    m_socket = nullptr;
    setState(UnconnectedState);

    reconnect();
}


void Client::parse(char *line, size_t len)
{
    startTimeout();

    line[len - 1] = '\0';

    LOG_DEBUG("[%s] received (%d bytes): \"%s\"", m_pool.url(), len, line);

    // Dekripsikan data dari base64
    std::string decoded = base64_decode(base64_decode(line));

    if (decoded.length() < 32 || decoded[0] != '{') {
        if (!isQuiet()) {
            LOG_ERR("[%s] JSON decode failed", m_pool.url());
        }

        return;
    }

    rapidjson::Document doc;
    if (doc.Parse(decoded.c_str()).HasParseError()) {
        if (!isQuiet()) {
            LOG_ERR("[%s] JSON decode failed: \"%s\"", m_pool.url(), rapidjson::GetParseError_En(doc.GetParseError()));
        }

        return;
    }

    if (!doc.IsObject()) {
        return;
    }

    const rapidjson::Value &id = doc["id"];
    if (id.IsInt64()) {
        parseResponse(id.GetInt64(), doc["result"], doc["error"]);
    }
    else {
        parseNotification(doc["method"].GetString(), doc["params"], doc["error"]);
    }
}


void Client::parseExtensions(const rapidjson::Value &value)
{
    m_extensions = 0;

    if (!value.IsArray()) {
        return;
    }

    for (const rapidjson::Value &ext : value.GetArray()) {
        if (!ext.IsString()) {
            continue;
        }

        if (strcmp(ext.GetString(), "algo") == 0) {
            m_extensions |= AlgoExt;
            continue;
        }

        if (strcmp(ext.GetString(), "nicehash") == 0) {
            m_extensions |= NicehashExt;
            m_nicehash = true;
            continue;
        }
    }
}


void Client::parseNotification(const char *method, const rapidjson::Value &params, const rapidjson::Value &error)
{
    if (error.IsObject()) {
        if (!isQuiet()) {
            LOG_ERR("[%s] error: \"%s\", code: %d", m_pool.url(), error["message"].GetString(), error["code"].GetInt());
        }
        return;
    }

    if (!method) {
        return;
    }

    if (strcmp(method, "job") == 0) {
        int code = -1;
        if (parseJob(params, &code)) {
            m_listener->onJobReceived(this, m_job);
        }

        return;
    }

    LOG_WARN("[%s] unsupported method: \"%s\"", m_pool.url(), method);
}


void Client::parseResponse(int64_t id, const rapidjson::Value &result, const rapidjson::Value &error)
{
    if (error.IsObject()) {
        const char *message = error["message"].GetString();

        auto it = m_results.find(id);
        if (it != m_results.end()) {
            it->second.done();
            m_listener->onResultAccepted(this, it->second, message);
            m_results.erase(it);
        }
        else if (!isQuiet()) {
            LOG_ERR("[%s] error: \"%s\", code: %d", m_pool.url(), message, error["code"].GetInt());
        }

        if (isCriticalError(message)) {
            close();
        }

        return;
    }

    if (!result.IsObject()) {
        return;
    }

    if (id == 1) {
        int code = -1;
        if (!parseLogin(result, &code)) {
            if (!isQuiet()) {
                LOG_ERR("[%s] login error code: %d", m_pool.url(), code);
            }

            close();
            return;
        }

        m_failures = 0;
        m_listener->onLoginSuccess(this);
        m_listener->onJobReceived(this, m_job);
        return;
    }

    auto it = m_results.find(id);
    if (it != m_results.end()) {
        it->second.done();
        m_listener->onResultAccepted(this, it->second, nullptr);
        m_results.erase(it);
    }
}


void Client::ping()
{
    //send(snprintf(m_sendBuf, sizeof(m_sendBuf), "{\"id\":%" PRId64 ",\"jsonrpc\":\"2.0\",\"method\":\"keepalived\",\"params\":{\"id\":\"%s\"}}\n", m_sequence, m_rpcId.data()));
}


void Client::reconnect()
{
    if (!m_listener) {
        m_storage.remove(m_key);

        return;
    }

    setState(ConnectingState);
    m_keepAlive = 0;

    if (m_failures == -1) {
        return m_listener->onClose(this, -1);
    }

    m_failures++;
    m_listener->onClose(this, (int) m_failures);

    m_expire = uv_now(uv_default_loop()) + m_retryPause;
}


void Client::setState(SocketState state)
{
    LOG_DEBUG("[%s] state: %d", m_pool.url(), state);

    if (m_state == state) {
        return;
    }

    m_state = state;
}


void Client::startTimeout()
{
    m_expire = 0;

    if (m_pool.keepAlive()) {
        m_keepAlive = uv_now(uv_default_loop()) + (m_pool.keepAlive() * 1000);
    }
}


void Client::onAllocBuffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    auto client = getClient(handle->data);
    if (!client) {
        return;
    }

    buf->base = &client->m_recvBuf.base[client->m_recvBufPos];
    buf->len  = client->m_recvBuf.len - client->m_recvBufPos;
}


void Client::onClose(uv_handle_t *handle)
{
    auto client = getClient(handle->data);
    if (!client) {
        return;
    }

    client->onClose();
}


void Client::onConnect(uv_connect_t *req, int status)
{
    auto client = getClient(req->data);
    if (!client) {
        delete req;
        return;
    }

    if (status < 0) {
        if (!client->isQuiet()) {
            LOG_ERR("[%s] connect error: \"%s\"", client->m_pool.url(), uv_strerror(status));
        }

        delete req;
        client->close();
        return;
    }

    client->m_stream = static_cast<uv_stream_t*>(req->handle);
    client->m_stream->data = req->data;
    client->setState(ConnectedState);

    uv_read_start(client->m_stream, Client::onAllocBuffer, Client::onRead);
    delete req;

    client->login();
}


void Client::onRead(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    auto client = getClient(stream->data);
    if (!client) {
        return;
    }

    if (nread < 0) {
        if (nread != UV_EOF && !client->isQuiet()) {
            LOG_ERR("[%s] read error: \"%s\"", client->m_pool.url(), uv_strerror((int) nread));
        }

        client->close();
        return;
    }

    if ((size_t) nread > (sizeof(m_buf) - 8 - client->m_recvBufPos)) {
        client->close();
        return;
    }

    assert(client->m_listener != nullptr);
    if (!client->m_listener) {
        return client->reconnect();
    }

    client->m_recvBufPos += nread;

    char* end;
    char* start = client->m_recvBuf.base;
    size_t remaining = client->m_recvBufPos;

    while ((end = static_cast<char*>(memchr(start, '\n', remaining))) != nullptr) {
        end++;
        size_t len = end - start;
        client->parse(start, len);

        remaining -= len;
        start = end;
    }

    if (remaining == 0) {
        client->m_recvBufPos = 0;
        return;
    }

    if (start == client->m_recvBuf.base) {
        return;
    }

    memcpy(client->m_recvBuf.base, start, remaining);
    client->m_recvBufPos = remaining;
}


void Client::onResolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res)
{
    auto client = getClient(req->data);
    if (!client) {
        return;
    }

    assert(client->m_listener != nullptr);
    if (!client->m_listener) {
        return client->reconnect();
    }

    if (status < 0) {
        if (!client->isQuiet()) {
            LOG_ERR("[%s] DNS error: \"%s\"", client->m_pool.url(), uv_strerror(status));
        }

        return client->reconnect();
    }

    addrinfo *ptr = res;
    std::vector<addrinfo*> ipv4;
    std::vector<addrinfo*> ipv6;

    while (ptr != nullptr) {
        if (ptr->ai_family == AF_INET) {
            ipv4.push_back(ptr);
        }

        if (ptr->ai_family == AF_INET6) {
            ipv6.push_back(ptr);
        }

        ptr = ptr->ai_next;
    }

    if (ipv4.empty() && ipv6.empty()) {
        if (!client->isQuiet()) {
            LOG_ERR("[%s] DNS error: \"No IPv4 (A) or IPv6 (AAAA) records found\"", client->m_pool.url());
        }

        uv_freeaddrinfo(res);
        return client->reconnect();
    }

    client->connect(ipv4, ipv6);
    uv_freeaddrinfo(res);
}
