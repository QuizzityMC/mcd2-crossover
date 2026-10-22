/* Real macOS libcurl transport, production diagnostics, sequential platform doubles.
 * Invoked only by test_http_diagnostics_loopback.py; all inputs are private fixtures.
 */
#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define DC_HTTP_NATIVE_TEST 1
typedef unsigned long DWORD;
typedef void *HANDLE;
static HANDLE self;
static int waitqueueFix;
static char trustedCA[2048];
static const char *caPath;
static void setupCA(void) {
    assert(caPath && strlen(caPath) < sizeof(trustedCA));
    strcpy(trustedCA, caPath);
}
static int waitqueue_fix_apply(void) { return 0; }
static unsigned long long GetTickCount64(void) {
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (unsigned long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static DWORD GetCurrentProcessId(void) { return (DWORD)getpid(); }
static int dcLogging(void) { return 1; }
static char logs[65536];
static void logline(const char *s) {
    assert(strlen(logs) + strlen(s) < sizeof(logs));
    strcat(logs, s);
}
static void *module;
static void *fn(const char *name) {
    if (!module) module = dlopen("/usr/lib/libcurl.4.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!module) { fprintf(stderr, "dlopen: %s\n", dlerror()); exit(1); }
    void *symbol = dlsym(module, name);
    if (!symbol) { fprintf(stderr, "dlsym %s: %s\n", name, dlerror()); exit(1); }
    return symbol;
}
#include "../src/curl.c"
/* Only this single-threaded C process accesses production trace state. */
void AcquireSRWLockExclusive(LOCK *p) { (void)p; }
void ReleaseSRWLockExclusive(LOCK *p) { (void)p; }
struct Sink { unsigned char bytes[16384]; SIZE length; unsigned calls; };
static SIZE sink(char *p, SIZE size, SIZE count, void *userdata) {
    struct Sink *s = userdata;
    assert(!size || count <= sizeof(s->bytes) / size);
    SIZE n = size * count;
    assert(n <= sizeof(s->bytes) - s->length);
    memcpy(s->bytes + s->length, p, n);
    s->length += n;
    s->calls++;
    return n;
}
static void option(void *easy, int key, void *value) {
    int rc = curl_easy_setopt(easy, key, value);
    if (rc) { fprintf(stderr, "setopt %d failed: %d\n", key, rc); exit(1); }
}
#define LONG(value) ((void *)(uintptr_t)(value))
int main(int argc, char **argv) {
    assert(argc == 5); /* CA, loopback port, expected CURLcode, sink file */
    caPath = argv[1];
    char *end;
    long port = strtol(argv[2], &end, 10);
    assert(!*end && port > 0 && port <= 65535);
    int expected = atoi(argv[3]);
    assert(expected == 0 || expected == 60);
    assert(curl_global_init(3) == 0);
    void *easy = curl_easy_init();
    assert(easy);
    void *(*listAppend)(void *, const char *) = fn("curl_slist_append");
    void (*listFree)(void *) = fn("curl_slist_free_all");
    char mapping[128];
    snprintf(mapping, sizeof(mapping), "profile.xboxlive.com:443:127.0.0.1:%ld", port);
    void *connections = listAppend(NULL, mapping);
    void *headers = listAppend(NULL, "Authorization: Bearer AUTH_SENTINEL");
    assert(connections && headers);
    void *next = listAppend(headers, "Cookie: session=COOKIE_SENTINEL");
    assert(next); headers = next;
    struct Sink received = {0};
    /* CONNECT_TO changes the socket destination, retaining HTTPS SNI/host checks.
     * No redirects, proxy, remote DNS, or alternate destination is permitted. */
    option(easy, 10243, connections);
    option(easy, 10004, "");       /* PROXY: override even environment proxies */
    option(easy, 10177, "*");      /* NOPROXY */
    option(easy, 52, LONG(0));      /* FOLLOWLOCATION */
    option(easy, 99, LONG(1));      /* NOSIGNAL */
    option(easy, 156, LONG(8000));  /* CONNECTTIMEOUT_MS */
    option(easy, 155, LONG(12000)); /* TIMEOUT_MS */
    option(easy, 10023, headers);
    option(easy, 20011, (void *)sink);
    option(easy, 10001, &received);
    option(easy, 10002, "https://profile.xboxlive.com/test?token=SYNTHETIC_SECRET");
    int rc = curl_easy_perform(easy);
    if (rc != expected) { fprintf(stderr, "CURLcode=%d, expected=%d\n", rc, expected); return 1; }
    if (!expected) assert(received.calls && received.length);
    else assert(!received.calls && !received.length);
    FILE *out = fopen(argv[4], "wb");
    assert(out && fwrite(received.bytes, 1, received.length, out) == received.length);
    assert(fclose(out) == 0);
    curl_easy_cleanup(easy);
    listFree(headers); listFree(connections);
    void (*cleanup)(void) = fn("curl_global_cleanup");
    cleanup();
    fputs(logs, stdout); /* Parent checks ALL logs before selecting exact rows. */
    assert(dlclose(module) == 0);
    return 0;
}
