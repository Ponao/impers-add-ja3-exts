# Adding missing JA3 features to curl-impersonate

Current libcurl-impersonate (v1.5.6, BoringSSL 673e61fc) is missing a few things needed for Firefox-like JA3 fingerprints. Specifically: cipher 0xCCAA, ffdhe4096-8192 groups, encrypt_then_mac extension, and X448 curve. All four have been implemented and tested successfully.


## Cipher 0xCCAA (DHE-RSA-CHACHA20-POLY1305)

DHE key exchange already works from the existing patch. CHACHA20_POLY1305 is native to BoringSSL. Just needs the cipher suite entry added.

In include/openssl/tls1.h add the constant and text name:

```c
#define TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 0x0300CCAA
#define TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 "DHE-RSA-CHACHA20-POLY1305"
```

In ssl/ssl_cipher.cc add the cipher entry between CCA9 and CCAB:

```c
{
    TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    SSL_kDHE,
    SSL_aRSA_DECRYPT,
    SSL_CHACHA20POLY1305,
    SSL_AEAD,
    SSL_HANDSHAKE_MAC_SHA256,
},
```

Also add `TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 & 0xffff` to kLegacyCiphers[].


## Groups ffdhe4096/6144/8192

Same pattern as ffdhe2048/3072 already in the patch.

In include/openssl/nid.h:

```c
#define SN_ffdhe4096 "ffdhe4096"
#define NID_ffdhe4096 968
#define SN_ffdhe6144 "ffdhe6144"
#define NID_ffdhe6144 969
#define SN_ffdhe8192 "ffdhe8192"
#define NID_ffdhe8192 970
```

In include/openssl/ssl.h:

```c
#define SSL_GROUP_FFDHE4096 0x0102
#define SSL_GROUP_FFDHE6144 0x0103
#define SSL_GROUP_FFDHE8192 0x0104
#define SSL_CURVE_FFDHE4096 SSL_GROUP_FFDHE4096
#define SSL_CURVE_FFDHE6144 SSL_GROUP_FFDHE6144
#define SSL_CURVE_FFDHE8192 SSL_GROUP_FFDHE8192
```

In ssl/ssl_key_share.cc kNamedGroups[]:

```c
{NID_ffdhe4096, SSL_CURVE_FFDHE4096, "dhe4096", "ffdhe4096"},
{NID_ffdhe6144, SSL_CURVE_FFDHE6144, "dhe6144", "ffdhe6144"},
{NID_ffdhe8192, SSL_CURVE_FFDHE8192, "dhe8192", "ffdhe8192"},
```


## X448 (curve 30)

BoringSSL 673e61fc has no X448 crypto implementation at all. But for fingerprinting we only need to advertise it in supported_groups — no key share needed. Servers won't pick X448 when X25519 and P-256 are available.

In include/openssl/ssl.h:

```c
#define SSL_GROUP_X448 0x001e
#define SSL_CURVE_X448 SSL_GROUP_X448
```

In ssl/ssl_key_share.cc kNamedGroups[] (NID_X448=961 already exists in nid.h):

```c
{NID_X448, SSL_GROUP_X448, "X448", "x448"},
```

The tricky part: ssl_setup_key_shares in ssl/extensions.cc will crash if it tries to create a key share for X448 (SSLKeyShare::Create returns nullptr). Fix by checking Create() before selecting a group for key share generation:

```c
group_id = 0;
for (size_t i = 0; i < groups.size(); i++) {
  if (group_id == 0 && SSLKeyShare::Create(groups[i])) {
    group_id = groups[i];
  } else if (enable_second_key_share && second_group_id == 0 &&
             SSLKeyShare::Create(groups[i]) &&
             (is_custom || is_post_quantum_group(group_id) != is_post_quantum_group(groups[i]))) {
    second_group_id = groups[i];
  } else if (enable_three_key_shares && third_group_id == 0 &&
             SSLKeyShare::Create(groups[i]) &&
             (is_custom || is_post_quantum_group(group_id) != is_post_quantum_group(groups[i]))) {
    third_group_id = groups[i];
  }
}
if (group_id == 0) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_NO_GROUPS_SPECIFIED);
  return false;
}
```

This replaces the original group selection block. Groups without key share support (X448, ffdhe*) still appear in supported_groups extension but are skipped for actual key share generation.


## Extension 22 (encrypt_then_mac)

Just advertise an empty extension in ClientHello. No real encrypt-then-mac logic needed since we use AEAD ciphers for actual data.

In include/openssl/tls1.h:

```c
#define TLSEXT_TYPE_encrypt_then_mac 22
```

In include/openssl/ssl.h:

```c
OPENSSL_EXPORT void SSL_set_encrypt_then_mac(SSL *ssl, int enabled);
OPENSSL_EXPORT void SSL_CTX_set_encrypt_then_mac(SSL_CTX *ctx, int enabled);
```

In ssl/internal.h add `bool encrypt_then_mac = false;` to both SSL_CONFIG and ssl_ctx_st.

In ssl/ssl_lib.cc implement the two functions (trivial setters) and propagate from ctx to config in SSL_new().

In ssl/extensions.cc add the extension handler — only encrypt_then_mac_add_clienthello does anything (writes the extension type + empty body). The rest just return true. Register in kExtensions[] before record_size_limit.


## curl side

Add CURLOPT_TLS_ENCRYPT_THEN_MAC (next free ID) in include/curl/curl.h.

Add `BIT(tls_encrypt_then_mac)` in lib/urldata.h.

Handle it in lib/setopt.c, register in lib/easyoptions.c.

Apply in lib/vtls/openssl.c:

```c
if(data->set.tls_encrypt_then_mac) {
  SSL_CTX_set_encrypt_then_mac(octx->ssl_ctx, 1);
}
```


## impers JS wrapper

In dist/utils/fingerprint.js add 0xccaa to cipher map, 30/258/259/260 to curves map, 22 to toggleable extensions with the curl option call.

In dist/ffi/constants.js add CURLOPT_TLS_ENCRYPT_THEN_MAC with matching ID.


## Build

```
# boringssl
patch -p1 < boringssl.patch
mkdir build && cd build && cmake -GNinja .. -DCMAKE_BUILD_TYPE=Release && ninja ssl crypto
mkdir -p ../lib && cp libssl.a libcrypto.a ../lib/

# curl (with curl.patch applied)
autoreconf -fi
./configure --with-openssl=<boringssl> --with-brotli --with-nghttp2 --with-zstd \
  --without-ngtcp2 --without-nghttp3 --without-libpsl --enable-websockets \
  CPPFLAGS="-I<boringssl>/include" LDFLAGS="-L<boringssl>/lib" LIBS="-lc++"
make -j4
```

Result is lib/.libs/libcurl-impersonate.4.dylib. Test with LIBCURL_IMPERSONATE_PATH or drop it in the impers cache.


## Additional fixes for JA3 hash accuracy

Two more things that cause the JA3 hash to differ from the real browser:

### ec_point_formats: send 0-1-2 instead of just 0

BoringSSL only sends uncompressed (0). Firefox sends all three formats. In ssl/extensions.cc, ext_ec_point_add_extension:

```c
!CBB_add_u8(&formats, TLSEXT_ECPOINTFORMAT_uncompressed) ||
!CBB_add_u8(&formats, TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime) ||
!CBB_add_u8(&formats, TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2) ||
```

Also need to define the missing constant in include/openssl/tls1.h:

```c
#define TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2 2
```

### Disable automatic padding extension when extension_order is set

BoringSSL adds padding (ext 21) automatically for the F5 workaround. This breaks JA3 when the target fingerprint doesn't include padding. In ssl/extensions.cc, add a check before the padding logic:

```c
if (hs->config->extension_order == nullptr &&
    !SSL_is_dtls(ssl) && !SSL_is_quic(ssl) &&
    !ssl->s3->used_hello_retry_request) {
```

This skips padding when a custom extension order is active (i.e. fingerprinting mode). The original condition was just `!SSL_is_dtls(ssl) && !SSL_is_quic(ssl) && !ssl->s3->used_hello_retry_request`.
