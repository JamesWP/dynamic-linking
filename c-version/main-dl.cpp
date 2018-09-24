#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string_view>
#include <vector>
#include <functional>
#include <cassert>

#include <openssl/bio.h>
#include <openssl/pem.h>

template <class R, class... Args>
class Dynamic {
    using func        = std::function<R(Args...)>;
    using return_type = R;

    // data members
    func              d_func;
    const char *const d_symbol;

  public:
    Dynamic(const char *symbol): d_symbol{symbol} {}

    void init(void *handle)
    {
        using sig_p = R (*)(Args...);

        sig_p s = (sig_p)dlsym(handle, d_symbol);

        d_func = s;

        const char* error;
        if ((error = dlerror()) != NULL) {
            throw std::runtime_error(error);
        }
    }

    // the extra template params are needed to support implicit conversions?
    template<class...CallArgs>
    return_type operator()(CallArgs&&... args)
    {
        assert(d_func);  // must have called init first
        return d_func(std::forward<CallArgs>(args)...);
    };
};

Dynamic<BIO_METHOD *>            bio_s_mem("BIO_s_mem");
Dynamic<BIO *, BIO_METHOD *>     bio_new("BIO_new");
Dynamic<int, BIO *, void *, int> bio_puts("BIO_puts");
Dynamic<int, BIO *, void *, int> bio_read("BIO_read");
Dynamic<int, BIO *, const void *, int> bio_write("BIO_write");
Dynamic<void, BIO*> bio_free_all("BIO_free_all");

using prbx = Dynamic<X509 *, BIO *, X509 **, pem_password_cb *, void *>;
prbx pem_read_bio_x509("PEM_read_bio_X509");

Dynamic<int, BIO *, EVP_PKEY *> pem_write_bio_pubkey("PEM_write_bio_PUBKEY");
Dynamic<EVP_PKEY *, X509 *>     x509_get_pubkey("X509_get_pubkey");
Dynamic<void, X509 *>           x509_free("X509_free");
Dynamic<void, EVP_PKEY *>       evp_pkey_free("EVP_PKEY_free");
Dynamic<int, EVP_PKEY *>        evp_pkey_bits("EVP_PKEY_bits");

void process(BIO* certbio, BIO* outbio)
{
    EVP_PKEY *pkey = NULL;
    X509     *cert = NULL;
    
    if (!(cert = pem_read_bio_x509(certbio, nullptr, nullptr, nullptr))) {
        const char* err = "Error loading cert into memory\n";
        bio_write(outbio, (void*)err, std::strlen(err));
        return;
    }

    if ((pkey = x509_get_pubkey(cert)) == NULL) {
        const char* err = "Error getting public key from certificate";
        bio_write(outbio, (void*)err, std::strlen(err));
    }

    /* display the key type and size here */
    if (pkey) {
        std::ostringstream info;

        int bits = evp_pkey_bits(pkey);

        switch (pkey->type) {
          case EVP_PKEY_RSA:
            info << bits << " bit RSA Key\n\n";
            break;
          case EVP_PKEY_DSA:
            info << bits << " bit DSA Key\n\n";
            break;
          default:
            info << bits << " bit non-RSA/DSA Key\n\n";
            break;
        }

        bio_write(outbio, (void*) info.str().c_str(), info.str().size());
    }

    if (!pem_write_bio_pubkey(outbio, pkey)) {
        const char* err = "Error writing public key data in PEM format";
        bio_write(outbio, (void*)err, std::strlen(err));
    }

    evp_pkey_free(pkey);
    x509_free(cert);
}

int main(int argc, char **argv)
{
    // ------------------- OPEN the dynamic lib

    void *handle;
    char *error;
    
    handle = dlopen("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0", RTLD_LAZY);

    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(1);
    }

    dlerror(); /* Clear any existing error */

    // ---------------- READ input
 
    char* cert_filestr; 
    if (argc > 1)
        cert_filestr = argv[1];

    std::ifstream ifs{cert_filestr};

    std::string content{std::istreambuf_iterator<char>(ifs),
                        std::istreambuf_iterator<char>()};

    // ---------------- BIND dynamic methods
    bio_s_mem.init(handle);
    bio_new.init(handle);
    bio_puts.init(handle);
    bio_read.init(handle);
    bio_write.init(handle);
    bio_free_all.init(handle);
    pem_read_bio_x509.init(handle);
    pem_write_bio_pubkey.init(handle);
    x509_get_pubkey.init(handle);
    x509_free.init(handle);
    evp_pkey_free.init(handle);
    evp_pkey_bits.init(handle);

    // --------------- USE library
    BIO_METHOD *m       = bio_s_mem();

    BIO        *certbio = bio_new(m);
    bio_puts(certbio, (void *)content.data(), content.size());

    BIO        *outbio = bio_new(m);

    process(certbio, outbio);

    std::vector<char> read_buf(1024);

    while (true) {
        int num_read = bio_read(
            outbio, static_cast<void *>(read_buf.data()), read_buf.size());
        if (num_read < 1)
            break;
        std::string_view read(read_buf.data(), num_read);
        std::cout << read;
    }

    bio_free_all(certbio);
    bio_free_all(outbio);
    // ----------- CLOSE dynamic library

    dlclose(handle);
    return 0;
}
