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

#include <openssl/bio.h>
#include <openssl/pem.h>


template<class R, class... Args>
class Dynamic {
  using func = std::function<R(Args...)>;
  using return_type = R;

  func d_func;

  public:
    Dynamic(void* handle, const char* symbol)
    {
      using sig_p = R(*)(Args...); 

      sig_p s = (sig_p) dlsym(handle, symbol);

      d_func = s;
    }
  
    return_type operator()(Args&&... args)
    {
      return d_func(std::forward<Args>(args)...);
    };
};

using bio_new_type              = BIO *(*)(BIO_METHOD *);
using bio_puts_type             = int (*)(BIO *b, void *buf, int len);
using bio_read_type             = int (*)(BIO *b, void *buf, int len);
using bio_write_type            = int (*)(BIO *b, const void *buf, int len);
using bio_free_all_type         = void (*)(BIO *b);
using pem_read_bio_x509_type    = X509 *(*)(BIO *b,
                                         X509 **,
                                         pem_password_cb *cb,
                                         void            *u);
using pem_write_bio_pubkey_type = int (*)(BIO *, EVP_PKEY *);
using x509_get_pubkey_type      = EVP_PKEY *(*)(X509 *);
using x509_free_type            = void (*)(X509 *);
using evp_pkey_free_type        = void (*)(EVP_PKEY *);
using evp_pkey_bits_type        = int (*)(EVP_PKEY *);

bio_new_type              bio_new;
bio_puts_type             bio_puts;
bio_read_type             bio_read;
bio_write_type            bio_write;
bio_free_all_type         bio_free_all;
pem_read_bio_x509_type    pem_read_bio_x509;
pem_write_bio_pubkey_type pem_write_bio_pubkey;
x509_get_pubkey_type      x509_get_pubkey;
x509_free_type            x509_free;
evp_pkey_free_type        evp_pkey_free;
evp_pkey_bits_type        evp_pkey_bits;

void process(BIO* certbio, BIO* outbio)
{
    EVP_PKEY *pkey = NULL;
    X509     *cert = NULL;
    
    if (!(cert = (*pem_read_bio_x509)(certbio, NULL, 0, NULL))) {
        const char* err = "Error loading cert into memory\n";
        (*bio_write)(outbio, (void*)err, std::strlen(err));
        return;
    }

    if ((pkey = (*x509_get_pubkey)(cert)) == NULL) {
        const char* err = "Error getting public key from certificate";
        (*bio_write)(outbio, (void*)err, std::strlen(err));
    }

    /* display the key type and size here */
    if (pkey) {
        std::ostringstream info;

        int bits = (*evp_pkey_bits)(pkey);

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

        (*bio_write)(outbio, (void*) info.str().c_str(), info.str().size());
    }

    if (!(*pem_write_bio_pubkey)(outbio, pkey)) {
        const char* err = "Error writing public key data in PEM format";
        (*bio_write)(outbio, (void*)err, std::strlen(err));
    }

    (*evp_pkey_free)(pkey);
    (*x509_free)(cert);
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

    Dynamic<BIO_METHOD*> bio_s_mem(handle, "BIO_s_mem");

    bio_new      = (bio_new_type)dlsym(handle, "BIO_new");
    bio_puts     = (bio_puts_type)dlsym(handle, "BIO_puts");
    bio_read     = (bio_read_type)dlsym(handle, "BIO_read");
    bio_write    = (bio_write_type)dlsym(handle, "BIO_write");
    bio_free_all = (bio_free_all_type)dlsym(handle, "BIO_free_all");
    pem_read_bio_x509 =
        (pem_read_bio_x509_type)dlsym(handle, "PEM_read_bio_X509");
    pem_write_bio_pubkey =
        (pem_write_bio_pubkey_type)dlsym(handle, "PEM_write_bio_PUBKEY");
    x509_get_pubkey = (x509_get_pubkey_type)dlsym(handle, "X509_get_pubkey");
    x509_free       = (x509_free_type)dlsym(handle, "X509_free");
    evp_pkey_free   = (evp_pkey_free_type)dlsym(handle, "EVP_PKEY_free");
    evp_pkey_bits   = (evp_pkey_bits_type)dlsym(handle, "EVP_PKEY_bits");
    // --------------- HANDLE errors

    if ((error = dlerror()) != NULL) {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }

    // --------------- USE library

    BIO_METHOD *m       = bio_s_mem();

    BIO        *certbio = (*bio_new)(m);
    (*bio_puts)(certbio, (void *)content.data(), content.size());

    BIO        *outbio = (*bio_new)(m);

    process(certbio, outbio);

    std::vector<char> read_buf(1024);

    while (true) {
        int num_read = (*bio_read)(
            outbio, static_cast<void *>(read_buf.data()), read_buf.size());
        if (num_read < 1)
            break;
        std::string_view read(read_buf.data(), num_read);
        std::cout << read;
    }

    (*bio_free_all)(certbio);
    (*bio_free_all)(outbio);
    // ----------- CLOSE dynamic library

    dlclose(handle);
    return 0;
}
