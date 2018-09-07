#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <vector>
#include <string_view>
#include <iostream>
#include <cstring>
#include <fstream>

#include <openssl/bio.h>
#include <openssl/pem.h>

using bio_s_mem_type         = BIO_METHOD *(*)(void);
using bio_new_type           = BIO *(*)(BIO_METHOD *);
using bio_puts_type          = int (*)(BIO *b, void *buf, int len);
using bio_read_type          = int (*)(BIO *b, void *buf, int len);
using bio_write_type         = int (*)(BIO *b, const void *buf, int len);
using bio_free_all_type      = void (*)(BIO *b);
using pem_read_bio_x509_type = X509 *(*)(BIO *b,
                                         X509 **,
                                         pem_password_cb *cb,
                                         void            *u);

bio_s_mem_type         bio_s_mem;
bio_new_type           bio_new;
bio_puts_type          bio_puts;
bio_read_type          bio_read;
bio_write_type         bio_write;
bio_free_all_type      bio_free_all;
pem_read_bio_x509_type pem_read_bio_x509;

void process(BIO* certbio, BIO* outbio)
{
    EVP_PKEY *pkey = NULL;
    X509     *cert = NULL;
    
    if (!(cert = (*pem_read_bio_x509)(certbio, NULL, 0, NULL))) {
        const char* err = "Error loading cert into memory\n";
        (*bio_write)(outbio, (void*)err, std::strlen(err));
        return;
    }

#if 0
    if ((pkey = X509_get_pubkey(cert)) == NULL)
        BIO_printf(outbio, "Error getting public key from certificate");

    /* display the key type and size here */
    if (pkey) {
        switch (pkey->type) {
          case EVP_PKEY_RSA:
            BIO_printf(outbio, "%d bit RSA Key\n\n", EVP_PKEY_bits(pkey));
            break;
          case EVP_PKEY_DSA:
            BIO_printf(outbio, "%d bit DSA Key\n\n", EVP_PKEY_bits(pkey));
            break;
          default:
            BIO_printf(
                outbio, "%d bit non-RSA/DSA Key\n\n", EVP_PKEY_bits(pkey));
            break;
        }
    }

    if (!PEM_write_bio_PUBKEY(outbio, pkey))
        BIO_printf(outbio, "Error writing public key data in PEM format");

    EVP_PKEY_free(pkey);
    X509_free(cert);
#endif
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

    bio_s_mem    = (bio_s_mem_type)dlsym(handle, "BIO_s_mem");
    bio_new      = (bio_new_type)dlsym(handle, "BIO_new");
    bio_puts     = (bio_puts_type)dlsym(handle, "BIO_puts");
    bio_read     = (bio_read_type)dlsym(handle, "BIO_read");
    bio_write    = (bio_write_type)dlsym(handle, "BIO_write");
    bio_free_all = (bio_free_all_type)dlsym(handle, "BIO_free_all");
    pem_read_bio_x509 =
        (pem_read_bio_x509_type)dlsym(handle, "PEM_read_bio_X509");

    // --------------- HANDLE errors

    if ((error = dlerror()) != NULL) {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }

    // --------------- USE library

    BIO_METHOD *m       = (*bio_s_mem)();

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
