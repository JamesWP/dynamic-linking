/* ------------------------------------------------------------ *
 * file:        certpubkey.c                                    *
 * purpose:     Example code to extract public keydata in certs *
 * author:      09/24/2012 Frank4DD                             *
 *                                                              *
 * gcc -o certpubkey certpubkey.c -lssl -lcrypto                *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <fstream>
#include <iostream>
#include <string_view>
#include <vector>

void process(BIO *certbio, BIO *outbio)
{
    EVP_PKEY *pkey = NULL;
    X509     *cert = NULL;
    
    if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        BIO_printf(outbio, "Error loading cert into memory\n");
        exit(-1);
    }

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
}

int main(int argc, char *argv[])
{
    const char *cert_filestr = "./cert-file.pem";
    BIO        *certbio      = NULL;
    BIO        *outbio       = NULL;

    // OpenSSL_add_all_algorithms();
    // ERR_load_BIO_strings();
    // ERR_load_crypto_strings();

    if (argc > 1)
        cert_filestr = argv[1];

    certbio = BIO_new(BIO_s_mem());

    std::ifstream ifs{cert_filestr};

    std::string content{std::istreambuf_iterator<char>(ifs),
                        std::istreambuf_iterator<char>()};

    BIO_puts(certbio, content.c_str());

    outbio = BIO_new(BIO_s_mem());

    process(certbio, outbio);

    std::vector<char> read_buf(1024);

    while (true) {
        int num_read = BIO_read(
            outbio, static_cast<void *>(read_buf.data()), read_buf.size());
        if (num_read < 1)
            break;

        std::string_view read(read_buf.data(), num_read);
        std::cout << read;
    }
    BIO_free_all(certbio);
    BIO_free_all(outbio);
}
