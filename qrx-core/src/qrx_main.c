#include <openssl/evp.h>
#include "qrx_core.h"
int main(int argc, char **argv) {
    OpenSSL_add_all_algorithms();
    return qrx_backend_main(argc, argv);
}
