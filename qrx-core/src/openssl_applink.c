/*
 * Windows/OpenSSL applink support.
 *
 * Required when QRX is built with MSVC and linked against OpenSSL.
 * This fixes runtime errors such as:
 *
 *   OPENSSL_Uplink(...): no OPENSSL_Applink
 *
 * The object must be linked into each Windows executable that uses OpenSSL.
 */

#ifdef _WIN32
#include <openssl/applink.c>
#endif
