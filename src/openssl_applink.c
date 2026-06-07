/*
 * OpenSSL Applink support for Windows/MSVC builds.
 *
 * Required when OpenSSL is built with a different C runtime boundary than
 * the application. This fixes runtime errors like:
 *   OPENSSL_Uplink(...): no OPENSSL_Applink
 */
#ifdef _WIN32
#include <openssl/applink.c>
#endif
