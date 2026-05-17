#include "qrx_signal_shutdown.h"

volatile sig_atomic_t qrx_running = 1;

static void qrx_handle_signal(int sig) {
    (void)sig;
    qrx_running = 0;
}

void qrx_install_signal_handlers(void) {
    signal(SIGINT, qrx_handle_signal);
    signal(SIGTERM, qrx_handle_signal);
}
