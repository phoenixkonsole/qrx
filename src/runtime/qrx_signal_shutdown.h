#pragma once

#include <signal.h>

extern volatile sig_atomic_t qrx_running;

void qrx_install_signal_handlers(void);
