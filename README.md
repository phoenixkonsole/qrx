## Fixed Linux Build with openssl build script

Clone the repository:

bash
git clone https://github.com/phoenixkonsole/qrx.git
cd qrx/qrx-core


Build the bundled OpenSSL dependency (required for hybrid wallets):

bash
chmod +x scripts/build-openssl.sh
./scripts/build-openssl.sh

This script automatically downloads and builds the required OpenSSL version with ML-DSA support into:


/opt/qrx-openssl


No manual OpenSSL installation is required.

---

Build QRX:

bash
mkdir build
cd build

cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR=/opt/qrx-openssl

make -j$(nproc)


---

Verify the resulting binary:

bash
ldd ./qrxd | grep crypto


Expected output:


libcrypto.so.3 => /opt/qrx-openssl/lib64/libcrypto.so.3


---

Run your node:

bash
./qrxd \
  --network alpha \
  --addnode seed1.qrxchain.org:26661
