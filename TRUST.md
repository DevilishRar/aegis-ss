# TRUST

Trust is a process, not a promise. Do these steps in order.

## 1. Get the source

    git clone https://github.com/DevilishRar/aegis-ss.git
    cd aegis-ss
    git checkout v1.0.0

## 2. Audit the source

There is no network code in the tree. Prove it:

    findstr /s /i "std::net TcpStream UdpSocket reqwest wininet WinHttpOpen InternetOpen" *.rs

Expected output: only the self check explanatory strings. Registry writes do not exist:

    findstr /s /i "set_value create_subkey RegSetValueEx RegCreateKeyEx" *.rs

Expected output: none in scanner logic.

## 3. Build it yourself

    rustup toolchain install 1.99.1
    cargo build --release --locked
    cargo test --release --locked

Windows binaries are not guaranteed bit identical across machines. Do not treat identical hashes as the only check. Source review plus test pass plus the runtime self check is the safety argument.

## 4. Compare hashes anyway

    certutil -hashfile aegis-ss.exe SHA256
    certutil -hashfile aegis-cli.exe SHA256

Compare the output to SHA256SUMS.txt in the release. This proves the file you are about to run is the file that was published. It does not prove running it is safe. The source audit above is the safety argument.

## 5. Runtime proof

The GUI Trust audit page and both binaries show at runtime:

* process ID
* network isolation status proving zero TCP sockets are owned by this process
* SHA256 of the running executable
* the exact queries each module performs

## 6. Independent verification

Every release lists hashes. Community members are encouraged to:

* build from source and compare against the published hashes
* upload the release binaries to their own preferred scanners
* report discrepancies as public issues

## If any step fails

Do not run it. File a public issue with the step that failed and the output.
