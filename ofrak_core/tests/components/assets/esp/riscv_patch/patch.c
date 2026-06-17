/*
 * Self-contained RISC-V patch used to prove the OFRAK ESP compile -> inject -> repack path on the
 * Espressif RISC-V parts (ESP32-C2/C3/C6, ESP32-H2, ESP32-C5, ESP32-P4).
 *
 * Public-domain test fixture. It references no external symbols and no libc, so it links standalone
 * into a single .text segment. The exact behaviour is irrelevant; the test only needs real
 * Espressif-RISC-V machine code to compile, inject into a real ESP32-C3 app image, and survive a
 * repack + esptool validation.
 */
int esp_patch_entry(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) {
        acc += i * 3 + 1;
    }
    return acc;
}
