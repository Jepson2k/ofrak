/*
 * Self-contained Xtensa patch used to prove the OFRAK ESP compile -> inject -> repack path.
 *
 * Public-domain test fixture. It references no external symbols and no libc, so it links
 * standalone into a single .text segment (the literals stay inline thanks to
 * -mtext-section-literals). The exact behaviour is irrelevant; the test only needs real
 * Espressif-Xtensa machine code to compile, inject into a real ESP32 app image, and survive a
 * repack + esptool validation.
 */
int esp_patch_entry(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) {
        acc += i * 3 + 1;
    }
    return acc;
}
