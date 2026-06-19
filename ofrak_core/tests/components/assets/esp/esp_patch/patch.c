int esp_patch_entry(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) {
        acc += i * 3 + 1;
    }
    return acc;
}
