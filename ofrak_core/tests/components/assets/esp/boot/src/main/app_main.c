#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_rom_sys.h"

extern int target(int n);

void app_main(void)
{
    /* The injected patch (esp_patch_entry) has the same int(int) signature, so retargeting this
     * call is calling-convention safe. Unpatched prints 7; after the OFRAK redirect it prints
     * esp_patch_entry(7). esp_rom_printf writes straight to the ROM UART, keeping the image small
     * (no newlib/VFS stdout stack) so the whole IROM disassembles quickly. */
    esp_rom_printf("ESP_PATCH_RESULT=%d\n", target(7));
    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}
