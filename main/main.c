/*
 * esp32c6-sniffer: a proof of concept ESP32C6 sniffer
 * Copyright (C) 2024 dj1ch
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
*/

// standard c libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// esp32 wifi libraries
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_console.h"
#include "esp_vfs_fat.h"
#include "esp_task_wdt.h"
#include "esp_vfs_dev.h"

// other CLI related libraries
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"
#include "soc/soc_caps.h"

// cli components
#include "cmd_nvs.h"
#include "cmd_system.h"
#include "cmd_wifi.h"

// nvs libraries
#include "nvs.h"
#include "nvs_flash.h"

// lwip libraries
#include "lwip/err.h"
#include "lwip/sys.h"

// freeRTOS libraries
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

// gpio libraries
#include "driver/gpio.h"

// define terminal thingy
#define PROMPT_STRING "esp32c6"

#define WDT_TIMEOUT 3 // 3 second timeout

// warnings from https://github.com/espressif/esp-idf/blob/v5.3/examples/system/console/advanced/main/console_example_main.c#L33C1-L45C45
#if SOC_USB_SERIAL_JTAG_SUPPORTED
#if !CONFIG_ESP_CONSOLE_SECONDARY_NONE
#warning "A secondary serial console is not useful when using the console component. Please disable it in menuconfig."
#endif
#endif

#if CONFIG_STORE_HISTORY
// filesystem
void fs_init(void);
#endif // CONFIG_STORE_HISTORY

// nvs
void nvs_init(void);

// CLI
void cli_init(void);

// watchdog
void wdt_reset(void *pvParameter);

// freeRTOS handles if needed
TaskHandle_t sniffer_task;
TaskHandle_t cli_task;

#if CONFIG_STORE_HISTORY

#define MOUNT_PATH "/data"
#define HISTORY_PATH MOUNT_PATH "/history.txt"

/**
 * Initializes NVS (if needed)
 */
void fs_init(void)
{
    static wl_handle_t wl_handle;
    const esp_vfs_fat_mount_config_t mount_config = {
            .max_files = 4,
            .format_if_mount_failed = true
    };
    esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl(MOUNT_PATH, "storage", &mount_config, &wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FATFS (%s)", esp_err_to_name(err));
        return;
    }
}
#endif // CONFIG_STORE_HISTORY

/**
 * Initializes NVS
 */
void nvs_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK( nvs_flash_erase() );
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

/**
 * Initializes the console
 */
void cli_init(void)
{
    // init NVS and fs if needed
    nvs_init();
    #if CONFIG_STORE_HISTORY
    fs_init();
    #endif

    // configure REPL
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = PROMPT_STRING "> ";
    repl_config.max_cmdline_length = 256;

    // commands
    esp_console_register_help_command();
    register_system_common();
    #if SOC_WIFI_SUPPORTED
    register_wifi();
    #endif
    register_nvs();

    // initialize repl
    #if defined(CONFIG_ESP_CONSOLE_UART_DEFAULT) || defined(CONFIG_ESP_CONSOLE_UART_CUSTOM)
    esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&hw_config, &repl_config, &repl));

    #elif defined(CONFIG_ESP_CONSOLE_USB_CDC)
    esp_console_dev_usb_cdc_config_t hw_config = ESP_CONSOLE_DEV_CDC_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_cdc(&hw_config, &repl_config, &repl));

    #elif defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG)
    esp_console_dev_usb_serial_jtag_config_t hw_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&hw_config, &repl_config, &repl));
    ESP_ERROR_CHECK(esp_console_start_repl(repl));

    #else
    #error Unsupported console type
    #endif

}


void app_main(void)
{
    // init watchdog
    static bool wdt_init = false;

    if (!wdt_init) {
        esp_task_wdt_config_t wdt_cfg = {
            .timeout_ms = WDT_TIMEOUT * 1000,
            .idle_core_mask = 0,
            .trigger_panic = true
        };
        esp_task_wdt_init(&wdt_cfg);
        esp_task_wdt_add(cli_task);
        wdt_init = true;
    }

    // create task
    // xTaskCreatePinnedToCore(cli_init, "CLI Task", 2048, NULL, 1, &cli_task, 0);

    cli_init();
}
