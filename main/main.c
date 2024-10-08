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

//-------------------------------------------------------------------------------------------------------------------------
// standard c libraries
//-------------------------------------------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//-------------------------------------------------------------------------------------------------------------------------
// esp32 wifi libraries
//-------------------------------------------------------------------------------------------------------------------------
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

//-------------------------------------------------------------------------------------------------------------------------
// other CLI related libraries
//-------------------------------------------------------------------------------------------------------------------------
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"
#include "soc/soc_caps.h"

//-------------------------------------------------------------------------------------------------------------------------
// cli components
//-------------------------------------------------------------------------------------------------------------------------
#include "cmd_nvs.h"
#include "cmd_system.h"
#include "cmd_wifi.h"

//-------------------------------------------------------------------------------------------------------------------------
// nvs libraries
//-------------------------------------------------------------------------------------------------------------------------
#include "nvs.h"
#include "nvs_flash.h"

//-------------------------------------------------------------------------------------------------------------------------
// lwip libraries
//-------------------------------------------------------------------------------------------------------------------------
#include "lwip/err.h"
#include "lwip/sys.h"

//-------------------------------------------------------------------------------------------------------------------------
// freeRTOS libraries
//-------------------------------------------------------------------------------------------------------------------------
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

//-------------------------------------------------------------------------------------------------------------------------
// gpio libraries
//-------------------------------------------------------------------------------------------------------------------------
#include "driver/gpio.h"

//-------------------------------------------------------------------------------------------------------------------------
// define terminal thingy
//-------------------------------------------------------------------------------------------------------------------------
#define PROMPT_STRING "esp32c6"
const char* TAG = "esp32c6";

//-------------------------------------------------------------------------------------------------------------------------
// warnings from 
// https://github.com/espressif/esp-idf/blob/v5.3/examples/system/console/advanced/main/console_example_main.c#L33C1-L45C45
//-------------------------------------------------------------------------------------------------------------------------
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

void app_main(void)
{
    //-------------------------------------------------------------------------------------------------------------------------
    // init NVS and fs if needed
    //-------------------------------------------------------------------------------------------------------------------------
    nvs_init();
    #if CONFIG_STORE_HISTORY
    fs_init();
    #endif

    //-------------------------------------------------------------------------------------------------------------------------
    // this issue kind of saved my life: http://forum.esp32.com/viewtopic.php?t=39038
    // here you will see the 10 billion (boilerplate) tests I needed to do
    //-------------------------------------------------------------------------------------------------------------------------

    esp_log_level_set("*", ESP_LOG_VERBOSE);

    // configs
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_country_t ctry_cfg = {.cc="US", .schan = 1, .nchan = 13};

    esp_err_t wifi_init_result = esp_wifi_init(&wifi_cfg);

    if (wifi_init_result != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize Wi-Fi: %d", wifi_init_result);
    } else {
        ESP_LOGI(TAG, "Wi-Fi Successfully initialized");
    }

    esp_err_t wifi_storage_result = esp_wifi_set_storage(WIFI_STORAGE_RAM);

    if (wifi_storage_result != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set Wi-Fi storage: %d", wifi_storage_result);
    } else {
        ESP_LOGI(TAG, "Wi-Fi RAM storage set");
    }

    esp_err_t wifi_country_result = esp_wifi_set_country(&ctry_cfg);

    if (wifi_country_result != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set Wi-Fi Country: %d", wifi_country_result);
    } else {
        ESP_LOGI(TAG, "Wi-Fi Country set");
    }

    esp_err_t wifi_mode_result = esp_wifi_set_mode(WIFI_MODE_NULL);

    if (wifi_mode_result != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set Wi-Fi mode to NULL: %d", wifi_mode_result);
    } else {
        ESP_LOGI(TAG, "Wi-Fi Mode set to NULL");
    }

    esp_err_t wifi_start_result = esp_wifi_start();

    if (wifi_start_result != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start WiFi: %s", esp_err_to_name(wifi_start_result));
    } else {
        ESP_LOGI(TAG, "Started WiFi!");
    }

    //-------------------------------------------------------------------------------------------------------------------------
    // set to mon mode
    //-------------------------------------------------------------------------------------------------------------------------
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    //-------------------------------------------------------------------------------------------------------------------------
    // configure REPL
    //-------------------------------------------------------------------------------------------------------------------------
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = PROMPT_STRING "> ";
    repl_config.max_cmdline_length = 256;

    //-------------------------------------------------------------------------------------------------------------------------
    // commands
    //-------------------------------------------------------------------------------------------------------------------------
    esp_console_register_help_command();
    register_system_common();

    //-------------------------------------------------------------------------------------------------------------------------
    // why do i need to do this to myself
    //-------------------------------------------------------------------------------------------------------------------------
    #if SOC_WIFI_SUPPORTED
    register_wifi();
    #endif

    //-------------------------------------------------------------------------------------------------------------------------
    // register nvs after initializing it
    //-------------------------------------------------------------------------------------------------------------------------
    register_nvs();

    //-------------------------------------------------------------------------------------------------------------------------
    // initialize repl
    // i expect you to be using JTAG, but ofc you can use UART if you'd like
    //-------------------------------------------------------------------------------------------------------------------------
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
