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

// drivers
#include "driver/uart_vfs.h"
#include "driver/uart.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"

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
static const char* TAG = "example";

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

// freeRTOS handles
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
    // flush stdout
    fflush(stdout);
    fsync(fileno(stdout));

    // disable buffering
    setvbuf(stdin, NULL, _IONBF, 0);

    usb_serial_jtag_vfs_set_rx_line_endings(ESP_LINE_ENDINGS_CR);
    usb_serial_jtag_vfs_set_rx_line_endings(ESP_LINE_ENDINGS_CRLF);
    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    usb_serial_jtag_driver_install(&cfg);

    usb_serial_jtag_vfs_register();

    // initialize console
    esp_console_config_t console_config = {
        .max_cmdline_args = 8,
        .max_cmdline_length = 256,
    #if CONFIG_LOG_COLORS
        .hint_color = atoi(LOG_COLOR_CYAN)
    #endif
    };
    ESP_ERROR_CHECK( esp_console_init(&console_config) );

    // configure linenoise
    linenoiseSetMultiLine(1);

    // when to do line completion
    linenoiseSetCompletionCallback(&esp_console_get_completion);
    linenoiseSetHintsCallback((linenoiseHintsCallback*) &esp_console_get_hint);

    // max history size
    linenoiseHistorySetMaxLen(100);

    // max command length
    linenoiseSetMaxLineLen(console_config.max_cmdline_length);

    // no empty lines
    linenoiseAllowEmpty(false);

    #if CONFIG_STORE_HISTORY
        // load command history
        linenoiseHistoryLoad(HISTORY_PATH);
    #endif

    ESP_LOGI(TAG, "CLI initialized successfully");
}

void app_main(void)
{
    // initialize stuff
    nvs_init();

    #if CONFIG_STORE_HISTORY
        fs_init();
        ESP_LOGI(TAG, "Command history enabled");
    #else
        ESP_LOGI(TAG, "Command history disabled");
    #endif

    cli_init();

    // registering
    esp_console_register_help_command();
    register_system_common();
    #if SOC_LIGHT_SLEEP_SUPPORTED
        register_system_light_sleep();
    #endif
    #if SOC_DEEP_SLEEP_SUPPORTED
        register_system_deep_sleep();
    #endif
    #if SOC_WIFI_SUPPORTED
        register_wifi();
    #endif
        register_nvs();

    // prompt before each line
    const char* prompt = LOG_COLOR_I PROMPT_STRING "> " LOG_RESET_COLOR;

    printf("\n"
           "Type 'help' to get the list of commands.\n"
           "Use UP/DOWN arrows to navigate through command history.\n"
           "Press TAB when typing command name to auto-complete.\n"
           "Press Enter or Ctrl+C will terminate the console environment.\n");

        /* Figure out if the terminal supports escape sequences */
    int probe_status = linenoiseProbe();
    if (probe_status) { /* zero indicates success */
        printf("\n"
               "Your terminal application does not support escape sequences.\n"
               "Line editing and history features are disabled.\n"
               "On Windows, try using Putty instead.\n");
        linenoiseSetDumbMode(1);
    #if CONFIG_LOG_COLORS
        /* Since the terminal doesn't support escape sequences,
         * don't use color codes in the prompt.
         */
        prompt = PROMPT_STRING "> ";
    #endif //CONFIG_LOG_COLORS
    }

    // main loop
    while(true) {
        // get a line using linenoise
        char* line = linenoise(prompt);
        if (line == NULL) { // break on EOF or error
            printf("Line input is null");
            break;
        }
        // add line to history
        if (strlen(line) > 0) {
            linenoiseHistoryAdd(line);
    #if CONFIG_STORE_HISTORY
            // save history to fs
            linenoiseHistorySave(HISTORY_PATH);
    #endif
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    // run the command
    int ret;
    esp_err_t err = esp_console_run(line, &ret);
    if (err == ESP_ERR_NOT_FOUND) {
        printf("Unrecognized command\n");
    } else if (err == ESP_ERR_INVALID_ARG) {
        // command was empty
    } else if (err == ESP_OK && ret != ESP_OK) {
        printf("Command returned non-zero error code: 0x%x (%s)\n", ret, esp_err_to_name(ret));
    } else if (err != ESP_OK) {
        printf("Internal error: %s\n", esp_err_to_name(err));
    }
        // free the heap
        linenoiseFree(line);
    }

    ESP_LOGE(TAG, "Error or end-of-input, terminating console");
    esp_console_deinit();
}
