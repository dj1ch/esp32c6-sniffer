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

// other CLI related libraries
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"
#include "soc/soc_caps.h"
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

// ESP32 LED PIN
#define LED_PIN 7

// warnings from https://github.com/espressif/esp-idf/blob/v5.3/examples/system/console/advanced/main/console_example_main.c#L33C1-L45C45
#if SOC_USB_SERIAL_JTAG_SUPPORTED
#if !CONFIG_ESP_CONSOLE_SECONDARY_NONE
#warning "A secondary serial console is not useful when using the console component. Please disable it in menuconfig."
#endif
#endif

#ifdef CONFIG_ESP_CONSOLE_USB_CDC
#error This firmware is incompatible with a USB CDC console.
#endif // CONFIG_ESP_CONSOLE_USB_CDC

#ifdef CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
#error This firmware is incompatible with a USB serial JTAG console.
#endif // CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG

/**
 * IEEE 802.11 Wifi Structures from ESP32-Sniffer example
 * Source: https://github.com/lpodkalicki/blog/blob/master/esp32/016_wifi_sniffer/main/main.c#L22
 * 
 * I'm not sure if you would consider this an easter egg but this was also included in the Minigotchi!
 * Link: https://github.com/dj1ch/minigotchi/blob/main/minigotchi/structs.h#L141
 */
typedef struct {
	unsigned frame_ctrl:16;
	unsigned duration_id:16;
	uint8_t addr1[6]; /* receiver address */
	uint8_t addr2[6]; /* sender address */
	uint8_t addr3[6]; /* filtering address */
	unsigned sequence_ctrl:16;
	uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
	wifi_ieee80211_mac_hdr_t hdr;
	uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

#if CONFIG_STORE_HISTORY
// filesystem
void fs_init(void);
#endif // CONFIG_STORE_HISTORY

// nvs
void nvs_init(void);

// CLI
void cli_init(void);
void cli_loop(void *pvParameters);

// misc
int random_num(int min, int max);

// sniffer related
void sniffer_init(void *pvParameters);
void sniffer_stop();

// functions relating to sniffer callback
void get_mac(char *addr, const unsigned char *buff, int offset);
char *extract_mac(const unsigned char *buff);
char *get_type(wifi_promiscuous_pkt_type_t type);

// channel stuff
int current_channel();
bool switch_channel(int channel);
bool filter_mac(char *mac, char *current);

// sniffer callback
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type);

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

    uart_vfs_dev_port_set_rx_line_endings(CONFIG_ESP_CONSOLE_UART_NUM, ESP_LINE_ENDINGS_CR);
    uart_vfs_dev_port_set_tx_line_endings(CONFIG_ESP_CONSOLE_UART_NUM, ESP_LINE_ENDINGS_CRLF);

    // uart config
        const uart_config_t uart_config = {
            .baud_rate = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
    #if SOC_UART_SUPPORT_REF_TICK
        .source_clk = UART_SCLK_REF_TICK,
    #elif SOC_UART_SUPPORT_XTAL_CLK
        .source_clk = UART_SCLK_XTAL,
    #endif

        };

    // install uart driver
    ESP_ERROR_CHECK( uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM,
            256, 0, 0, NULL, 0) );
    ESP_ERROR_CHECK( uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config) );

    // vfs
    uart_vfs_dev_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);

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
}

/**
 * Handles commands sent in the console
 */
void cli_loop(void *pvParameters)
{
    // prompt before each line
    const char* prompt = LOG_COLOR_I PROMPT_STR "> " LOG_RESET_COLOR;

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
        prompt = PROMPT_STR "> ";
    #endif //CONFIG_LOG_COLORS
    }

    // main loop
    while(true) {
        // get a line using linenoise
        char* line = linenoise(prompt);
        if (line == NULL) { // break on EOF or error
            break;
        }
        // add line to history
        if (strlen(line) > 0) {
            linenoiseHistoryAdd(line);
    #if CONFIG_STORE_HISTORY
            // save history to fs
            linenoiseHistorySave(HISTORY_PATH);
    #endif
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

/**
 * Generates random number
 * @param min Minimum number
 * @param max Maximum number
 * @return The random number
 */
int random_num(int min, int max) { return min + rand() % (max - min + 1); }

/**
 * Starts the sniffer, initializes configuration
 * @param pvParameters Ignore this, it's for freeRTOS
 */
void sniffer_init(void *pvParameters) 
{
    // set wifi config
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_country_t ctry_cfg = {.cc="US", .schan = 1, .nchan = 13};

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_country(&ctry_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    // turn on mon mode, change channel
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_channel(random_num(1, 13), WIFI_SECOND_CHAN_NONE));

    printf("Currently on channel %i", current_channel());

    // set cb
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);

    // wait forever
    while (true) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}

/**
 * Stops the sniffer callback
 */
void stop_sniffer(void)
{
    esp_wifi_set_promiscuous_rx_cb(NULL);
}

/**
 * Get's the mac based on source address
 * @param addr Address to use
 * @param buff Buffer to use
 * @param offset Data offset
 */
void get_mac(char *addr, const unsigned char *buff, int offset) {
    snprintf(addr, 18, "%02x:%02x:%02x:%02x:%02x:%02x", buff[offset],
             buff[offset + 1], buff[offset + 2], buff[offset + 3],
             buff[offset + 4], buff[offset + 5]);
}

/**
 * Extract Mac Address using get_mac()
 * @param buff Buffer to use
 * @return Source Mac Address from buffer
 */
char *extract_mac(const unsigned char *buff) {
    static char addr[] = "00:00:00:00:00:00";
    get_mac(addr, buff, 10);
    return addr;
}

/**
 * Acquires the type of Wifi packet
 * @param type Type of packet
 * @return Specific type of Wifi packet
 */
char *get_type(wifi_promiscuous_pkt_type_t type) {
    switch(type) {
        case WIFI_PKT_MGMT:
            return "Management Packet";
        case WIFI_PKT_DATA:
            return "Data Packet";
        case WIFI_PKT_MISC:
            return "Misc Packet";
        default:
            return "Unknown Packet";
    }
}

/**
 * Returns current Wifi channel as an integer
 * @return Current Wifi channel
 */
int current_channel() 
{
    uint8_t primary;
    wifi_second_chan_t second;
    esp_wifi_get_channel(&primary, &second);
    return primary;
}

/**
 * Switch channels
 * @param channel Channel to switch to
 * @return Whether or not the switch was successful
 */
bool switch_channel(int channel)
{
    // switch channel then check if our current channel matches
    ESP_ERROR_CHECK(esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE));
    if (channel == current_channel()) 
    {
        return true;
    } 
    else 
    {
        return false;
    }
}

/**
 * Checks whether or not mac we're filtering for matches the current mac address found in the callback
 * @param mac
 * @param current
 * @return Result of whether or not mac addresses match
 */
bool filter_mac(char *mac, char *current) 
{
    if (mac == current) 
    {
        return true;
    }
    else
    {
        return false;
    }
}

/**
 * Sniffer callback
 * @param buf Packet buffer
 * @param type Type of Packet
 */
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    // start with LED off
    esp_rom_gpio_pad_select_gpio(LED_PIN);
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(LED_PIN, 0);

    char *packet_type = get_type(type);
    char *mac = extract_mac(buf);

    wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t *)buf;
    int len = snifferPacket->rx_ctrl.sig_len;

    // turn on
    gpio_set_level(LED_PIN, 1);

    printf("Packet type: %s\n", packet_type);
    printf("Packet Length: %i\n", len);
    printf("Packet Mac Address: %s\n", mac);
    printf("Current Channel: %i\n", current_channel());
    printf("\n");

    // turn off
    gpio_set_level(LED_PIN, 0);
}

void app_main(void)
{
    // initialize stuff
    nvs_init();

    #if CONFIG_STORE_HISTORY
        initialize_filesystem();
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

    // create tasks
    xTaskCreatePinnedToCore(sniffer_init, "Sniffer Task", 4096, NULL, 1, &sniffer_task, 0);
    xTaskCreatePinnedToCore(cli_init, "CLI Task", 4096, NULL, 1, &cli_task, 1);
}
