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

// esp32 wifi libraries
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "esp_log.h"

// other libraries
#include "nvs_flash.h"

// lwip libraries
#include "lwip/err.h"
#include "lwip/sys.h"

// freeRTOS libraries
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

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

// function declarations
int random_num(int min, int max);
void sniffer_init(void *pvParameters);
void get_mac(char *addr, const unsigned char *buff, int offset);
char *extract_mac(const unsigned char *buff);
char *get_type(wifi_promiscuous_pkt_type_t type);
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type);

// freeRTOS handles
TaskHandle_t sniffer_task;
TaskHandle_t Task2; // to do: serial task?

/**
 * Generates random number
 */
int random_num(int min, int max) { return min + rand() % (max - min + 1); }

/**
 * Starts the sniffer, initializes configuration
 */
void sniffer_init(void *pvParameters) 
{
    // set wifi config
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_country_t ctry_cfg = {.cc="US", .schan = 1, .nchan = 13};

    ESP_ERROR_CHECK(esp_wifi_set_country(&ctry_cfg));
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_channel(random_num(1, 13), WIFI_SECOND_CHAN_NONE));

    // set cb
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);

    // wait forever
    while (true) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
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
 */
char *extract_mac(const unsigned char *buff) {
    static char addr[] = "00:00:00:00:00:00";
    get_mac(addr, buff, 10);
    return addr;
}

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
 * Sniffer callback
 * @param buf Packet buffer
 * @param type Type of Packet
 */
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    char *packet_type = get_type(type);
    char *mac = extract_mac(buf);

    wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t *)buf;
    int len = snifferPacket->rx_ctrl.sig_len;

    printf("\n");
    printf("Packet type: %s\n", packet_type);
    printf("Packet Length: %i\n", len);
    printf("Packet Mac Address: %s\n", mac);
    printf("\n");
}

void app_main(void)
{
    // create tasks
    xTaskCreatePinnedToCore(sniffer_init, "Sniffer Task", 4096, NULL, 1, &sniffer_task, 0);
}