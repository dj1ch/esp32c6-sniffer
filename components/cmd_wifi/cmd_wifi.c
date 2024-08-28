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
#include <string.h>

//-------------------------------------------------------------------------------------------------------------------------
// esp32 wifi libraries
//-------------------------------------------------------------------------------------------------------------------------
#include "esp_log.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_console.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "cmd_wifi.h"

//-------------------------------------------------------------------------------------------------------------------------
// other CLI related libraries
//-------------------------------------------------------------------------------------------------------------------------
#include "argtable3/argtable3.h"

//-------------------------------------------------------------------------------------------------------------------------
// freeRTOS libraries
//-------------------------------------------------------------------------------------------------------------------------
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

//-------------------------------------------------------------------------------------------------------------------------
// cli libraries
//-------------------------------------------------------------------------------------------------------------------------
#include "cmd_wifi.h"

//-------------------------------------------------------------------------------------------------------------------------
// gpio libraries
//-------------------------------------------------------------------------------------------------------------------------
#include "driver/gpio.h"

//-------------------------------------------------------------------------------------------------------------------------
// ESP32 LED PIN
//-------------------------------------------------------------------------------------------------------------------------
#define LED_PIN 7

//-------------------------------------------------------------------------------------------------------------------------
// this is supported using esp_wifi_remote
//-------------------------------------------------------------------------------------------------------------------------
#if CONFIG_SOC_WIFI_SUPPORTED

//-------------------------------------------------------------------------------------------------------------------------
//
// IEEE 802.11 Wifi Structures from ESP32-Sniffer example
// Source: https://github.com/lpodkalicki/blog/blob/master/esp32/016_wifi_sniffer/main/main.c#L22
// 
// I'm not sure if you would consider this an easter egg but this was also included in the Minigotchi!
// Link: https://github.com/dj1ch/minigotchi/blob/main/minigotchi/structs.h#L141
//
//-------------------------------------------------------------------------------------------------------------------------
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

//-------------------------------------------------------------------------------------------------------------------------
// arguments for start command
//-------------------------------------------------------------------------------------------------------------------------
static struct {
    struct arg_str *mac;
    struct arg_str *type;
    struct arg_end *end;
} start_args;

//-------------------------------------------------------------------------------------------------------------------------
// type for packets
//-------------------------------------------------------------------------------------------------------------------------
typedef enum {
    MANAGEMENT_PACKET,
    DATA_PACKET,
    MISC_PACKET,
    UNKNOWN_PACKET
} sniffer_packet_type_t;

const char *sniffer_packet_type[] = {
    "management",
    "data",
    "misc"
};

//-------------------------------------------------------------------------------------------------------------------------
// arguments for switchchannel command
//-------------------------------------------------------------------------------------------------------------------------
static struct {
    struct arg_int *channel;
    struct arg_end *end;
} switchchannel_args;

static char target_mac[18];
static bool filter;

/**
 * Generates random number
 * @param min Minimum number
 * @param max Maximum number
 * @return The random number
 */
int random_num(int min, int max) { return min + rand() % (max - min + 1); }

/**
 * Starts the sniffer, initializes configuration
 * @param argc Number of arguments
 * @param argv Arguments
 */
int sniffer_init(int argc, char **argv)
{
    //-------------------------------------------------------------------------------------------------------------------------
    // parse command arguments
    //-------------------------------------------------------------------------------------------------------------------------
    if (start_args.mac->count > 0) {
        strncpy(target_mac, start_args.mac->sval[0], sizeof(target_mac) - 1);
        filter = true;
        printf("Target MAC: %s\n", target_mac);
    }

    sniffer_packet_type_t packet_type = UNKNOWN_PACKET;
    if (start_args.type->count >= 1) {
        const char *input_type = start_args.type->sval[0];
        for (int i = 0; i < sizeof(sniffer_packet_type); i++) {
            if (strcmp(input_type, sniffer_packet_type[i]) == 0) {
                packet_type = (sniffer_packet_type_t)i;
                printf("Target Packet Type: %s", sniffer_packet_type[i]);
                break;
            }
        }

        if (packet_type == UNKNOWN_PACKET) {
            printf("Unknown packet type: %s\n", input_type);
            return 1;
        }
    }
    
    printf("Currently on channel %i", current_channel());

    //-------------------------------------------------------------------------------------------------------------------------
    // set cb
    //-------------------------------------------------------------------------------------------------------------------------
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);

    //-------------------------------------------------------------------------------------------------------------------------
    // wait forever
    //-------------------------------------------------------------------------------------------------------------------------
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
 * @param argc Number of arguments
 * @param argv Arguments
 * @return Whether or not the switch was successful
 */
int switch_channel(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&switchchannel_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, switchchannel_args.end, argv[0]);
        return 1;
    }
    
    //-------------------------------------------------------------------------------------------------------------------------
    // access channel number
    //-------------------------------------------------------------------------------------------------------------------------
    int channel = switchchannel_args.channel->ival[0];

    //-------------------------------------------------------------------------------------------------------------------------
    // double check
    //-------------------------------------------------------------------------------------------------------------------------
    if (channel < 1 || channel > 13) {
        printf("Invalid channel. Must be between 1 and 13.\n");
        return 1;
    }

    printf("Switching to channel %d\n", channel);

    //-------------------------------------------------------------------------------------------------------------------------
    // disable promiscuous mode before switching channel
    //-------------------------------------------------------------------------------------------------------------------------
    esp_err_t ret = esp_wifi_set_promiscuous(false);
    if (ret != ESP_OK) {
        printf("Failed to disable promiscuous mode: %d\n", ret);
        return 1;
    }

    //-------------------------------------------------------------------------------------------------------------------------
    // quick delay
    //-------------------------------------------------------------------------------------------------------------------------
    vTaskDelay(pdMS_TO_TICKS(100));

    //-------------------------------------------------------------------------------------------------------------------------
    // set the channel
    //-------------------------------------------------------------------------------------------------------------------------
    ret = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (ret != ESP_OK) {
        printf("Failed to set channel: %d\n", ret);
        return 1;
    }

    printf("\nSwitched to channel %i\n", current_channel());

    //-------------------------------------------------------------------------------------------------------------------------
    // and yet another delay
    //-------------------------------------------------------------------------------------------------------------------------
    vTaskDelay(pdMS_TO_TICKS(100));

    //-------------------------------------------------------------------------------------------------------------------------
    // re-enable promiscuous mode
    //-------------------------------------------------------------------------------------------------------------------------
    ret = esp_wifi_set_promiscuous(true);
    if (ret != ESP_OK) {
        printf("Failed to enable promiscuous mode: %d\n", ret);
        return 1;
    }

    return 0;
}


/**
 * Checks whether or not mac we're filtering for matches the current mac address found in the callback
 * @param mac
 * @param current
 * @return Result of whether or not mac addresses match
 */
bool filter_mac(char *mac, char *current) 
{
    return strcmp(mac, current) == 0;
}


/**
 * Sniffer callback
 * @param buf Packet buffer
 * @param type Type of Packet
 */
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t *)buf;
    int len = snifferPacket->rx_ctrl.sig_len;

    //-------------------------------------------------------------------------------------------------------------------------
    // start with LED off
    //-------------------------------------------------------------------------------------------------------------------------
    esp_rom_gpio_pad_select_gpio(LED_PIN);
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(LED_PIN, 0);

    char *packet_type = get_type(type);
    char *mac = extract_mac(buf);

    if (filter && strcmp(mac, target_mac) != 0) {
        printf("Packet type: %s\n", packet_type);
        printf("Packet Length: %i\n", len);
        printf("Packet Mac Address: %s\n", mac);
        printf("Current Channel: %i\n", current_channel());
        printf("\n");

        return;
    }

    if (filter && strcmp(mac, target_mac) == 0) {
        //-------------------------------------------------------------------------------------------------------------------------
        // turn on led once found
        //-------------------------------------------------------------------------------------------------------------------------
        gpio_set_level(LED_PIN, 1);

        printf("Filtered Mac (%s) found!\n", target_mac);
        printf("Packet type: %s\n", packet_type);
        printf("Packet Length: %i\n", len);
        printf("Packet Mac Address: %s\n", mac);
        printf("Current Channel: %i\n", current_channel());
        printf("\n");

        //-------------------------------------------------------------------------------------------------------------------------
        // stop sniffer
        //-------------------------------------------------------------------------------------------------------------------------
        printf("Stopping sniffer\n");
        stop_sniffer();
        gpio_set_level(LED_PIN, 0);

        return;
    } 
    
    if (!filter) {
        //-------------------------------------------------------------------------------------------------------------------------
        // turn on
        //-------------------------------------------------------------------------------------------------------------------------
        gpio_set_level(LED_PIN, 1);
    
        printf("Packet type: %s\n", packet_type);
        printf("Packet Length: %i\n", len);
        printf("Packet Mac Address: %s\n", mac);
        printf("Current Channel: %i\n", current_channel());
        printf("\n");

        //-------------------------------------------------------------------------------------------------------------------------
        // turn off
        //-------------------------------------------------------------------------------------------------------------------------
        gpio_set_level(LED_PIN, 0);
    }
}

int get_channel() {
    printf("Current channel: %i\n", current_channel());
    return 0;
}

void register_wifi(void)
{
    start_args.mac = arg_str0(NULL, "mac", "<mac_address>", "Start sniffer set to find the specified Mac Address");
    start_args.mac = arg_str0(NULL, "type", "<packet_type>", "Start sniffer set to find the specific Packet Type");
    start_args.end = arg_end(2);

    switchchannel_args.channel = arg_int0(NULL, "channel", "<channel>", "Switches to specified channel");
    switchchannel_args.end = arg_end(2);

    const esp_console_cmd_t start_cmd = {
        .command = "start",
        .help = "Start the Wifi Sniffer",
        .hint = NULL,
        .func = &sniffer_init,
        .argtable = &start_args
    };

    const esp_console_cmd_t switchchannel_cmd = {
        .command = "switchchannel",
        .help = "Switches Wifi channel to given channel",
        .hint = NULL,
        .func = &switch_channel,
        .argtable = &switchchannel_args
    };

    const esp_console_cmd_t currentchannel_cmd = {
        .command = "currentchannel",
        .help = "Returns current WiFi channel as an integer",
        .hint = NULL,
        .func = &get_channel,
        .argtable = NULL
    };

    ESP_ERROR_CHECK(esp_console_cmd_register(&start_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&switchchannel_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&currentchannel_cmd));
}

#endif // CONFIG_SOC_WIFI_SUPPORTED