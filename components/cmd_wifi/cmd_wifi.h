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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// misc
int random_num(int min, int max);

// sniffer related
int sniffer_init(int argc, char **argv);
void sniffer_stop();

// functions relating to sniffer callback
void get_mac(char *addr, const unsigned char *buff, int offset);
char *extract_mac(const unsigned char *buff);
char *get_type(wifi_promiscuous_pkt_type_t type);

// channel stuff
int current_channel();
int switch_channel(int argc, char **argv);
bool filter_mac(char *mac, char *current);

// sniffer callback
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type);

// Register WiFi functions
void register_wifi(void);

#ifdef __cplusplus
}
#endif
