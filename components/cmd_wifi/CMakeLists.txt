idf_component_register(SRCS "cmd_wifi.c"
                    INCLUDE_DIRS "." REQUIRES console esp_netif esp_event esp_wifi esp_system esp_driver_gpio)
