# ESP_network_ip_scanner
This tool can be used to scan a local network (LAN) for any live devices (like computers, smartphones, routers, IoT devices and more), in order to get their IP address, MAC address and other information.\
I tested it on Espressif ESP32 but it should also work on other ESP-IDF microchips using the lwIP stack.
In order to use it, clone and set the EXAMPLE_ESP_WIFI_SSID and EXAMPLE_ESP_WIFI_PASS on wifi_connect.c to your WIFI SSID and password.\\
The way it works is by sending ARP requests packets to all of the network possible addresses (currently it assumes the network's subnet mask is 255.255.255.0 as most home netowrk are) and then trying to read from the lwIP ARP table in batches of 10 (this is because the default MAX_SIZE of lwIP ARP table is 10 entries, so in order to not mess around with the default configs I preferred to use this soultion).\
When the scan is finished, all of the found IPs are printed to stdout of the device. The found devices list is stored in a cJSON object which can be sent later to server-side.
