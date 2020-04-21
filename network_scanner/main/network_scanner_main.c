#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_http_client.h"
#include "esp_tls.h"
#include "cJSON.h"
#include "lwip/opt.h"
#include "lwip/etharp.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "netif/ethernet.h"
#include "lwip/ip4_addr.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "esp_console.h"
#include "ping/ping_sock.h"
#include "tcpip_adapter.h"
#include "esp_netif.h"

#include "wifi_connect.h"


/* Constants that aren't configurable in menuconfig */
static const char *TAG = "Network_Scanner";

//gloabls
cJSON *arp_table_json;;	


void split_ip(char *interface_ip, char *from_ip){
	int string_index = 0;
	char *token = strtok(interface_ip, ".");
	for (int i = 0; i < 3; i++) {
		sprintf(from_ip + string_index, "%s.", token);
		string_index = string_index + strlen(token) + 1; //string index + '.'
		token = strtok(NULL, ".");
	}
}


void print_arp_table(){
    ESP_LOGI(TAG, "Printing ARP table");
    for (char i = 1; i < 255; i++) {
        char entry_name[10];
        itoa(i, entry_name, 10);
        cJSON *entry = cJSON_GetObjectItem(arp_table_json, entry_name);
        if (entry!= NULL){
            printf("\n**********************************************\n");
            printf("IP: %s\n", cJSON_GetObjectItem(entry, "ip")->valuestring);
            printf("MAC address: %s\n", cJSON_GetObjectItem(entry, "mac")->valuestring);
            printf("Vendor: %s\n", cJSON_GetObjectItem(entry, "vendor")->valuestring);
        }
    }
}


void read_arp_table(char * from_ip, int read_from, int read_to){
    ESP_LOGI(TAG, "Reading ARP table from: %d to %d", read_from, read_to);
    for (int i = read_from; i <= read_to; i++) {
		char test[32];
		sprintf(test, "%s%d", from_ip, i);
        const ip_addr_t test_ip;
        ipaddr_aton(test, &test_ip);
        
        ip4_addr_t *ipaddr_ret = NULL;
        struct eth_addr *eth_ret = NULL;
        if(etharp_find_addr(NULL, &test_ip, &eth_ret, &ipaddr_ret) >= 0){
            ESP_LOGI(TAG, "Adding found IP: %s", ipaddr_ntoa(&test_ip));

            cJSON *entry;
            char entry_name[10];
            char mac[20];
            sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",eth_ret->addr[0],eth_ret->addr[1],eth_ret->addr[2],eth_ret->addr[3],eth_ret->addr[4],eth_ret->addr[5]);        

            itoa(i, entry_name, 10);
            cJSON_AddItemToObject(arp_table_json, entry_name, entry=cJSON_CreateObject()); //the key name will be the last ip byte
            cJSON_AddStringToObject(entry, "ip", ipaddr_ntoa(&test_ip));
            cJSON_AddStringToObject(entry, "mac", mac);
            cJSON_AddStringToObject(entry, "vendor", "");
        }
	}
}


void send_arp(char * from_ip){
    ESP_LOGI(TAG, "Sending ARP requests to the whole network");
    const TickType_t xDelay = (500) / portTICK_PERIOD_MS; //set sleep time for 0.5 seconds
    void * netif = NULL;
    tcpip_adapter_get_netif(0, &netif);
    struct netif *netif_interface = (struct netif *)netif;
    int counter = 0;
    int read_entry_from = 1;
    int read_entry_to = 10;
    for (char i = 1; i < 255; i++) {
		if (counter > 9){
            //since the default arp table size in lwip is 10, and after 10 it overrides existing entries,
            //after each 10 arp reqeusts sent, we'll try to read and store from the arp table.
            counter = 0; //zeoring arp table counter back to 0
            read_arp_table(from_ip, read_entry_from, read_entry_to);
            read_entry_from = read_entry_from + 10;
            read_entry_to = read_entry_to + 10;
        }
        char test[32];
		sprintf(test, "%s%d", from_ip, i);
        const ip_addr_t test_ip;
        ipaddr_aton(test, &test_ip);
        
        // do arp request
        int8_t arp_request_ret = etharp_request(netif_interface, &test_ip);
        //ESP_LOGI(TAG, "etharp_request result: %d", arp_request_ret);
        vTaskDelay( xDelay ); //sleep for 0.5 seconds
        counter++;
	}
    //reading last entries
    read_arp_table(from_ip, read_entry_from, 255);
}


static void scanner_task(void *pvParameters){
    tcpip_adapter_ip_info_t netif_network_info;
    tcpip_adapter_get_ip_info(0, &netif_network_info);
    char interface_ip[16]; //used for arp quering
    strcpy(interface_ip, ip4addr_ntoa(&netif_network_info.ip));

    ESP_LOGI(TAG, "Your IP: %s", ip4addr_ntoa(&netif_network_info.ip));
    ESP_LOGI(TAG, "Your netmask: %s", ipaddr_ntoa(&netif_network_info.netmask));
    ESP_LOGI(TAG, "Your Default Gateway: %s", ipaddr_ntoa(&netif_network_info.gw));

    arp_table_json = cJSON_CreateObject(); //init arp_table json
    char from_ip[16];
    split_ip(interface_ip, from_ip);
    
    send_arp(from_ip);
    print_arp_table();
	
    cJSON_Delete(arp_table_json);
    vTaskDelete(NULL);
}


void app_main()
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "starting network scanner");
    wifi_init_sta(); //init for wifi
    xTaskCreate(&scanner_task, "scanner_task", 20000, NULL, 5, NULL);

}
