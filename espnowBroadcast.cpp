//#define DEBUG_PRINTS

#ifdef ESP32
    #include <esp_now.h>
    #include <WiFi.h>
#else
    #include <ESP8266WiFi.h>
    #include <Esp.h>
    #include <espnow.h>
  #define ESP_OK 0
#endif
#include "espnowBroadcast.h"

const unsigned char broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
bool init_done = false;
void(*espnowCB)(const uint8_t *, int, const uint8_t *) = NULL;

#ifdef ESP32
void esp_msg_recv_cb(const uint8_t *mac_addr, const uint8_t *data, int len)
#else
void esp_msg_recv_cb(u8 *mac_addr, u8 *data, u8 len)
#endif
{
  #ifdef DEBUG_PRINTS
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
           mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
  Serial.print("Last Packet Recv from: "); Serial.println(macStr);
  #endif
  //Serial.print(".");
  if ( espnowCB != NULL ) {
    espnowCB(data, len, mac_addr);
  }
}

#ifdef DEBUG_PRINTS
bool sending = false;
long send_ts = 0;
#endif

#ifdef ESP32
static void msg_send_cb(const uint8_t* mac, esp_now_send_status_t sendStatus)
{
  #ifdef DEBUG_PRINTS
  Serial.print("^");
  Serial.println(sendStatus);
  #endif
}
#else
static void msg_send_cb(u8* mac_addr, u8 status)
{
  #ifdef DEBUG_PRINTS
  sending = false;
  Serial.print("^");
  Serial.print(status);
  Serial.print(" > elapsed: ");
  Serial.println(micros() - send_ts);
  #endif
}
#endif

void espnowBroadcast_begin(int channel) {
 
  // takes too much time - now it's external
  //WiFi.mode(WIFI_STA);
  //WiFi.disconnect();

  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }

  // Set up callback
  esp_now_register_recv_cb(esp_msg_recv_cb);
  esp_now_register_send_cb(msg_send_cb);


  #ifdef ESP32
    static esp_now_peer_info_t slave;
    memset(&slave, 0, sizeof(slave));
    for (int ii = 0; ii < 6; ++ii) {
      slave.peer_addr[ii] = (uint8_t)0xff;
    }
    slave.channel = channel; // pick a channel
    slave.encrypt = 0; // no encryption

    const esp_now_peer_info_t *peer = &slave;
    const uint8_t *peer_addr = slave.peer_addr;
    esp_now_add_peer(peer);
  #else
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
    esp_now_add_peer((u8*)broadcast_mac, ESP_NOW_ROLE_SLAVE, channel, NULL, 0);
  #endif
  init_done = true;
 
}

void espnowBroadcast_send(const uint8_t *d, int len){
  if (init_done == false) {
    #ifdef DEBUG_PRINTS
    Serial.println("espnowBroadcast not initialized");
    #endif
    return;
  }
  #ifdef ESP32
    esp_now_send(broadcast_mac, (uint8_t*)(d), len);
  #else
    #ifdef DEBUG_PRINTS
    //Serial.print("*");
    if (sending) { 
      Serial.print("Error - we did't receive sent callback!, last sent was: ");
      Serial.println(micros() - send_ts);
      //delay(3);
    }
    sending = true;
    send_ts = micros();
    #endif
    int result = esp_now_send((u8*)broadcast_mac, (u8*)(d), len);

    if (result != ESP_OK) {
      #ifdef DEBUG_PRINTS
      Serial.print("Error sending the data: ");
      Serial.println(result);
      #endif
    }

  #endif
}

void espnowBroadcast_cb(void(*cb)(const uint8_t *, int, const uint8_t *)) {
  espnowCB = cb;
}
