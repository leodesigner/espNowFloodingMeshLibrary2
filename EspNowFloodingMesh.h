#ifndef ESP_NOBRADCAST_H
#define ESP_NOBRADCAST_H

#define DEFAULT_TIMEOUT_MS  3000
#define DEFAULT_TRY_CNT     3
//#define USE_RAW_801_11

#define ENABLE_TELEMETRY
#define TELEMETRY_STATS_SIZE    10

#define LED_BLINK_RX_MODE       1
#define LED_BLINK_TX_MODE       2
#define LED_BLINK_TIMEOUT_MS    40

#ifndef USE_RAW_801_11
  #ifdef ESP32
//  #include <esp_now.h>
  #else
//  #include <espnow.h>
  #endif
#endif

//#define DISABLE_CRYPTING //send messages as plain text
//#define DEBUG_PRINTS

#define MAX_ALLOWED_TIME_DIFFERENCE_IN_MESSAGES 3 //if message time differens more than this from RTC, reject message

    #ifndef USE_RAW_801_11
    void espNowFloodingMesh_begin(int channel, int bsid, bool disconnect_wifi = true);
    #else
    void espNowFloodingMesh_begin(int channel, char bsId[6], bool disconnect_wifi = true);
    #endif

    void espNowFloodingMesh_end();

    void espNowFloodingMesh_enableBlink(int8_t pin, uint8_t mode = 1);

    void espNowFloodingMesh_setChannel(int channel);

    void espNowFloodingMesh_setToMasterRole(bool master=true, unsigned char ttl=0 /*ttl for sync messages*/);
    void espNowFloodingMesh_setToBatteryNode(bool isBatteryNode=true);

    void espNowFloodingMesh_RecvCB(void (*callback)(const uint8_t *, int, uint32_t));
    void espNowFloodingMesh_send(uint8_t* msg, int size, int ttl=0); //Max message length is 236byte
    void espNowFloodingMesh_secredkey(const unsigned char key[16]);
    void espNowFloodingMesh_setAesInitializationVector(const unsigned char iv[16]);

    void espNowFloodingMesh_ErrorDebugCB(void (*callback)(int,const char *));

    void espNowFloodingMesh_disableTimeDifferenceCheck(bool disable=true); //Decreases security, but you can communicate without master and without timesync

    uint32_t espNowFloodingMesh_sendAndHandleReply(uint8_t* msg, int size, int ttl, void (*f)(const uint8_t *, int)); //Max message length is 236byte
    uint32_t espNowFloodingMesh_sendAndHandleReplyUmid(uint8_t* msg, int size, uint32_t umsgid, int ttl, void (*f)(const uint8_t *, int)); //Max message length is 236byte

    // Run this only in Mainloop!!!
    // Max message length is 236byte
    bool espNowFloodingMesh_sendAndWaitReply(uint8_t* msg, int size, int ttl, int tryCount=10, void (*f)(const uint8_t *, int)=NULL, int timeoutMs=DEFAULT_TIMEOUT_MS, int expectedCountOfReplies=1, uint16_t backoffMs=0); 
    bool espNowFloodingMesh_syncTimeAndWait(unsigned long timeoutMs=DEFAULT_TIMEOUT_MS, int tryCount=DEFAULT_TRY_CNT, uint16_t backoffMs=0);
    // the same but with the message annoncement (can be device name, config etc.)
    bool espNowFloodingMesh_syncTimeAnnonceAndWait(uint8_t* msg, int size, unsigned long timeoutMs=DEFAULT_TIMEOUT_MS, int tryCount=DEFAULT_TRY_CNT, uint16_t backoffMs=0);

    void espNowFloodingMesh_sendReply(uint8_t* msg, int size, int ttl, uint32_t replyIdentifier);

    void espNowFloodingMesh_loop();

    void espNowFloodingMesh_delay(unsigned long tm);
    int espNowFloodingMesh_getTTL();

    void espNowFloodingMesh_setRTCTime(time_t time);
    time_t espNowFloodingMesh_getRTCTime();

    #pragma pack(push, 1)
    struct telemetry_stats_st {
      uint32_t received_pkt;
      uint32_t dup_pkt;
      uint32_t sent_pkt;
      uint32_t fwd_pkt;
      // uint32_t ttl0_pkt;
    };
    #pragma pack(pop)

    telemetry_stats_st *espNowFloodingMesh_get_tmt_stats_ptr(void);

    #ifdef ENABLE_TELEMETRY
  
    #pragma pack(push, 1)
    struct telemetry_db_item {
      uint8_t mac_addr[6];
      uint32_t lastseen; // truncated ts from time_t
      uint16_t msg_cnt;
      uint16_t dup_msg_cnt;
    };
    #pragma pack(pop)

    struct telemetry_db_item *espNowFloodingMesh_get_tdb_ptr(void);
    void espNowFloodingMesh_telemetry_reset_tdb(void);
    #endif

#endif
