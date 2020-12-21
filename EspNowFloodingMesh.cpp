#ifdef ESP32
  #ifndef USE_RAW_801_11
    #include <esp_now.h>
    #include <WiFi.h>
  #endif
  #include <rom/crc.h>
  #include "mbedtls/aes.h"
#else
#include <ESP8266WiFi.h>
#include "AESLib.h" // From https://github.com/kakopappa/arduino-esp8266-aes-lib
#endif

#ifndef USE_RAW_801_11
    #include "espnowBroadcast.h"
#endif
#include "EspNowFloodingMesh.h"
#include <time.h>

#ifdef USE_RAW_801_11
#include "wifi802_11.h"
#endif

#define AES_BLOCK_SIZE  16
#define DISPOSABLE_KEY_LENGTH AES_BLOCK_SIZE
#define REJECTED_LIST_SIZE 50
#define REQUEST_REPLY_DATA_BASE_SIZE 30

#define ALLOW_TIME_ERROR_IN_SYNC_MESSAGE false //Decrease security. false=Validate sync messages against own RTC time

// 10 - 300 sec
#define RESEND_SYNC_TIME_MS           15000

#define USER_MSG                      1
#define SYNC_TIME_MSG                 2
#define INSTANT_TIME_SYNC_REQ         3
#define USER_REQUIRE_RESPONSE_MSG     4
#define USER_REQUIRE_REPLY_MSG        5
#define INSTANT_TIME_SYNC_REQ_ANNONCE 7


unsigned char ivKey[16] = {0xb2, 0x4b, 0xf2, 0xf7, 0x7a, 0xc5, 0xec, 0x0c, 0x5e, 0x1f, 0x4d, 0xc1, 0xae, 0x46, 0x5e, 0x75};

bool masterFlag = false;
bool syncronized = false;
bool batteryNode = false;
bool timeStampCheckDisabled = false;
uint8_t syncTTL = 0;
bool isespNowFloodingMeshInitialized = false;
int myBsid = 0x112233;

telemetry_stats_st telemetry_stats;

#pragma pack(push,1)
struct header {
  uint8_t msgId;
  uint8_t length;
  uint32_t p1;
  time_t time;
};

struct mesh_secred_part{
  struct header header;
  uint8_t data[240];
};

struct mesh_unencrypted_part {
  unsigned char bsid[3];
  uint8_t ttl;
  uint16_t crc16;
  void setBsid(uint32_t v) {
      bsid[0]=(v>>(16))&0xff;
      bsid[1]=(v>>(8))&0xff;
      bsid[2]=v&0xff;
  }
  void set(const uint8_t *v) {
      memcpy(this,v,sizeof(struct mesh_unencrypted_part));
  }
  uint32_t getBsid(){
      uint32_t ret=0;
      ret|=((uint32_t)bsid[0])<<16;
      ret|=((uint32_t)bsid[1])<<8;
      ret|=((uint32_t)bsid[2]);
      return ret;
  }
};

typedef struct mesh_unencrypted_part unencrypted_t;
#define SECRED_PART_OFFSET sizeof(unencrypted_t)


struct meshFrame{
  unencrypted_t unencrypted;
  struct mesh_secred_part encrypted;
};
#pragma pack(pop)

int espNowFloodingMesh_getTTL() {
    return syncTTL;
}

const unsigned char broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t aes_secredKey[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE, 0xFF};

bool forwardMsg(const uint8_t *data, int len);
uint32_t sendMsg(uint8_t* msg, int size, int ttl, int msgId, void *ptr=NULL);
void hexDump(const uint8_t*b,int len);
static void (*espNowFloodingMesh_receive_cb)(const uint8_t *, int, uint32_t) = NULL;

uint16_t calculateCRC(int c, const unsigned char*b, int len);
uint16_t calculateCRC(struct meshFrame *m);
int decrypt(const uint8_t *_from, struct meshFrame *m, int size);
bool compareTime(time_t current, time_t received, time_t maxDifference);



void (*errorPrintCB)(int,const char *) = NULL;

void espNowFloodingMesh_ErrorDebugCB(void (*callback)(int, const char *)) {
    errorPrintCB = callback;
}

void espNowFloodingMesh_disableTimeDifferenceCheck(bool disable) {
    timeStampCheckDisabled = disable;
    if (disable) {
        syncronized = true;
    }
}

int8_t led_pin = -1;
bool led_is_on = false;
uint8_t led_blink_mode = 0;
uint32_t recv_packet_ts = 0;
uint32_t tx_packet_ts = 0;

void espNowFloodingMesh_enableBlink(int8_t pin, uint8_t mode) {
    led_pin = pin;
    led_blink_mode = mode;
    pinMode(led_pin, OUTPUT);
    digitalWrite(led_pin, HIGH); // turn off
}

void print(int level, const char * format, ... ) {
  if (errorPrintCB) {
      static char buffer[256];
      va_list args;
      va_start (args, format);
      vsprintf (buffer,format, args);

      errorPrintCB(level, buffer);

      va_end (args);
  }
}


void espNowFloodingMesh_setAesInitializationVector(const unsigned char iv[16]) {
  memcpy(ivKey, iv, sizeof(ivKey));
}

void espNowFloodingMesh_setToBatteryNode(bool isBatteryNode) {
  batteryNode = isBatteryNode;
}

telemetry_stats_st *espNowFloodingMesh_get_tmt_stats_ptr(void) {
  return &telemetry_stats;
}


// Telemetry related processing

#ifdef ENABLE_TELEMETRY

struct telemetry_db_item tdb[TELEMETRY_STATS_SIZE];

struct telemetry_db_item *espNowFloodingMesh_get_tdb_ptr(void) {
  return tdb;
}

void espNowFloodingMesh_telemetry_reset_tdb(void) {
  memset(tdb, 0, sizeof(tdb));
}

// search for mac address in telemetry, return -1 if not found
// index returned if found
int16_t telemetry_get_tdb_idx_by_mac(const uint8_t *mac_addr) {
  int16_t idx = 0;
  bool found = false;
  while ( idx < TELEMETRY_STATS_SIZE && !found ) {
    if ( tdb[idx].mac_addr[0] == mac_addr[0] 
         && tdb[idx].mac_addr[1] == mac_addr[1]
         && tdb[idx].mac_addr[2] == mac_addr[2]
         && tdb[idx].mac_addr[3] == mac_addr[3] 
         && tdb[idx].mac_addr[4] == mac_addr[4] 
         && tdb[idx].mac_addr[5] == mac_addr[5] ) {
      return idx;
    }
    idx++;
  }
  // not found
  return -1;
}

int16_t telemetry_get_tdb_slot(const uint8_t *mac_addr) {
  int16_t idx = telemetry_get_tdb_idx_by_mac(mac_addr);
  int16_t lidx = 0; // oldest lastseen index
  if (idx == -1) {
    // not found, let's find free spot or the oldest one
    bool found = false; 
    uint32_t ts = 0;
    idx = 0;
    while ( idx < TELEMETRY_STATS_SIZE && !found ) {
      if ( tdb[idx].mac_addr[0] == 0 
            && tdb[idx].mac_addr[1] == 0
            && tdb[idx].mac_addr[2] == 0
            && tdb[idx].mac_addr[3] == 0 
            && tdb[idx].mac_addr[4] == 0 
            && tdb[idx].mac_addr[5] == 0 ) {
        // found empty spot
        found = true;
        break;
      }
      if (ts == 0 || tdb[idx].lastseen < ts) { ts = tdb[idx].lastseen; lidx = idx; }
      idx++;
    }
    if (!found) { idx = lidx; } // replace the oldest one
    // copy mac addr
    for (int i=0; i<6; i++) {
      tdb[idx].mac_addr[i] = mac_addr[i];
    }
  }
  return idx;
}

#endif


struct requestReplyDbItem {
    void (*cb)(const uint8_t *, int);
    uint32_t messageIdentifierCode;
    time_t time;
    uint8_t ttl;
};

class RequestReplyDataBase {
 public:
  RequestReplyDataBase() {
    index = 0;
    memset(db, 0, sizeof(db));
    c = 1;
    mac = WiFi.macAddress();
    muuid_base = calculateCRC(0, (const uint8_t*)mac.c_str(), 6);
  }
  ~RequestReplyDataBase(){}
  void add(uint32_t messageIdentifierCode, void (*f)(const uint8_t *, int)) {
    db[index].cb = f;
    db[index].messageIdentifierCode = messageIdentifierCode;
    db[index].time = espNowFloodingMesh_getRTCTime();
    index++;
    if (index >= REQUEST_REPLY_DATA_BASE_SIZE) {
      index = 0;
    }
  }
  uint32_t calculateMessageIdentifier() {
    uint32_t ret = muuid_base;
    #ifdef ESP32
      ret = ret<<8 | (esp_random()&0xff);
    #else
      // ret = ret<<8 | (random(0, 0xff)&0xff);
      ret = ret<<8 | (secureRandom(0, 0xff) & 0xff);
    #endif
    ret = ret<<8 | c;
    c++;
    if (ret == 0) { ret = 1; } //messageIdentifier is never zero
    return ret;
  }

  const struct requestReplyDbItem* getCallback(uint32_t messageIdentifierCode) {
    time_t currentTime = espNowFloodingMesh_getRTCTime();
    for (int i = 0; i < REQUEST_REPLY_DATA_BASE_SIZE; i++) {
      if (db[i].messageIdentifierCode == messageIdentifierCode) {
        if (compareTime(currentTime, db[i].time, MAX_ALLOWED_TIME_DIFFERENCE_IN_MESSAGES)) {
            if ( db[i].cb != NULL) {
              return &db[i];
            }
        }
      }
    }
    return NULL;
  }

  void removeItem() { //Cleaning db  --> Remove the oldest item
    memset(&db[index], 0, sizeof(struct requestReplyDbItem));
    index++;
    if (index >= REQUEST_REPLY_DATA_BASE_SIZE) {
      index = 0;
    }
  }
 private:
    struct requestReplyDbItem db[REQUEST_REPLY_DATA_BASE_SIZE];
    int index;
    uint8_t c;
    String mac;
    uint32_t muuid_base;
};

RequestReplyDataBase requestReplyDB;

class RejectedMessageDB {
public:
  ~RejectedMessageDB() {}
  RejectedMessageDB() {
    memset(rejectedMsgList, 0, sizeof(rejectedMsgList));
    memset(ttlList, 0, sizeof(ttlList));
    index = 0;
  }

  void removeItem() { //Cleaning db  --> Remove the oldest item
    rejectedMsgList[index] = 0;
    ttlList[index] = 0;
    index++;
    if (index >= REJECTED_LIST_SIZE) {
      index = 0;
    }
  }

  void addMessageToHandledList(struct meshFrame *m) {
    uint16_t crc = m->unencrypted.crc16;
    for (int i=0; i<REJECTED_LIST_SIZE; i++){
      if (rejectedMsgList[i] == crc) {
        if (ttlList[i] < m->unencrypted.ttl) {
          ttlList[i] = m->unencrypted.ttl;
        }
        return;
      }
    }
    rejectedMsgList[index] = crc;
    ttlList[index] = m->unencrypted.ttl;

    index++;
    if (index >= REJECTED_LIST_SIZE) {
      index = 0;
    }
  }

  int isMessageInHandledList(struct meshFrame *m) {
    bool forwardNeeded = false;
    bool handled = false;
    uint16_t crc = m->unencrypted.crc16;
    for (int i=0; i<REJECTED_LIST_SIZE; i++) {
      if (rejectedMsgList[i] == crc) {
        handled = true;
        if (ttlList[i] < m->unencrypted.ttl) {
          forwardNeeded = true;
        }
        break;
      }
    }
    if (forwardNeeded) return 2;
    if (handled) return 1;
    return 0;
  }
private:
    uint16_t rejectedMsgList[REJECTED_LIST_SIZE];
    uint8_t ttlList[REJECTED_LIST_SIZE];
    int index;
};
RejectedMessageDB rejectedMessageDB;


void espNowFloodingMesh_RecvCB(void (*callback)(const uint8_t *, int, uint32_t)) {
  espNowFloodingMesh_receive_cb = callback;
}

void espNowFloodingMesh_delay(unsigned long tm) {
  // should be avoided or rewritten
  for (unsigned int i=0; i<(tm/10); i++) {
    espNowFloodingMesh_loop();
    delay(10);
  }
}

void espNowFloodingMesh_loop() {

  if (isespNowFloodingMeshInitialized == false) { 
    yield();
    return;
  }

  uint32_t now = millis();

  if (masterFlag) {
      static unsigned long start = 0;
      unsigned long elapsed = now - start;
      if ( elapsed >= RESEND_SYNC_TIME_MS ) { // 10s
        start = now;
        #ifdef DEBUG_PRINTS
        Serial.println("Send time sync message!!");
        #endif
        print(3,"Send time sync message.");
        sendMsg(NULL, 0, syncTTL, SYNC_TIME_MSG);
      }
  }
  // Clean database
  static unsigned long dbtm = millis();
  unsigned long elapsed = now - dbtm;
  if ( elapsed >= 500 ) {
    dbtm = now;
    requestReplyDB.removeItem();
    rejectedMessageDB.removeItem();
  }
  
  if (led_blink_mode == LED_BLINK_RX_MODE && led_is_on == true && recv_packet_ts < now - LED_BLINK_TIMEOUT_MS) {
    led_is_on = false;
    digitalWrite(led_pin, HIGH); // off
  }
  if (led_blink_mode == LED_BLINK_TX_MODE && led_is_on == true && tx_packet_ts < now - LED_BLINK_TIMEOUT_MS) {
    led_is_on = false;
    digitalWrite(led_pin, HIGH); // off
  }

  yield();
}

void espNowFloodingMesh_setToMasterRole(bool master, unsigned char ttl) {
  masterFlag = master;
  syncTTL = ttl;
}

uint16_t calculateCRC(int c, const unsigned char*b,int len) {
  #ifdef ESP32JJJ
    return crc16_le(0, b, len);
  #else
    // Copied from https://www.lammertbies.nl/forum/viewtopic.php?t=1528
    uint16_t crc = 0xFFFF;
    uint8_t i;
    if (len) do {
      crc ^= *b++;
      for (i=0; i<8; i++) {
        if (crc & 1) crc = (crc >> 1) ^ 0x8408;
        else crc >>= 1;
      }
    } while (--len);
    return(~crc);
  #endif
}

uint16_t calculateCRC(struct meshFrame *m){
  //uint16_t crc = m->encrypted.header.crc16;
  //m->encrypted.header.crc16 = 0;
  int size = m->encrypted.header.length + sizeof(m->encrypted.header);
  uint16_t ret = calculateCRC(0, (const unsigned char*)m + SECRED_PART_OFFSET, size);
  //m->encrypted.header.crc16 = crc;
  return ret;
}

void hexDump(const uint8_t*b, int len){
  //#ifdef DEBUG_PRINTS
  Serial.println();
  for (int i=0; i < len; i = i + 16) {
    Serial.print("           ");
    for(int x=0; x<16 && (x+i) < len; x++) {
      if(b[i+x]<=0xf) Serial.print("0");
      Serial.print(b[i+x],HEX);
      Serial.print(" ");
    }
    Serial.print(" ");
    for(int x=0; x<16 && (x+i) < len; x++) {
      if (b[i+x]<=32||b[i+x] >= 126) {
          Serial.print(".");
      } else Serial.print((char)b[i+x]);
    }
    Serial.print("\n");
  }
  Serial.print("                   Length: ");
  Serial.println(len);
//  #endif
}

#ifdef ESP32
void espNowFloodingMesh_setRTCTime(time_t time) {
  struct timeval now = { .tv_sec = time };
  settimeofday(&now, NULL);
    if(masterFlag){
        print(3, "Send time sync");
        sendMsg(NULL, 0, syncTTL, SYNC_TIME_MSG);
    }
}
time_t espNowFloodingMesh_getRTCTime() {
  return time(NULL);
}
#else
long long rtcFixValue = 0;
void espNowFloodingMesh_setRTCTime(time_t t) {
  long long newTime = t;
  long long currentTime = time(NULL);
  rtcFixValue = newTime - currentTime;

    if (masterFlag) {
        print(3, "Send time sync");
        sendMsg(NULL, 0, syncTTL, SYNC_TIME_MSG);
    }
}
time_t espNowFloodingMesh_getRTCTime() {
  long long currentTime = time(NULL);
  long long fixedTime = currentTime + rtcFixValue;
  return fixedTime;
}
#endif

bool compareTime(time_t current, time_t received, time_t maxDifference) {
  if (timeStampCheckDisabled) {
    return true;
  }

  if (current == received) return true;
  if (current < received) {
    return ((received-current) <= maxDifference);
  } else {
    return ((current-received) <= maxDifference);
  }
  return false;
}

#ifdef USE_RAW_801_11
void msg_recv_cb(const uint8_t *data, int len, uint8_t rssi)
#else
void msg_recv_cb(const uint8_t *data, int len, const uint8_t *mac_addr)
#endif
{
  // Serial.println("."); // RECEIVE PACKET
  #ifdef DEBUG_PRINTS
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
           mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
  Serial.print("Recv from: "); Serial.println(macStr);
  Serial.print("REC[RAW]:");
  hexDump((uint8_t*)data, len);
  #endif

  recv_packet_ts = millis();

  if (led_blink_mode == LED_BLINK_RX_MODE) {
    digitalWrite(led_pin, LOW); // turn on
    led_is_on = true;
  }

  time_t currentTime = espNowFloodingMesh_getRTCTime();

  #ifdef ENABLE_TELEMETRY
  int16_t tdb_idx = telemetry_get_tdb_slot(mac_addr);
  tdb[tdb_idx].msg_cnt++;
  tdb[tdb_idx].lastseen = currentTime & 0xFFFFFFFF; // truncated real timestamp
  telemetry_stats.received_pkt++;
  #endif

  struct meshFrame m;
  m.unencrypted.set(data);

    if ( (unsigned int) myBsid != m.unencrypted.getBsid() ) {
      // Serial.println(myBsid, HEX);
      // Serial.println(m.unencrypted.getBsid(), HEX);
      return;
    }
    if ( (unsigned int) len >= sizeof(struct meshFrame) ) return;

    int messageStatus = rejectedMessageDB.isMessageInHandledList(&m);
    if ( messageStatus != 0 ) {
      // Message is already handled... No need to forward
      #ifdef ENABLE_TELEMETRY
      tdb[tdb_idx].dup_msg_cnt++;
      //Serial.println("D");
      #endif
      telemetry_stats.dup_pkt++;
      return;
    }
    rejectedMessageDB.addMessageToHandledList(&m);

    //memset(&m,0,sizeof(m));
    decrypt((const uint8_t*)data, &m, len);
    #ifdef DEBUG_PRINTS
    Serial.print("REC:");
    hexDump((uint8_t*)&m, m.encrypted.header.length + sizeof(m.encrypted.header) + 5 );
    #endif

    if (!(m.encrypted.header.msgId == USER_MSG 
        || m.encrypted.header.msgId == SYNC_TIME_MSG 
        || m.encrypted.header.msgId == INSTANT_TIME_SYNC_REQ
        || m.encrypted.header.msgId == INSTANT_TIME_SYNC_REQ_ANNONCE
        || m.encrypted.header.msgId == USER_REQUIRE_RESPONSE_MSG 
        || m.encrypted.header.msgId == USER_REQUIRE_REPLY_MSG)) {
        //Quick wilter;
        return;
    }

    if (m.encrypted.header.length >= 0 && m.encrypted.header.length < (sizeof(m.encrypted.data) ) ) {
      uint16_t crc = m.unencrypted.crc16;
      uint16_t crc16 = calculateCRC(&m);

        #ifdef DEBUG_PRINTS
        int messageLengtWithHeader = m.encrypted.header.length + sizeof(struct header);
        Serial.print("REC HEADER:");
        hexDump((uint8_t*)&m, messageLengtWithHeader);
        #endif

        bool messageTimeOk = true;

        if (crc16 == crc) {

          if (!compareTime(currentTime, m.encrypted.header.time, MAX_ALLOWED_TIME_DIFFERENCE_IN_MESSAGES)) {
              messageTimeOk = false;
              print(1,"Received message with invalid time stamp.");
              //  Serial.print("CurrentTime:");Serial.println(currentTime);
              //  Serial.print("ReceivedTime:");Serial.println(m.encrypted.header.time);
              // shell we syncronize to it ? what about replay attack ?
          }

          bool ok = false;
          if (messageStatus == 0) { //if messageStatus==0 --> message is not handled yet.
            if (espNowFloodingMesh_receive_cb) {
              if ( m.encrypted.header.msgId == USER_MSG) {
                if (messageTimeOk) {
                  // shell we rebroadcast message first ? (to reduce latency?) 
                  espNowFloodingMesh_receive_cb(m.encrypted.data, m.encrypted.header.length, m.encrypted.header.p1);
                  ok = true;
                } else {
                  #ifdef DEBUG_PRINTS
                  Serial.print("Reject message because of time difference:"); 
                  Serial.print(currentTime);
                  Serial.print(" ");
                  Serial.println(m.encrypted.header.time);
                  hexDump((uint8_t*)&m,  messageLengtWithHeader);
                  #endif
                }
              }

              if (m.encrypted.header.msgId == USER_REQUIRE_REPLY_MSG) { // ACK received
                if (messageTimeOk) {
                  const struct requestReplyDbItem* d = requestReplyDB.getCallback(m.encrypted.header.p1);
                  if (d != NULL) {
                    d->cb(m.encrypted.data, m.encrypted.header.length);
                  } else {
                    espNowFloodingMesh_receive_cb(m.encrypted.data, m.encrypted.header.length, m.encrypted.header.p1);
                  }
                  ok = true;
                } else {
                  #ifdef DEBUG_PRINTS
                  Serial.print("Reject message because of time difference:");Serial.print(currentTime);Serial.print(" ");Serial.println(m.encrypted.header.time);
                  hexDump((uint8_t*)&m,  messageLengtWithHeader);
                  #endif
                  print(1,"ACK - Message rejected because of time difference.");
                }
              }

              if (m.encrypted.header.msgId == USER_REQUIRE_RESPONSE_MSG) {
                if (messageTimeOk) {
                  espNowFloodingMesh_receive_cb(m.encrypted.data, m.encrypted.header.length, m.encrypted.header.p1);
                  ok = true;
                } else {
                  #ifdef DEBUG_PRINTS
                  Serial.print("Reject message because of time difference:");Serial.print(currentTime);Serial.print(" ");Serial.println(m.encrypted.header.time);
                  hexDump((uint8_t*)&m,  messageLengtWithHeader);
                  #endif
                  print(1,"MSG REQUIRE RESPONSE - Message rejected because of time difference.");
                }
              }
            }

            if ( m.encrypted.header.msgId == INSTANT_TIME_SYNC_REQ ) {
              // ok = true;   // we do not forward time sync messages -- only direct nodes can send time sync response
              if (masterFlag) {
                #ifdef DEBUG_PRINTS
                Serial.println("Send time sync message!! (Requested)");
                #endif
                sendMsg(NULL, 0, 0, SYNC_TIME_MSG); // only for the direct nodes
                print(3,"Master - send time sync message (Requested)");
              } else {
                if (syncronized) {
                  sendMsg(NULL, 0, 0, SYNC_TIME_MSG); // only for the direct nodes
                  print(3,"Send time sync message by node directly (Requested)");
                } else {
                  ok = true; // let's forward sync time request if we are not in sync
                }
              }
            }
            // timesync request with annoncement
            if ( m.encrypted.header.msgId == INSTANT_TIME_SYNC_REQ_ANNONCE ) {
              ok = true; // should be forwarded
              if (masterFlag) {
                #ifdef DEBUG_PRINTS
                Serial.println("Annonce - Send time sync message!! (Requested)");
                #endif
                sendMsg(NULL, 0, 0, SYNC_TIME_MSG); // only for the direct nodes
                print(3,"Annonce + Master - send time sync message (Requested)");
              } else {
                if (syncronized) {
                  sendMsg(NULL, 0, 0, SYNC_TIME_MSG); // only for the direct nodes
                  print(3,"Annonce + Send time sync message by node directly (Requested)");
                }
              }
              if (espNowFloodingMesh_receive_cb) {
                espNowFloodingMesh_receive_cb(m.encrypted.data, m.encrypted.header.length, 0);
              }
            }

            if ( m.encrypted.header.msgId == SYNC_TIME_MSG ) {
              if (masterFlag) {
                //only slaves can be syncronized
                return;
              }
              static time_t last_time_sync = 0;
              #ifdef DEBUG_PRINTS
                Serial.print("Last sync time:"); Serial.println(last_time_sync);
                Serial.print("Sync time in message:"); Serial.println(m.encrypted.header.time);
              #endif

              if (last_time_sync<m.encrypted.header.time || ALLOW_TIME_ERROR_IN_SYNC_MESSAGE) {
                ok = true;
                last_time_sync = m.encrypted.header.time;
                #ifdef DEBUG_PRINTS
                Serial.println("TIME SYNC MSG");
                  currentTime = espNowFloodingMesh_getRTCTime();
                  Serial.print("Current time: "); Serial.print(asctime(localtime(&currentTime)));
                #endif
                espNowFloodingMesh_setRTCTime(m.encrypted.header.time);
                #ifdef DEBUG_PRINTS
                  currentTime = espNowFloodingMesh_getRTCTime();
                  Serial.print("    New time: "); Serial.print(asctime(localtime(&currentTime)));
                #endif
                syncronized = true;
                print(3,"Time syncronised with mesh");
              }
            }
        }
        //if (ok) {
        //  Serial.print("* TTL: ");
        //  Serial.println(m.unencrypted.ttl);
        //}
        if (ok && m.unencrypted.ttl > 0 && batteryNode == false) {
          forwardMsg(data, len);
        }
      } else {
      #ifdef DEBUG_PRINTS
        Serial.print("#CRC: ");Serial.print(crc16);Serial.print(" "),Serial.println(crc);
        for (int i=0;i<m.encrypted.header.length;i++){
          Serial.print("0x");Serial.print(data[i],HEX);Serial.print(",");
        }
        Serial.println();
        hexDump((uint8_t*)&m,200);
        Serial.println();
        hexDump((uint8_t*)data,200);
       #endif
      }
    } else {
      #ifdef DEBUG_PRINTS
      Serial.print("Invalid message received:"); Serial.println(0,HEX);
      hexDump(data,len);
      #endif
    }
}

void espNowFloodingMesh_requestInstantTimeSync() {
  if (masterFlag) return;
  #ifdef DEBUG_PRINTS
  Serial.println("Request instant time sync from mesh.");
  #endif
  sendMsg(NULL, 0, syncTTL, INSTANT_TIME_SYNC_REQ);
}

// with node name annocement
void espNowFloodingMesh_requestInstantTimeSyncAnnonce(uint8_t* msg, int size) {
  if (masterFlag) return;
  #ifdef DEBUG_PRINTS
  Serial.println("Annonce + Request instant time sync from mesh.");
  #endif
  sendMsg(msg, size, syncTTL, INSTANT_TIME_SYNC_REQ_ANNONCE);
}

void espNowFloodingMesh_end() {
}


#ifndef USE_RAW_801_11
void espNowFloodingMesh_begin(int channel, int bsid, bool disconnect_wifi ) {
#else
void espNowFloodingMesh_begin(int channel, char bsId[6], bool disconnect_wifi) {
#endif

  if (disconnect_wifi) 
  { // takes significant amount of time, now disconnect is optional
    // Serial.println("Disconnecting WIFI for espnow");
    WiFi.disconnect();
    WiFi.mode(WIFI_OFF);
    WiFi.mode(WIFI_STA);
  }

  #ifndef ESP32
    randomSeed(analogRead(0));
  #endif

  #ifndef USE_RAW_801_11
      espnowBroadcast_cb(msg_recv_cb);
      espnowBroadcast_begin(channel);
  #else
        wifi_802_11_begin(bsId, channel);
        wifi_802_receive_cb(msg_recv_cb);
  #endif
  isespNowFloodingMeshInitialized = true;

  myBsid = bsid;
  #ifdef ENABLE_TELEMETRY
  espNowFloodingMesh_telemetry_reset_tdb();
  #endif
  memset(&telemetry_stats, 0, sizeof(telemetry_stats) );
}

void espNowFloodingMesh_secredkey(const unsigned char key[16]) {
  memcpy(aes_secredKey, key, sizeof(aes_secredKey));
}

int decrypt(const uint8_t *_from, struct meshFrame *m, int size) {
  unsigned char iv[16];
  memcpy(iv,ivKey,sizeof(iv));

  uint8_t to[2*16];
  for (int i=0; i<size; i=i+16) {
      const uint8_t *from = _from + i + SECRED_PART_OFFSET;
      uint8_t *key = aes_secredKey;

      #ifdef DISABLE_CRYPTING
        memcpy(to,from,16);
      #else
        #ifdef ESP32

          esp_aes_context ctx;
          esp_aes_init( &ctx );
          esp_aes_setkey( &ctx, key, 128 );
          esp_aes_acquire_hardware ();
          esp_aes_crypt_cbc(&ctx, ESP_AES_DECRYPT, 16, iv, from, to);
          esp_aes_release_hardware ();
          esp_aes_free(&ctx);

        #else
          AES aesLib;
          aesLib.set_key( (byte *)key , sizeof(key));
          aesLib.do_aes_decrypt((byte *)from,16 , to, key, 128, iv);
        #endif
      #endif

      if ((i+SECRED_PART_OFFSET+16) <= sizeof(m->encrypted)) {
        memcpy((uint8_t*)m+i+SECRED_PART_OFFSET, to, 16);
      }
  }
  return 0;
}

int encrypt(struct meshFrame *m) {
  int size = ((m->encrypted.header.length + sizeof(m->encrypted.header))/16)*16+16;

  unsigned char iv[16];
  memcpy(iv,ivKey,sizeof(iv));
  uint8_t to[2*16];

  for(int i=0;i<size;i=i+16) {
      uint8_t *from = (uint8_t *)m+i+SECRED_PART_OFFSET;
      uint8_t *key = aes_secredKey;
     #ifdef DISABLE_CRYPTING
       memcpy((void*)to,(void*)from,16);
     #else
        #ifdef ESP32
         esp_aes_context ctx;
         esp_aes_init( &ctx );
         esp_aes_setkey( &ctx, key, 128 );
         esp_aes_acquire_hardware();
         esp_aes_crypt_cbc(&ctx, ESP_AES_ENCRYPT, 16, iv, from, to);
         esp_aes_release_hardware();
         esp_aes_free(&ctx);
        #else
          AES aesLib;
          aesLib.set_key( (byte *)key , sizeof(key));
          aesLib.do_aes_encrypt((byte *)from, size , (uint8_t *)&m->encrypted, key, 128, iv);
          break;
        #endif
      #endif
      memcpy((uint8_t*)m+i+SECRED_PART_OFFSET, to, 16);
  }
/*
  for(int i=m->encrypted.header.length + sizeof(m->encrypted.header)+1;i<size;i++) {
    #ifdef ESP32
    ((unsigned char*)&m->encrypted.header)[i]=esp_random();
    #else
    ((unsigned char*)&m->encrypted.header)[i]=random(0, 255);
    #endif
  }*/

  return size + SECRED_PART_OFFSET;
}

bool forwardMsg(const uint8_t *data, int len) {
  struct meshFrame m;
  memcpy(&m, data,len);

  if (m.unencrypted.ttl == 0) {
    #ifdef DEBUG_PRINTS
    Serial.print("FORWARD: TTL=0\n");
    #endif
    // telemetry_stats.ttl0_pkt++;
    return false; 
  }

  m.unencrypted.ttl = m.unencrypted.ttl-1;

  #ifdef DEBUG_PRINTS
  Serial.print("FORWARD:");
  hexDump((const uint8_t*)data, len);
  #endif

  #ifdef USE_RAW_801_11
      wifi_802_11_send((uint8_t*)(&m), len);
  #else
      espnowBroadcast_send((uint8_t*)(&m), len);
  #endif
  telemetry_stats.fwd_pkt++;
  return true;
}

uint32_t sendMsgId(uint8_t* msg, int size, uint32_t umsgid, int ttl, int msgId, void *ptr) {
  uint32_t ret = 0;
  if ( (unsigned int) size >= sizeof(struct mesh_secred_part) ) {
    #ifdef DEBUG_PRINTS
    Serial.println("espNowFloodingMesh_send: Invalid size");
    #endif
    return false;
  }

  static struct meshFrame m;
  memset(&m, 0x00, sizeof(struct meshFrame));
  m.encrypted.header.length = size;
  m.unencrypted.crc16 = 0;
  m.encrypted.header.msgId = msgId; // message type
  m.unencrypted.ttl= ttl;
  m.unencrypted.setBsid(myBsid);
  m.encrypted.header.p1 = umsgid;
  m.encrypted.header.time = espNowFloodingMesh_getRTCTime();

  if ( msg != NULL ) {
    memcpy(m.encrypted.data, msg, size);
  }

  if ( msgId == USER_REQUIRE_RESPONSE_MSG ) {

    ret = m.encrypted.header.p1;
    requestReplyDB.add(m.encrypted.header.p1, (void (*)(const uint8_t*, int))ptr);
    //Serial.print("Send request with "); Serial.println(m.encrypted.header.p1);
  } if ( msgId == USER_REQUIRE_REPLY_MSG && ptr != NULL ) {
    m.encrypted.header.p1 = *((uint32_t*)ptr);
  }

  m.unencrypted.crc16 = calculateCRC(&m);
  #ifdef DEBUG_PRINTS
   Serial.print("Send0:");
   hexDump((const uint8_t*)&m, size+20);
  #endif
  rejectedMessageDB.addMessageToHandledList(&m);

  int sendSize = encrypt(&m);

/*
struct meshFrame mm;
Serial.print("--->:");
decrypt((const uint8_t*)&m, &mm, sendSize);
Serial.print("--->:");
hexDump((const uint8_t*)&mm, size+20);
Serial.print("--->:");
*/

  #ifdef DEBUG_PRINTS
    Serial.print("Send[RAW]:");
    hexDump((const uint8_t*)&m, sendSize);
  #endif
  // Serial.println("#"); // SEND PACKET

  #ifdef USE_RAW_801_11
      wifi_802_11_send((uint8_t*)&m, sendSize);
  #else
      espnowBroadcast_send((uint8_t*)&m, sendSize);
  #endif
  telemetry_stats.sent_pkt++;

  if (led_blink_mode == LED_BLINK_TX_MODE) {
    digitalWrite(led_pin, LOW); // turn on
    led_is_on = true;
  }

  tx_packet_ts = millis();

  return ret;
}

uint32_t sendMsg(uint8_t* msg, int size, int ttl, int msgId, void *ptr) {
  uint32_t umgsid = requestReplyDB.calculateMessageIdentifier();
  return sendMsgId(msg, size, umgsid, ttl, msgId, ptr);
}

void espNowFloodingMesh_send(uint8_t* msg, int size, int ttl)  {
   sendMsg(msg, size, ttl, USER_MSG);
}

void espNowFloodingMesh_sendReply(uint8_t* msg, int size, int ttl, uint32_t replyIdentifier)  {
   sendMsg(msg, size, ttl, USER_REQUIRE_REPLY_MSG, (void*)&replyIdentifier);
}

uint32_t espNowFloodingMesh_sendAndHandleReply(uint8_t* msg, int size, int ttl, void (*f)(const uint8_t *, int)) {
  return sendMsg(msg, size, ttl, USER_REQUIRE_RESPONSE_MSG, (void*)f);
}

uint32_t espNowFloodingMesh_sendAndHandleReplyUmid(uint8_t* msg, int size, uint32_t umsgid, int ttl, void (*f)(const uint8_t *, int)) {
  return sendMsgId(msg, size, umsgid, ttl, USER_REQUIRE_RESPONSE_MSG, (void*)f);
}

bool espNowFloodingMesh_sendAndWaitReply(uint8_t* msg, int size, int ttl, int tryCount, void (*f)(const uint8_t *, int), int timeoutMs, int expectedCountOfReplies, uint16_t backoffMs){
  static uint16_t replyCnt = 0;
  replyCnt = 0;
  static void (*callback)(const uint8_t *, int);
  callback = f;

  for (int i=0; i<tryCount; i++) {
    espNowFloodingMesh_sendAndHandleReply(msg, size, ttl, [](const uint8_t *data, int len){
      if (callback != NULL) {
        callback(data,len);
      }
      replyCnt++;
    });

    unsigned long dbtm = millis();

    while(1) {
      espNowFloodingMesh_loop();
      if ( expectedCountOfReplies <= replyCnt ) {
        return true; //OK all received;
      }
      unsigned long elapsed = millis() - dbtm;
      if ( elapsed > (unsigned int) timeoutMs ) {
        //timeout
        if (i < 10) { timeoutMs += backoffMs; }
        print(0, "Timeout: waiting replies");
        break;
      }
    }
  }
  return false;
}

bool espNowFloodingMesh_syncTimeAndWait(unsigned long timeoutMs, int tryCount, uint16_t backoffMs) {
  if (masterFlag || timeStampCheckDisabled) return true;
  syncronized = false;
  for (int i=0; i<tryCount; i++) {
      unsigned long dbtm = millis();
      espNowFloodingMesh_requestInstantTimeSync();

      while(1) {
        espNowFloodingMesh_loop();
        if (syncronized) {
          return true; // OK all received;
        }
        unsigned long elapsed = millis() - dbtm;
        if (elapsed > timeoutMs) {
          if (i < 10) { timeoutMs += backoffMs; }
          break;
        }
      }
  }
  return false;
}

bool espNowFloodingMesh_syncTimeAnnonceAndWait(uint8_t* msg, int size, unsigned long timeoutMs, int tryCount, uint16_t backoffMs) {
  if (masterFlag || timeStampCheckDisabled) return true;
  syncronized = false;
  for (int i=0; i<tryCount; i++) {
      unsigned long dbtm = millis();
      espNowFloodingMesh_requestInstantTimeSyncAnnonce(msg, size);

      while(1) {
        espNowFloodingMesh_loop();
        if (syncronized) {
          return true; // OK all received;
        }
        unsigned long elapsed = millis() - dbtm;
        if (elapsed > timeoutMs) {
          if (i < 10) { timeoutMs += backoffMs; }
          break;
        }
      }
  }
  return false;
}
