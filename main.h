#pragma once

#include <cstdint>
#include <cstring>
#include <string>

#define MANAGEMENT_FRAME 0b00
#define BEACON_FRAME 0b1000
#define PROBE_RESPONSE 0b0101
#define DATA_FRAME 0b10
#define NULL_SUBTYPE 0b0100
#define QOS_NULL 0b1100

typedef struct Mac final {
    static const int SIZE = 6;
    uint8_t mac_[SIZE];

    //
    // constructor
    //
    Mac() {}
    Mac(const uint8_t* r) { memcpy(this->mac_, r, SIZE); }
    Mac(const std::string r);


    // casting operator
    //
    operator uint8_t*() const { return const_cast<uint8_t*>(mac_); } // default
    explicit operator std::string() const;

    //
    // comparison operator
    //

    bool operator < (const Mac& r) const
    {
        for (int i=0; i<6; i++){
            if(mac_[i] == r.mac_[i])
                continue;
            return mac_[i] > r.mac_[i];
        }
        return false;
    };

    bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; };
    bool operator != (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) != 0; };



} Mac;

Mac::Mac(const std::string r) {
    unsigned int a, b, c, d, e, f;
    int res = sscanf(r.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", &a, &b, &c, &d, &e, &f);
    if (res != SIZE) {
        fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
        return;
    }
    mac_[0] = a;
    mac_[1] = b;
    mac_[2] = c;
    mac_[3] = d;
    mac_[4] = e;
    mac_[5] = f;
}

Mac::operator std::string() const {
    char buf[32]; // enough size
    sprintf(buf, "%02x:%02X:%02X:%02X:%02X:%02X",
            mac_[0],
            mac_[1],
            mac_[2],
            mac_[3],
            mac_[4],
            mac_[5]);
    return std::string(buf);
}


#pragma pack(push, 1)

typedef struct Present_Flags{
    uint8_t tsft:1;
    uint8_t flags:1;
    uint8_t rate:1;
    uint8_t channel:1;
    uint8_t fhss:1;
    uint8_t dbm_antenna_sig:1;


    uint8_t extra1:2;
    uint8_t extra2[2];
    uint8_t extra3:7;

    uint8_t ext:1;
}Present_Flags;

typedef struct Rtap{

    uint8_t header_revision;
    uint8_t header_pad;
    uint16_t header_length;
    Present_Flags present_flags[2];

} Rtap;




typedef struct Frame_Control_Field{
    uint8_t version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t flags;

    void init(uint16_t i){
        this->subtype = i >> 12;
        this->type = (i >> 10) & 0b11;
        this->version = (i >> 8) & 0b11;
        this->flags = i & 0xFF;
    }

    bool isBeaconFrame(){
        if (this->type == MANAGEMENT_FRAME && this->subtype == BEACON_FRAME)
            return true;

        return false;
    }

    bool isProbeResponse(){
        if (this->type == MANAGEMENT_FRAME && this->subtype == PROBE_RESPONSE)
            return true;

        return false;
    }


    bool isDataFrame(){
        if (this->type == DATA_FRAME && this->subtype != NULL_SUBTYPE && this->subtype != QOS_NULL )
            return true;

        return false;
    }


}Frame_Control_Field;

//Beacon Frame and Probe Response Can Use This Structure.
typedef struct Beacon_Frame{
    Frame_Control_Field frame_control_field;
    uint16_t duration;
    Mac mac1;
    Mac mac2;
    Mac mac3;
    uint16_t sequence_number:12;
    uint16_t fragment_number:4;
}Beacon_Frame;

typedef struct Data_Frame{
    Frame_Control_Field frame_control_field;
    uint16_t duration;
    Mac mac1;
    Mac mac2;

}DATA_Frame;

typedef struct Dot11_wlan{
    uint8_t fixed_parameters[12];
    uint8_t tag_number;
    uint8_t tag_length;
    char ssid[32];

    void getSSID(char* buf){

        strncpy(buf, ssid,(size_t)tag_length );
        buf[(size_t)tag_length] = '\0';
    }
}Dot11_wlan;



typedef struct Ap_value{
    uint8_t Beacons;
    uint8_t nData;
    char enc[4];
    char ESSID[33];
    unsigned int pwr;

    Ap_value(uint8_t Beacons,
             uint8_t nData,
             char* enc,
             char* ESSID,
             int pwr){
        this->Beacons = Beacons;
        this->nData = nData;
        strncpy((char*)&this->enc, enc, strlen(enc)+1);
        strncpy((char*)&this->ESSID, ESSID, strlen(ESSID)+1);
        this->pwr = pwr;
    };

}Ap_value;
#pragma pack(pop)
