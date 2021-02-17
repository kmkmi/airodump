#include <pcap.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "main.h"
#include <map>
#include <pthread.h>
#include <unistd.h>
#include <vector>

std::map<Mac, Ap_value> AP_List;

std::map<Mac, std::vector<int>> PowerList;

void usage() {
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan0\n");
}


char* hex(u_int8_t *addr, char* buf, int size)
{

    for(int i=0;i<size;i++)
    {
        snprintf(buf+(3*i),size, "%02x",addr[i]);
        if(i!=size-1)
            snprintf(buf+2+(3*i),2,":");

    }

    return buf;

}


void* consoleRefresh(void* p){


    while(true){
        sleep(1);
        system("clear");
        printf("BSSID\t\t\tBeacons\tPWR\t#Data\tENC\tESSID\n\n");

        for(auto i : AP_List){
            printf("%s\t%u\t%d\t%u\t%s\t%s\n", std::string(i.first).c_str(),
                   i.second.Beacons,i.second.pwr, i.second.nData, i.second.enc, i.second.ESSID);
        }
    }

}



void callback(u_char *user ,const struct pcap_pkthdr* header, const u_char* pkt_data ){

    struct Rtap *rtap_hdr;



    rtap_hdr = (struct Rtap*)pkt_data;

    size_t offset=8 ;

    int pwr = 0;

    if(rtap_hdr->present_flags[0].ext)
        offset+=4;

    if(rtap_hdr->present_flags[0].tsft)
        offset+=8;

    if(rtap_hdr->present_flags[0].flags)
        offset+=1;
    if(rtap_hdr->present_flags[0].rate)
        offset+=1;
    if(rtap_hdr->present_flags[0].channel)
        offset+=4;
    if(rtap_hdr->present_flags[0].fhss)
        offset+=1;

    if(rtap_hdr->present_flags[0].dbm_antenna_sig )
    {

        uint8_t* p = (uint8_t*)pkt_data+offset;
        pwr =  -((int)p[0]-1)^0xFF;
    }


    if(rtap_hdr->present_flags[0].ext ){

        if(rtap_hdr->present_flags[1].tsft && !rtap_hdr->present_flags[0].tsft)
            offset+=8;

        if(rtap_hdr->present_flags[1].flags && !rtap_hdr->present_flags[0].flags)
            offset+=1;
        if(rtap_hdr->present_flags[1].rate && !rtap_hdr->present_flags[0].rate)
            offset+=1;
        if(rtap_hdr->present_flags[1].channel && !rtap_hdr->present_flags[0].channel)
            offset+=4;
        if(rtap_hdr->present_flags[1].fhss && !rtap_hdr->present_flags[0].fhss)
            offset+=1;
        if(rtap_hdr->present_flags[0].dbm_antenna_sig || rtap_hdr->present_flags[1].dbm_antenna_sig)
        {

            uint8_t* p = (uint8_t*)pkt_data+offset;
            pwr =  -((int)p[0]-1)^0xFF;
        }

    }

    if(1){

        struct Beacon_Frame *bf_hdr;
        struct Data_Frame *df_hdr;

        pkt_data+= rtap_hdr->header_length;
        bf_hdr = (struct Beacon_Frame*)pkt_data;
        df_hdr = (struct Data_Frame*)bf_hdr;



        if(bf_hdr->frame_control_field.isBeaconFrame()){



            auto itr = AP_List.find(bf_hdr->mac3);
            if(itr != AP_List.end()){
                itr->second.Beacons++;
                if(pwr!=0) itr->second.pwr = pwr;
            }else{

                Dot11_wlan* d11wl = (struct Dot11_wlan*)(bf_hdr+1);
                char buf[33];
                d11wl->getSSID(buf);
                char enc[] = "";
                Ap_value v(1, 0, enc, buf, pwr);
                AP_List.insert({bf_hdr->mac3,v});
            }


            auto itr2 = PowerList.find(bf_hdr->mac2);
            if(itr2 != PowerList.end()){
                if(pwr!=0) itr2->second.push_back(pwr);
            }else{

                std::vector<int> v = {pwr};
                if(pwr!=0) PowerList.insert({bf_hdr->mac2,v});
            }

        }else if(df_hdr->frame_control_field.isDataFrame()){

            if(df_hdr->mac1 != Mac("ff:ff:ff:ff:ff:ff")){
                auto itr = AP_List.find(df_hdr->mac1);
                if(itr != AP_List.end()){
                    itr->second.nData++;
                    if(pwr!=0) itr->second.pwr = pwr;
                }else{

                    Ap_value v(0, 1, (char*)"", (char*)"",pwr);
                    AP_List.insert({df_hdr->mac1,v});
                }
            }
            auto itr = AP_List.find(df_hdr->mac2);
            if(itr != AP_List.end()){
                itr->second.nData++;
                if(pwr!=0) itr->second.pwr = pwr;
            }else{

                Ap_value v(0, 1, (char*)"", (char*)"",pwr);
                AP_List.insert({df_hdr->mac2,v});
            }

            auto itr2 = PowerList.find(bf_hdr->mac2);
            if(itr2 != PowerList.end()){
                if(pwr!=0) itr2->second.push_back(pwr);
            }else{

                std::vector<int> v = {pwr};
                if(pwr!=0) PowerList.insert({bf_hdr->mac2,v});
            }



        }else if(bf_hdr->frame_control_field.isProbeResponse()){

            auto itr = AP_List.find(bf_hdr->mac3);
            if(itr != AP_List.end()){
                if(pwr!=0) itr->second.pwr = pwr;
            }else{

                Dot11_wlan* d11wl = (struct Dot11_wlan*)(bf_hdr+1);
                char buf[33];
                d11wl->getSSID(buf);
                char enc[] = "";
                Ap_value v(0, 0, enc, buf,pwr);
                AP_List.insert({bf_hdr->mac3,v});
            }
            auto itr2 = PowerList.find(bf_hdr->mac2);
            if(itr2 != PowerList.end()){
                if(pwr!=0) itr2->second.push_back(pwr);
            }else{

                std::vector<int> v = {pwr};
                if(pwr!=0) PowerList.insert({bf_hdr->mac2,v});
            }

        }


    }

}




int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];



    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", argv[1], errbuf);
        return -1;
    }




    pthread_t p_thread;
    int tid;
    int stat;
    if ((tid = pthread_create(&p_thread, NULL, consoleRefresh, (void*)NULL)) < 0)
    {
        perror("Failed to create pthread.");
        exit(-1);
    }
    printf("started.");

    int ret = pcap_loop(handle, -1, callback, NULL );
    if (ret == -1 || ret == -2) {
        printf("pcap_next_ex return %d(%s)\n", ret, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    pcap_close(handle);


    pthread_join(p_thread, (void **) &stat);
    printf("Thread end stat : %d\n", stat);




}
