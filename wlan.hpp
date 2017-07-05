// 802.11 Programming example
// Author: Michel Barbeau, January 2004
//
// File: wlan.hpp
//

typedef int Outcome;
#define OK 0
#define NOK -1

typedef int FrameType;
#define MANAGEMENT_FRAME 0x00;
#define CONTROL_FRAME 0x01
#define DATA_FRAME 0x02

typedef int MANAGEMENT_SUB_TYPE;
#define PROBE_REQUEST 0x04;
#define PROBE_RESPONSE 0x05;
#define BEACON 0x08;

typedef int CONTROL_SUB_TYPE;
#define RTS 0x11;
#define CTS 0x12;
#define ACK 0x13;

typedef int DATA_SUB_TYPE;
#define NULL_FUNCTION 0x04;
#define CF_ACK_NODATA 0x05;
#define CF_POLL_NODATA 0x06;
#define CF_ACK_POLL_NODATA 0x07;

#define MAX_NAME_LEN 128

// Declaration of struct WLANAddr.
#define WLAN_ADDR_LEN 6
struct WLANAddr {
    // address
    unsigned char data[WLAN_ADDR_LEN];
    // return the address in a human readable form
    char* wlan2asc();
    // defined the address from a human readable form
    Outcome str2wlan(char*);

    bool operator==(const WLANAddr& addr)
    {
        if (addr.data[0] == data[0] && addr.data[1] == data[1] && addr.data[2] == data[2] && addr.data[3] == data[3] && addr.data[4] == data[4] && addr.data[5] == data[5])
            return true;
        else
            return false;
    }
};

// format of an WLAN header
struct WLANHeader {
    __u64 destAddr;
    __u64 srcAddr;
};
#define WLAN_HEADER_LEN 12 // bytes

// wireless interface configuration
struct Ifconfig {
    int sockid; // socket descriptor
    int ifindex; // index of the interface
    WLANAddr hwaddr; // MAC address
    int mtu; // maximum transmission unit
};

