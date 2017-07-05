/*
 *  Created on: Jan 17, 2010
 *      Author: Jordan Myronuk 
 * Description: This program is responsible for receiving beacon or
 * 				addressed frames and will save each source MAC
 * 				address to a Neighbour table. 3 Threads are responsible
 * 				for reception, table updates, and user input respectively.
 *		 TODOS: Whitelist of MAC addresses.  Broadcasting targeted Deauth
 */
using namespace std;
#include <iostream>
#include <list>
#include <netinet/in.h>

#include <sys/socket.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif

#include <linux/if.h> // for "struct ifreq"
//#include <linux/wireless.h> // for ther wireless extensions

#include <errno.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/types.h>
#include "wlan.hpp"
#include "timer.h"
#include <pthread.h>//needed for user input, update and receive methods
#include <iomanip>
#include <iostream>
#include <math.h>

void * Receive();
void * update();
void * getUserInput();
bool quit = false;
bool sending = false;
const int MAX_UPDATES = 10;//maximum # of seconds before losing neighbour
const int UPDATE_INTERVAL = 2000000;//regular interval to update
char * PROGRAM_OPTIONS_DISPLAY = "Options: (q)uit <enter>";
char * device; //the server's interface ID
bool targetSelectionMode = true; //start without a target selected.

Ifconfig ifconfig;// interface configuration
pthread_mutex_t NEIGHBOUR_TABLE_MUTEX = PTHREAD_MUTEX_INITIALIZER;
//
// WLANAddr
//
char * WLANAddr::wlan2asc()
{
   static char str[32];

   sprintf(str, "%x:%x:%x:%x:%x:%x",
      data[0],data[1],data[2],data[3],data[4],data[5]);

   return str;
}
/* A Neighbour Entry */
struct neighbourEntry
{
	//WLANAddr address;
	__u64 address;
	unsigned char * addressString;//for output
	bool arrival; //initial arrival
	int lastRecord;//time since last received
	char * tag;//network name
	int numberOfBeacons;//number of beacons received
	int targetIndex;

	//create == operator if two entries equal (same address)
	bool operator==(const neighbourEntry &ne)
	{
		if (address == ne.address) return true;
		return false;
	}
};
//create an iterator for the STL list of neighbour entries
list<neighbourEntry>::iterator n;//table maintenance
list<neighbourEntry> neighbours; //keep a GLOBAL list of neighbour entries


struct targetMeasurement
{
	int signal;
	int noise;
	long targetTime;
	long localTime;
};
list<targetMeasurement>::iterator t;
list<targetMeasurement> measurements;

/* convert hex digit to int */
static int hexdigit(char a)
{
    if (a >= '0' && a <= '9') return(a-'0');
    if (a >= 'a' && a <= 'f') return(a-'a'+10);
    if (a >= 'A' && a <= 'F') return(a-'A'+10);
    return -1;
}


/* parse a MAC address */
static int sscanf6(char *str, char *format, int *a1, int *a2, int *a3, int *a4, int *a5, int *a6)
{
    int n;

    *a1 = *a2 = *a3 = *a4 = *a5 = *a6 = 0;
    while ((n=hexdigit(*str))>=0)
        (*a1 = 16*(*a1) + n, str++);
    if (*str++ != ':') return 1;
    while ((n=hexdigit(*str))>=0)
        (*a2 = 16*(*a2) + n, str++);
    if (*str++ != ':') return 2;
    while ((n=hexdigit(*str))>=0)
        (*a3 = 16*(*a3) + n, str++);
    if (*str++ != ':') return 3;
    while ((n=hexdigit(*str))>=0)
        (*a4 = 16*(*a4) + n, str++);
    if (*str++ != ':') return 4;
    while ((n=hexdigit(*str))>=0)
        (*a5 = 16*(*a5) + n, str++);
    if (*str++ != ':') return 5;
    while ((n=hexdigit(*str))>=0)
        (*a6 = 16*(*a6) + n, str++);

    return 6;
}

/* initialize the wireless interface and socket */
Outcome init()
{
   // (1) create device level socket
   // - PF_PACKET : low level packet interface
   // - SOCK_RAW : raw packets including link level header
   // - ETH_P_ALL : all frames will be received
	if ((ifconfig.sockid = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		printf("cannot open socket: %s\n", strerror(errno));
	    return NOK;
	}
   // (2) fetch the interface index
   struct ifreq ifr;
   strcpy(ifr.ifr_name, device);
   if (ioctl(ifconfig.sockid, SIOGIFINDEX, &ifr) < 0)
   {
	  printf("failed to fetch ifindex: %s\n", strerror(errno));
	  return NOK;
   }
   ifconfig.ifindex = ifr.ifr_ifindex;
   printf("ifindex: %d\n", ifconfig.ifindex);

   // (3) fetch the hardware address
   if (ioctl(ifconfig.sockid, SIOCGIFHWADDR, &ifr) == -1)
   {
	  printf("failed to fetch hardware address: %s\n", strerror(errno));
	  return NOK;
   }
   memcpy(&ifconfig.hwaddr.data, &ifr.ifr_hwaddr.sa_data, WLAN_ADDR_LEN);
   printf("hwaddr: %s\n", ifconfig.hwaddr.wlan2asc());

   // (4) fetch the MTU
   if (ioctl(ifconfig.sockid, SIOCGIFMTU, &ifr) == -1)
   {
	  printf("WLANProtocol, failed to the MTU: %s\n", strerror(errno));
	  return NOK;
   }
   ifconfig.mtu = ifr.ifr_mtu;
   printf("MTU: %d\n", ifconfig.mtu);

   // (5) add the promiscuous mode
   struct packet_mreq mr;
   memset(&mr,0,sizeof(mr));
   mr.mr_ifindex = ifconfig.ifindex;
   mr.mr_type =  PACKET_MR_PROMISC;
   if (setsockopt(ifconfig.sockid, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
	  (char *)&mr, sizeof(mr)) < 0)
   {
	  printf("WLANProtocol, failed to add the promiscuous mode: %d\n",
		 strerror(errno));
	  return NOK;
   }

   // (6) bind the socket to the interface (device)
   struct sockaddr_ll sll;
   memset(&sll, 0, sizeof(sll));
   sll.sll_family = AF_PACKET;
   sll.sll_ifindex = ifconfig.ifindex;
   sll.sll_protocol = htons(ETH_P_ALL);
   if (bind(ifconfig.sockid, (struct sockaddr*)&sll, sizeof(sll)) < 0)
   {
	  printf("WLANProtocol, failed to bind the socket: %d\n", strerror(errno));
	  return NOK;
   }
   return OK;
}
/* model in Neighbour Table ? */
//bool inNeighbourTable(WLANAddr & neighbour)
bool inNeighbourTable(__u64 & neighbour)
{
	for (n = neighbours.begin(); n != neighbours.end(); n++)
		if (n->address == neighbour)
		{//in neighbour table
			n->arrival = true;//set arrival true.
			return true;//return true
		}
	//neighbour does not exist
	return false;
}

/* add neighbourEntry to table */
//void addEntry(WLANAddr & neighbour)
void addEntry(__u64 & neighbour, unsigned char * addressString, char * tag)
{
	neighbourEntry ne;
	ne.address = neighbour;
	ne.arrival = true;	//signup entry
	ne.lastRecord = -1;	//last record = -1
	ne.addressString = addressString;
	ne.tag = tag;
	ne.numberOfBeacons = 1;
	neighbours.insert(neighbours.begin(), ne);
}

/* display neighbour table to the console */
void displayNeighbourTable()
{//output Neighbour table
	system("clear");
	cout << "===============================================================================================" << endl;
    cout << "TARGET No AVAILABLE TARGET(S)\tARRIVAL\t\tLast Recorded\tBEACONS\tNETWORK" << endl;
    cout << "===============================================================================================" << endl;

    int targetIndex = 1;
    for (n = neighbours.begin(); n != neighbours.end(); n++)
    {//loop for all neighbours in the table
    	cout << "\t" << targetIndex << " ";
    	//display the target MAC address
    	for (int i = 0; i < 6; i++)
		{
			cout << setbase(16) << setw(2) << setfill('0') << uppercase << (int)n->addressString[i];
			if (i != 5) cout << ":";
		}
      cout << '\t';
  	  if (n->arrival == 0) cout << "false";
  	  else cout << "true";
  	  cout << "\t\t" << n->lastRecord << "\t\t" << setbase(10) << n->numberOfBeacons << "\t" << n->tag << endl;
  	  targetIndex++;
    }
    cout << endl << endl << PROGRAM_OPTIONS_DISPLAY << endl;
}

// receive data over a socket
void * Receive(void * dummyPtr)
{
	// pointer to received data
	unsigned int i;// frame length
	struct sockaddr_ll from;// source address of the  message
	socklen_t fromlen = sizeof(struct sockaddr_ll);

	// infinite loop, safe from modifying any variables
	// that a thread would want to get to
	while (!quit)
	{
		//declare a fresh buffer
		unsigned char * buff = new unsigned char[ifconfig.mtu];
	  // (5) loop until a non-empty frame on "device"
	  while (!quit)
	  {
		 // (6) wait and receive a frame
		 fromlen = sizeof(from);

		 /* receive a frame over wireless medium */
		 i = recvfrom(ifconfig.sockid,
				 buff,
				 ifconfig.mtu,
				 0,
				 (struct sockaddr *) &from,
				 &fromlen);
		 if (i == -1)
		 {
			printf("Cannot receive data: %s\n", strerror(errno));
			// sleep for 10 milliseconds before re-trying
			usleep(10000);
		 }
		 else break; // exit the loop
	  }
	  /* frame received! */

	  //Extract destination and source addresses
	  //WLANHeader * frameHeader = processFrameSource(buff);

	  //save frame control - BEACON FRAME = 0x0080
      __u16 frame_control = buff[33];
      frame_control <<= 2;
      frame_control += buff[32];

		if (frame_control == 0x0080)
		{//only concerned with beacon frames

			//save radiotap header length
			__u16 radioTapHeaderLength = buff[3];
			radioTapHeaderLength <<= 2;//shift bits right 2 places
			radioTapHeaderLength += buff[2]; //add remaining 2 bytes

			//save the network name of the AP
			int beaconTagLength = (int)buff[69];
			char * beaconTag = new char[beaconTagLength + 1];
			beaconTag = (char*) &buff[70];
			beaconTag[beaconTagLength] = '\0';//add null string termination character @ end of string

			/*cout << "TARGET AP: ";
			for (int i = 0; i < 6; i++)
			{
				cout << setbase(16) << setw(2) << setfill('0') << hex << uppercase << (int)buff[42+i] << " ";
			}
			cout << endl;*/

			unsigned char * aSrcAddr = new unsigned char[7];
			//copy over source address to char * array
			for (int i = 0; i < 6; i++)
			{
				aSrcAddr[i] = buff[42+i];
			}
			aSrcAddr[6] = '\0'; //add termination character

			__u64 sourceAddress = buff[42];
			for (int i = 42; i < 48; i++)
			{
				sourceAddress <<= 2;
				sourceAddress += buff[i];
			}

			//save channel frequency (in MHz)
			__u32 channelFrequency = buff[19];
			channelFrequency <<= 8; //shift bits right 8 positions
			channelFrequency += buff[18];//add lower end of the 32bit integer

			__u16 signalStrength = 0xff - buff[22];//signal strength in -dB
			__u16 noiseStrength = 0xff - buff[23];//noise strength in -dB

			//calculate free space loss
			double FSL = 10 * log((int)signalStrength);

			targetMeasurement aMeasurement;
			aMeasurement.signal = signalStrength;
			aMeasurement.noise = noiseStrength;
			measurements.insert(measurements.begin(), aMeasurement);

			//output frame information
			/*
			cout << setbase(10);
			cout << "TAG LENGTH: " << beaconTagLength << endl;
			cout << "NETWORK: " << beaconTag << endl;
			cout << "SIGNAL STRENGTH: -" << (int)signalStrength << " dB" << endl;
			cout << "NOISE LEVEL: -" << (int)noiseStrength << " dB" << endl;
			cout << "FREQUENCY: " << (int)channelFrequency << " MHz" << endl;
			cout << "FREE SPACE LOSS: " << FSL << " dBm" << endl;
			cout << "TOTAL MEASUREMENTS: " << measurements.size() << endl;
			cout << "FRAME CONTROL: " << (int)frame_control << endl;
			cout << "TARGET AP: ";
			for (int i = 0; i < 6; i++)
			{
				cout << setbase(16) << setw(2) << setfill('0') << hex << uppercase << (int)buff[42+i] << " ";
			}
			cout << endl;*/


			/* aquire mutex lock over neighbour table */
			pthread_mutex_lock(&NEIGHBOUR_TABLE_MUTEX);

			//in neighbour table?
			//if (inNeighbourTable(frameHeader->srcAddr))
			if (inNeighbourTable(sourceAddress))
			{//yes, which one?
			  for (n = neighbours.begin();
					  n != neighbours.end(); n++)
					  if (n->address == sourceAddress)
					  {//this one, set arrival true, break
						  n->arrival = true;
						  n->numberOfBeacons++;
						  break;
					  }
			}
			else
			{//not in neighbour table, add entry
				addEntry(sourceAddress, aSrcAddr, beaconTag);
			}

			/* release mutex lock over neighbour table */
			pthread_mutex_unlock(&NEIGHBOUR_TABLE_MUTEX);

			/*float avgSig;
			for (int j = 0; j < measurements.size(); j++)
			{
				avgSig += aMeasurement.signal;
			}

			float aSigAvg = avgSig / measurements.size();*/

			//output frame raw data
			/*
			cout << "AVG Signal:" << aSigAvg << endl;

			cout << "[FRAME BEGIN] - LENGTH:" << setbase(10) << i << " Bytes" << endl;
			cout << "       0| 1| 2| 3| 4| 5| 6| 7|     8| 9| A| B| C| D| E| F|" << endl;
			int k = 0;
			cout << setw(4) << setbase(10) << k << ": ";//addressing row begin
			for (int j = 0; j <= (int)i; j++)
			{
				if (j % 8 == 0 && j % 16 != 0) cout << "    ";
				else if (j % 16 == 0 && j != 0) { k += 10; cout << endl << setbase(10) << setw(4) << k << ": ";}

				cout << setbase(16) << setw(2) << setfill('0') << uppercase << hex << (int)buff[j] << " ";
			}
			cout << endl << "[FRAME END]" << endl;
			*/
		}
	}//end while
}
/* Update the Neighbour Table lastRecord entries */
void * update(void * dummyPtr)
{
	Timer timer;
	//loop until user says quit
	while(!quit)
		if (timer.elapsed(UPDATE_INTERVAL))
		{//update tables
			//aquire mutex to work with neighbour table
			/* lock access to the neighbour table */
			pthread_mutex_lock (&NEIGHBOUR_TABLE_MUTEX);

			//loop through all neighbours
			for (n = neighbours.begin();
					n != neighbours.end(); n++)
			{/* IMPLEMENTATION OF FIG 2 */
				if (n->arrival)
				{
					if (n->lastRecord == -1)
					{
						//neighbour found
					}

					n->arrival = false;
					n->lastRecord = 0;
				}
				else
				{
					if (n->lastRecord >= MAX_UPDATES)
					{	//neighbour lost!
						//SOURCE:http://www.gidforums.com/t-17428.html
						//CREDIT TO: davekw7x for the post
						n = neighbours.erase(n);
						n--;//next 'for' will increment iterator
					}
					else n->lastRecord++;
				}
			}
			/* EXIT POINT OF FIG 2 */

			//display the neighbour table
			displayNeighbourTable();

			pthread_mutex_unlock(&NEIGHBOUR_TABLE_MUTEX);
			/* unlock access to the neighbour table */
			//mutex no longer needed.
		}
}
//close ports for clean shutdown
void shutdown()
{
   // close the socket
   if (ifconfig.sockid != -1) close(ifconfig.sockid);
   cout << "clean shutdown" << endl;
}
/* User Input Thread quits when any key is hit. */
void * getUserInput(void * dummyPtr)
{
	char a = 'x';
	while (a != '\n')
	{
		fflush(stdin);
		char a;
		cin >> a;
		if (a == 'q') break;
		//check for user selection of target
	}
	quit = true;
}
/* main program loop */
int main(int argc, char* argv[])
{
	Timer timer;//update timer
	/* Threading code adapted from...
	 * http://www.yolinux.com/TUTORIALS/LinuxTutorialPosixThreads.html
	 * Example: pthread1.c, and Mutexes: mutex1.c
	 */
	pthread_t receiveThread, updateThread, userInputThread;

	if (argc != 2) cout << "Dartanion Usage: ./Dartanion <wireless interface>" << endl;
	else
	{//proper amount of input args anyways
		device = argv[1]; //save wireless interface
		if (init()==OK)
		{//adapted pthread1.c code

			/* create 3 threads needed for program operation*/

			//start recieve packet thread
			pthread_create(&receiveThread, NULL, &Receive, NULL);

			//start table update thread
			pthread_create(&updateThread, NULL, &update, NULL);

			//start user input thread
			pthread_create(&userInputThread, NULL, &getUserInput, NULL);

			Timer timer;
			while (!quit)
			{
				/* main program loop, it will quit
				 * when the user hits 'q' and enter.
				 * the threads will loop in the back-
				 * ground.
				 */
				usleep(5000);
			}
			/* quit variable will force all threads to exit loops */

			//these threads will finish gracefully
			pthread_join(userInputThread, NULL);
			pthread_join(updateThread, NULL);

			cout << "forcing last thread" << endl;
			//this thread will need to be crushed
			pthread_cancel(receiveThread);
		}
		shutdown();//close socket
		//graceful shutdown.
	}
	return 0;
}
