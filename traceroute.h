/*
	TRACEROUTE
	PROJEKT #2 pro IPK
	Autor: Jakub Zapletal (xzaple36)
*/
#include <linux/errqueue.h>
#include <linux/icmpv6.h>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include <regex.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>

#include <string>
#include <iostream>
#include <vector>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>


#define TTL_ZERO 		0
#define PORT_UNR 		1
#define HOST_UNR 		2
#define NET_UNR			3
#define PROT_UNR		4
#define TIMEOUT			5
#define ADM_DOWN		13
#define UNKNOWN_ICMP 	-1


using namespace std;