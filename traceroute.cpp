/*
	TRACEROUTE
	PROJEKT #2 pro IPK
	Autor: Jakub Zapletal (xzaple36)
*/
#include "traceroute.h"

//Globální proměnná uchovávající pořadové číslo posledního odeslaného paketu
int packet_count = 0;

/*
	bool validateIp(string IP)
		=> PARAMETRY:
			=> string IP - IPv4/IPv6 adresa v tečkové/dvojtečkové notaci

		=> Provede validaci IP adresy
		=> Vrací true pokud parametrem předaná adresa odpovídá formátu IP adresy.
*/
bool validateIp(string IP)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, IP.c_str(), &(sa.sin_addr));
    if ((result == 0 || result == -1))
    	result = inet_pton(AF_INET6, IP.c_str(), &(sa.sin_addr));
    return (result != 0 && result != -1);
}

/*
	void argHandle(int argc, char* argv[], int *TTL_first, int *TTL_max, string *IP)
		=> PARAMETRY:
			=> int argc 		- počet argumentů příkazové řádky
			=> char* argv[] 	- argumenty příkazové řádky
			=> int *TTL_first	- ukazatel na proměnnou s počátečním TTL
			=> int *TTL_max		- ukazatel na proměnnou s maximálním TTL
			=> string *IP 		- ukazatel na proměnnou s IP adresou

		=> Zpracuje argumenty příkazové řádky.
		=> Pokud je zadáno hostname místo IP adresy, je proveden DNS lookup. 
*/
void argHandle(int argc, char* argv[], int *TTL_first, int *TTL_max, string *IP)
{
	if (argc < 2)
	{
		fprintf(stderr, "Error: MISSING_PARAMETER_ERROR\n");
		exit(-1);
	}

	if (argc > 2)
	{
		int arg;
		while ((arg = getopt(argc, argv, "f:m:")) != -1)
		{
			switch (arg)
			{
				case 'f':
					*TTL_first = atoi(optarg);
					break;
				case 'm':
					*TTL_max = atoi(optarg);
					break;
				default:
					fprintf(stderr, "Error: UNKNOWN_PARAMETER_ERROR\n");
					exit(-1);
			}
		}
		*IP = argv[optind];
	}
	else
		*IP = argv[1];

	if (!validateIp(*IP))
	{
		/*
			DNS lookup
		*/
		hostent * record = gethostbyname((*IP).c_str());
		if(record == NULL)
		{
			fprintf(stderr, "Error: HOSTNAME_UNRESOLVABLE\n");
			exit(-1);
		}
		in_addr * address = (in_addr * )record->h_addr;
		*IP = inet_ntoa(* address);
	}
}

/*
	int socketInit(int family)
		=> PARAMETRY:
			=> int family - celočíselný identifikátor IP protocol (IPv4/IPv6)

		=> Vytvoří UDP socket s příslušnými parametry.
		=> Nastaví vlastnost IP_RECVERR/IPV6_RECVERR socketu aby bylo možné zpracovávat ICMP chyby.
		=> Vrací identifikátor vytvořeného socketu.
*/
int socketInit(int Family)
{
	int s;

	if (Family == AF_INET)
	{
		if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		{
			fprintf(stderr, "Error: SOCKET_CREATE_ERR\n");
			exit(errno);
		}
		int val = 1; 
		if (setsockopt(s, SOL_IP, IP_RECVERR,(char*)&val, sizeof(val)))
		{
			fprintf(stderr, "Error: SOCKET_SET_OPTION_ERR\n");
			exit(errno);
		}
	}
		
	else
	{
		if((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		{
			fprintf(stderr, "Error: SOCKET_CREATE_ERR\n");
			exit(errno);
		}
		int val = 1; 
		if (setsockopt(s, SOL_IPV6, IPV6_RECVERR,(char*)&val, sizeof(val)))
		{
			fprintf(stderr, "Error: SOCKET_SET_OPTION_ERR\n");
			exit(errno);
		}
	}

	return s;
}

/*
	string resolve(struct sockaddr_in *sin)
		=> PARAMETRY:
			=> struct sockaddr_in *sin - odkaz na strukturu adresy, jejíž hostname chceme zjistit

		=> Provede reverzní PTR dotaz k ipv4 adrese získané z ICMP chyby.
		=> Provede 3 pokusy pokud se první nezdaří.
		=> Pokud je hostname získáno, je i vráceno, jinak je vrácen prázdný řetězec.
*/
string resolve(struct sockaddr_in *sin)
{
	char host[1024];
	char service[20];
	int result;

	result = getnameinfo((sockaddr *)sin, sizeof (*sin), host, sizeof (host), service, sizeof (service), 0);
	if (result = EAI_AGAIN)
	{
		for (int i = 0; i < 3 && result == EAI_AGAIN; i++)
		{
			result = getnameinfo((sockaddr *)sin, sizeof (*sin), host, sizeof (host), service, sizeof (service), 0);
		}
	}
	if (result == 0)
		return host;
	else
		return "";
}

/*
	string resolve6(struct sockaddr_in *sin6)
		=> PARAMETRY:
			=> struct sockaddr_in *sin6 - odkaz na strukturu adresy, jejíž hostname chceme zjistit

		=> Provede reverzní PTR dotaz k ipv6 adrese získané z ICMP chyby.
		=> Provede 3 pokusy pokud se první nezdaří.
		=> Pokud je hostname získáno, je i vráceno, jinak je vrácen prázdný řetězec.
*/
string resolve6(struct sockaddr_in6 *sin6)
{
	char host[1024];
	char service[20];
	int result;

	result = getnameinfo((sockaddr *)sin6, sizeof (*sin6), host, sizeof (host), service, sizeof (service), 0);
	if (result = EAI_AGAIN)
	{
		for (int i = 0; i < 3 && result == EAI_AGAIN; i++)
		{
			result = getnameinfo((sockaddr *)sin6, sizeof (*sin6), host, sizeof (host), service, sizeof (service), 0);
		}
	}
	if (result == 0)
		return host;
	else
		return "";
}

/*
	int recv_err(int s, string *host, string *latency, struct timeval timestamp)
		=> PARAMETRY:
			=> int s 						- identifikátor socketu
			=> string *host 				- ukazatel na řetězec, do nějž se uloží hostname a IP adresa odesílatele ICMP chyby
			=> string *latency				- ukazatel na řetězec, do nějž se uloží časová odezva
			=> struct timeval timestamp 	- timestamp odeslání paketu

		=> Funkce, která zpracovává příchozí ICMP chyby a dekóduje je.
		=> Vrácí celočíselný kód identifikující ICMP chybu.
*/
int recv_err(int s, string *host, string *latency, struct timeval timestamp)
{
	int res;
	char cbuf[512];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sock_extended_err *e;
	struct icmphdr icmph;
	struct sockaddr_in target, addr;
	struct timeval arrive_time;
	int opts;

	for (;;)
	{
		iov.iov_base = &icmph;
		iov.iov_len = sizeof(icmph);
		msg.msg_name = (void*)&target;
		msg.msg_namelen = sizeof(target);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);


		/*
			timeout
		*/
		struct pollfd fd;
		int res;

		fd.fd = s;
		fd.events = POLLIN;
		res = poll(&fd, 1, 2000); // 2000 ms timeout

		if (res == 0)
		{
			*latency = "*";
		    return TIMEOUT;
		}
		else if (res == -1)
		{
		    fprintf(stderr, "Error: SOCKET_SET_TIMEOUT_ERR\n");
			exit(errno);
		}
		else
		{
		    res = recvmsg(s, &msg, MSG_ERRQUEUE | MSG_WAITALL);
		}
		if (res<0)
		{
			continue;
		}

		gettimeofday(&arrive_time, NULL); //Druhý timestamp pro výpočet odezvy

		/*
			Kontrola toho, jestli se opravdu jedná o ICMP/ICMPV6 chybu
		*/
		for (cmsg = CMSG_FIRSTHDR(&msg);cmsg; cmsg =CMSG_NXTHDR(&msg, cmsg))
		{
			if (cmsg->cmsg_level == SOL_IP || cmsg->cmsg_level == SOL_IPV6)
			{
				if (cmsg->cmsg_type == IP_RECVERR || cmsg->cmsg_type == IPV6_RECVERR)
				 {
					e = (struct sock_extended_err*)CMSG_DATA(cmsg);
					if (e)
						if (e->ee_origin == SO_EE_ORIGIN_ICMP || e->ee_origin == SO_EE_ORIGIN_ICMP6) 
						{
							/*
								Výpočet odezvy z rozdílu dvou timestampů, první je proveden po odeslání paketu a druhý po přijetí ICMP chyby.
								Timestampy jsou převedeny na milisekundy a odezva je zaokrouhlena na 3 desetinná místa.
							*/
							float lag = float((arrive_time.tv_sec*1000000 + arrive_time.tv_usec) - (timestamp.tv_sec*1000000 + timestamp.tv_usec))/1000;
							stringstream precision;
							precision << fixed << setprecision(3) << lag;	//
							*latency = precision.str();						//	Zaokrouhlování odezvy 			
							(*latency).append("ms");						//

							if (e->ee_origin == SO_EE_ORIGIN_ICMP)
							{
								struct sockaddr_in *sin = (struct sockaddr_in *)(e+1);
								/*
									Zpětné získání Hostname a vytvoření výpisu ve tvaru HOSTNAME(IP)
								*/
								*host = resolve(sin);
								(*host).append("(");
								(*host).append(inet_ntoa(sin->sin_addr));
								(*host).append(")");
								/*
									Dekódování ICMP chyby
								*/
								if ((e->ee_type == ICMP_DEST_UNREACH) && (e->ee_code == ICMP_PORT_UNREACH))
								{
									return PORT_UNR;
								}
								else if ((e->ee_type == ICMP_TIME_EXCEEDED) && (e->ee_code == ICMP_EXC_TTL))
								{
									return TTL_ZERO;
								}
								else if ((e->ee_type == ICMP_DEST_UNREACH ) && (e->ee_code == ICMP_NET_UNREACH))
								{
									return NET_UNR;
								}
								else if ((e->ee_type == ICMP_DEST_UNREACH) && (e->ee_code == ICMP_HOST_UNREACH))
								{
									return HOST_UNR;
								}
								else if ((e->ee_type == ICMP_DEST_UNREACH) && (e->ee_code == ICMP_PROT_UNREACH))
								{
									return PROT_UNR;
								}
								else if ((e->ee_type == ICMP_DEST_UNREACH)&& (e->ee_code == ICMP_PKT_FILTERED))
								{
									return ADM_DOWN;
								}
									return 0;
							}
							else
							{
								struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(e+1);
								/*
									Zpětné získání Hostname a vytvoření výpisu ve tvaru HOSTNAME(IP)
								*/
								char buffer[INET6_ADDRSTRLEN]; 
								inet_ntop(AF_INET6, &(sin6->sin6_addr), buffer, sizeof(buffer));
								*host = resolve6(sin6);
								(*host).append("(");
								(*host).append(buffer);
								(*host).append(")");
								/*
									Dekódování ICMP6 chyby
								*/
								if ((e->ee_type == ICMPV6_DEST_UNREACH) && (e->ee_code == ICMPV6_PORT_UNREACH))
								{
									return PORT_UNR;
								}
								else if ((e->ee_type == ICMPV6_TIME_EXCEED) && (e->ee_code == ICMPV6_EXC_HOPLIMIT))
								{
									return TTL_ZERO;
								}
								else if ((e->ee_type == ICMPV6_DEST_UNREACH ) && (e->ee_code == ICMPV6_NOROUTE))
								{
									return NET_UNR;
								}
								else if ((e->ee_type == ICMPV6_DEST_UNREACH) && (e->ee_code == ICMPV6_ADDR_UNREACH))
								{
									return HOST_UNR;
								}
								else if ((e->ee_type == ICMPV6_PARAMPROB) && (e->ee_code == ICMPV6_UNK_NEXTHDR))
								{
									return PROT_UNR;
								}
								else if ((e->ee_type == ICMPV6_DEST_UNREACH)&& (e->ee_code == ICMPV6_ADM_PROHIBITED))
								{
									return ADM_DOWN;
								}
									return 0;
							}
							
						}
				}
			}
		}
	}
}

/*
	int ping(int socket, void *sa, int size, int family)
		=> PARAMETRY:
			=> int socket 	- identifikátor socketu
			=> void *sa 	- void ukazatel na adresovou strukturu (void zajišťuje univerzálnost pro IPV4 a IPV6)
			=> int size 	- velikost adresové struktury
			=> int family 	- celočíselný identifikátor IP protocol (IPv4/IPv6)

		=> Funkce provede zaslání 3 paketů s momentálně nastaveným TTL a vypíše hostname, IP adresu a odezvu.
		=> Ukončí běh programu pokud ICMP odpověď značí nedosáhnutelnou síť, hosta, port, protokol nebo administratively down chybu.
		=> Vrací výsledek funkce recv_err.
*/
int ping(int socket, void *sa, int size, int family)
{
	int result;
	string host;
	string latency [3] = {"","",""};
	string message = "";
	bool finished = false;
	struct timeval timestamp;

	packet_count++;
	for (int i = 0; i < 3; i++)
	{
		if (sendto(socket, NULL, 0, 0,  (struct sockaddr*)sa, size))
		{
			if (errno != 113)
			{
				fprintf(stderr, "Error: SOCKET_SEND_ERR\n");
				exit(errno);
			}
				
		}
		gettimeofday(&timestamp, NULL);
		result = recv_err(socket, &host, &latency[i], timestamp);

		switch (result)
		{
			case HOST_UNR:
				latency[i] = "!H";
				i = 4;
				finished = true;
				break;
			case NET_UNR:
				latency[i] = "!N";
				i = 4;
				finished = true;
				break;
			case PROT_UNR:
				latency[i] = "!P";
				i = 4;
				finished = true;
				break;
			case ADM_DOWN:
				latency[i] = "!X";
				i = 4;
				finished = true;
				break;
			case PORT_UNR:
				finished = true;
			case TIMEOUT:
			case TTL_ZERO:
				continue;
		}
		break;
	}

	cout << packet_count << ")\t" << host << "\t" <<  latency[0] << " " << latency[1] << " " << latency[2] << "\n";

	if (finished)
		exit(0);

	return result;
}

int main(int argc, char* argv[])
{
	int TTL_first = 1; 			// ttl prvního paketu
	int TTL_max = 30; 			// maximální ttl
	string IP = "";				// ip adresa v tečkové/dvojtečkové notaci
	int IPFamily;				// celočíselný identifikátor ip protokolu
	int pingSocket;				// identifikátor socketu
	struct sockaddr_in sa;  	// struktura IPV4 adresy
	struct sockaddr_in6 sa6;	// struktura IPV6 adresy

	argHandle(argc, argv, &TTL_first, &TTL_max, &IP);

	/*
		Typ adresy je rozhodnut podle přítomnosti dvojtečky v adrese
	*/
	if (IP.find(':') == string::npos)
	{
		sa.sin_family = AF_INET;
		IPFamily = AF_INET;
		sa.sin_port = htons(33434);
		inet_pton(AF_INET, IP.c_str(), &(sa.sin_addr));
	}
		
	else
	{
		sa6.sin6_family = AF_INET6;
		IPFamily = AF_INET6;
		sa6.sin6_port = htons(33434);
		inet_pton(AF_INET6, IP.c_str(), &(sa6.sin6_addr));
	}

	pingSocket = socketInit(IPFamily);

	/*
		samotná komunikace
	*/
	for (int i = TTL_first; i <= TTL_max; i++)
	{
		if (IPFamily == AF_INET)
		{
			if (setsockopt(pingSocket, IPPROTO_IP, IP_TTL, &i, sizeof(i)))
		 	{
				fprintf(stderr, "Error: SOCKET_SET_TTL_ERR\n");
				exit(errno);
			}
			ping(pingSocket, &sa, sizeof(sa), 4);
		}
		else
		{
			if (setsockopt(pingSocket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &i, sizeof(i)))
		 	{
				fprintf(stderr, "Error: SOCKET_SET_HOP_LIMIT_ERR\n");
				exit(errno);
			}
			ping(pingSocket, &sa6, sizeof(sa6), 6);
		}
	}
}