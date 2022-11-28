/*
	Packet sniffer using libpcap library
*/
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sys/socket.h>
// #include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h>	 //Provides declarations for udp header
#include <netinet/tcp.h>	 //Provides declarations for tcp header
#include <netinet/ip.h>		 //Provides declarations for ip header

#include <sqlite3.h>
#include <time.h>
#include <pthread.h>
// #include <signal.h>

#define DEBUG 1
#define HOSTNAME "WWW"
#define FileName "sniffer.db"
#define N 50
#define SQL_LEN 150
#define TIME 86400 // number seconds in a day

static int callback_open_db(void *not_used, int argc, char **argv, char **az_col_name);
int create_DB();
static int callback_insert(void *not_used, int argc, char **argv, char **az_col_name);
int insert_URLS_to_block_to_DB();
u_char *extract_url_from_packet(const u_char *buffer);
static int callback_check_result(void *p_user, int argc, char **col_data, char **col_names);
static int callback_check_time(void *req, int argc, char **argv, char **az_col_name);
int insert_url_to_DB(const char url[N], long enter_time);
int is_exist_PACKETS_table(const char url[N], long enter_time);
int is_exist_URLS_table(const char *url, long enter_time);
int blockPacket(const char url[N]);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
int freePacket(const char url[N]);
static int callback_delete(void *not_used, int argc, char **argv, char **az_col_name);
int delete_url_from_DB(const char url[N]);

struct Data
{
	const char url[N];
	long enter_time;
	int flag;
};

typedef struct
{
	uint16_t xid;	  /* Randomly chosen identifier */
	uint16_t flags;	  /* Bit-mask to indicate request/response */
	uint16_t qdcount; /* Number of questions */
	uint16_t ancount; /* Number of answers */
	uint16_t nscount; /* Number of authority records */
	uint16_t arcount; /* Number of additional records */
} dns_header_t;

typedef struct
{
	char *name;		   /* Pointer to the domain name in memory */
	uint16_t dnstype;  /* The QTYPE (1 = A) */
	uint16_t dnsclass; /* The QCLASS (1 = IN) */
} dns_question_t;

FILE *logfile;
sqlite3 *sniffer;
struct sockaddr_in source, dest; // ???? not used
int i, j;
FILE *urlBlockFile;

int main()
{
	// put in thread 1
	// create_DB();
	// recycle thread 1 - to do another func
	// insert_URLS_to_block_to_DB();

	int time_to_block, count = 1, n;
	time_t enter_time;
	pcap_if_t *alldevsp, *device;
	// Handle of the device that shall be sniffed
	pcap_t *handle;
	char errbuf[100], *devname, devs[100][100];
	// First get the list of available devices
	if (pcap_findalldevs(&alldevsp, errbuf))
	{
		printf("Error finding devices : %s\n", errbuf);
		exit(1);
	}
	for (device = alldevsp; device != NULL; device = device->next)
	{
		if (device->name != NULL)
		{
			strcpy(devs[count], device->name);
		}
		count++;
	}

	// printf("%s", devs[1]);
	devname = devs[1];
	// Open the device for sniffing
	// printf("Opening device %s for sniffing ... \n", devname);

	handle = pcap_open_live(devname, 65536, 1, 0, errbuf);
	// #ifdef DEBUG
	// #if (DEBUG == 1)
	// 	assert(handle != NULL);
	// #endif
	// #if (DEBUG == 0)
	// 	fprintf(stderr, "Couldn't open device %s : %s\n", devname, errbuf);
	// 	exit(1);
	// #endif
	// #endif
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s : %s\n", devname, errbuf);
		exit(1);
	}
	/* Code Listing 4.17:
	   Creating a DNS header and question to send to OpenDNS
	*/

	// maybe in pcap_loop????
	int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	/* OpenDNS is currently at 208.67.222.222 (0xd043dede) */
	address.sin_addr.s_addr = htonl(0xd043dede);
	/* DNS runs on port 53 */
	address.sin_port = htons(53);
	//
	/* Set up the DNS header */
	// dns_header_t header;
	// memset(&header, 0, sizeof(dns_header_t));
	// header.xid = htons(0x1234);	  /* Randomly chosen ID */
	// header.flags = htons(0x0100); /* Q=0, RD=1 */
	// header.qdcount = htons(1);	  /* Sending 1 question */
	//
	/* Code Listing 4.18:
	   Creating a DNS header and question to send to OpenDNS
	*/

	/* Set up the DNS question */
	dns_question_t question;
	question.dnstype = htons(1);  /* QTYPE 1=A */
	question.dnsclass = htons(1); /* QCLASS 1=IN */

	/* DNS name format requires two bytes more than the length of the
	   domain name as a string */
	question.name = calloc(strlen(HOSTNAME) + 2, sizeof(char));
	memcpy(question.name + 1, HOSTNAME, strlen(HOSTNAME));

	printf("tttttt %s", *(question.name));
	return 0;
}
/* Code Listing 4.19:
Algorithm for converting a hostname string to DNS question fields
*/

/* Leave the first byte blank for the first field length */
// memcpy(question.name + 1, hostname, strlen(hostname));
// uint8_t *prev = (uint8_t *)question.name;
// uint8_t count = 0; /* Used to count the bytes in a field */

// /* Traverse through the name, looking for the . locations */
// for (size_t i = 0; i < strlen(hostname); i++)
// {
// 	/* A . indicates the end of a field */
// 	if (hostname[i] == '.')
// 	{
// 		/* Copy the length to the byte before this field, then
// 		   update prev to the location of the . */
// 		*prev = count;
// 		prev = question.name + i + 1;
// 		count = 0;
// 	}
// 	else
// 		count++;
// }
// *prev = count;

/* Code Listing 4.22:
Checking the header and question name of the DNS response
*/

// dns_header_t *response_header = (dns_header_t *)response;
// assert((ntohs(response_header->flags) & 0xf) == 0);

// /* Get a pointer to the start of the question name, and
//    reconstruct it from the fields */
// uint8_t *start_of_name = (uint8_t *)(response + sizeof(dns_header_t));
// uint8_t total = 0;
// uint8_t *field_length = start_of_name;
// while (*field_length != 0)
// {
// 	/* Restore the dot in the name and advance to next length */
// 	total += *field_length + 1;
// 	*field_length = '.';
// 	field_length = start_of_name + total;
// }

// open the DB
// int rc = sqlite3_open(FileName, &sniffer);
// if (rc) // if error open
// {
// 	fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(sniffer));
// 	return 0;
// }
// else // succses open - start sniffing
// {
// 	printf("opened the DB\n");
// 	// recycle thred 1 - to do another func
// 	pcap_loop(handle, 10, process_packet, NULL);
// }

// // fclose(urlBlockFile);
// sqlite3_close(sniffer);
// return 0;
// }

//
// callback to create the DB
static int callback_open_db(void *not_used, int argc, char **argv, char **az_col_name)
{
	printf("I'm in callback_open_db\n");
	// for (int i = 0; i < argc; i++)
	// 	printf("%s = %s\n", az_col_name[i], argv[i] ? argv[i] : "NULL");
	return 0;
}

//
// create the DB
int create_DB()
{
	printf("I'm func create_DB \n");
	// create DB - open
	int rc = sqlite3_open(FileName, &sniffer);
	if (rc) // if error open
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(sniffer));
		return 0;
	}
	else // succses open
	{
		// try to create PACKETS table
		printf("open the DB and create tables \n");
		char sql[SQL_LEN];
		char **err = 0;
		sprintf(sql, "DROP TABLE IF EXISTS PACKETS; "
					 "CREATE TABLE PACKETS( "
					 "URL_ADRESS TEXT, "
					 "TIME_ENTER INTEGER ); ");
		rc = sqlite3_exec(sniffer, sql, callback_open_db, 0, err);
		if (rc != SQLITE_OK) // error create PACKETS table
		{
			fprintf(stdout, "--------------------\n");
			fprintf(stderr, "SQL error: %s\n", *err);
			printf("can't create PACKETS table\n");
			return 1;
		}
		else
		{
			printf("PACKETS table created\n");
		}

		// create URLS table
		sprintf(sql, "DROP TABLE IF EXISTS URLS; "
					 "CREATE TABLE URLS( "
					 "URL_TIME INT, "
					 "URL_ADRESS TEXT );");
		rc = sqlite3_exec(sniffer, sql, callback_open_db, 0, err);
		if (rc != SQLITE_OK) // error create URLS table
		{
			fprintf(stdout, "--------------------\n");
			fprintf(stderr, "SQL error: %s\n", *err);
			printf("can't create URLS table\n");
			return 0;
		}
		else
		{
			printf("PACKETS URLS created\n");
		}
		sqlite3_free(err);
		sqlite3_close(sniffer);
	}
	return 0;
}

//
// callback to insert urls to the DB
static int callback_insert(void *not_used, int argc, char **argv, char **az_col_name)
{
	printf("I'm in callback insert to db\n");
	// for (int i = 0; i < argc; i++)
	// printf("%s = %s\n", az_col_name[i], argv[i] ? argv[i] : "NULL");
	printf("\n");
	return 0;
}

//
// enter the desirability urls to block, and the amount of tume
int insert_URLS_to_block_to_DB()
{
	const char urlAdress[N];
	char sql[SQL_LEN];
	char **err1 = 0;
	int rc, time_to_block, urls = 1;
	printf("I'm func insert_URLS_to_block_to_DB \n");

	// open the DB
	rc = sqlite3_open(FileName, &sniffer);
	if (rc) // error open
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(sniffer));
		return 0;
	}
	else // succses open
	{
		printf("opened the DB");

		while (urls != 0)
		{
			printf("\nto get out of the insertion press 0, continue - press 1\n");
			scanf("%d", &urls);
			printf("\nenter the url adress you want to block:\n");
			scanf("%s", urlAdress);
			printf("enter num minutes you want to block:\n");
			scanf("%d", &time_to_block);
			sprintf(sql, "INSERT INTO URLS VALUES (%d, '%s');", time_to_block, urlAdress);
			// make func insert to URLS table DB
			rc = sqlite3_exec(sniffer, sql, callback_insert, 0, err1);
			if (rc != SQLITE_OK) // if error
			{
				printf(" error insert to url table \n");
				// fprintf(stderr, "SQL error: %s\n", *err1);
				return 1;
			}
			else
			{
				printf("successfully insert to URLS\n");
				printf("the url to block is: %s the time to block is: %d", urlAdress, time_to_block);
			}
		}
	}
	sqlite3_free(err1);
	sqlite3_close(sniffer);
	return 0;
}

// ------------------------------------------------------------------
// extract the url from the packet
u_char *extract_url_from_packet(const u_char *buffer)
{
	printf("I'm func extract_url_from_packet \n");
	// code from stackoverflow

	// int tcp_len, url_length;
	// u_char *url, *end_url, *final_url, *tcp_payload;

	// /* retireve the position of the tcp header */
	// ip_len = (ih->ver_ihl & 0xf) * 4;

	// /* retireve the position of the tcp payload */
	// tcp_len = (((u_char *)ih)[ip_len + 12] >> 4) * 4;
	// tcpPayload = (u_char *)ih + ip_len + tcp_len;

	// /* start of url - skip "GET " */
	// url = tcpPayload + 4;

	// /* length of url - lookfor space */
	// end_url = strchr((char *)url, ' ');
	// url_length = end_url - url;

	// /* copy the url to a null terminated c string */
	// final_url = (u_char *)malloc(url_length + 1);
	// strncpy((char *)final_url, (char *)url, url_length);
	// final_url[url_length] = '\0';
	// return final_url;
}

//
// check if was result from urls table
static int callback_check_result(void *p_user, int argc, char **col_data, char **col_names)
{
	printf("I'm func callback_check_result \n");

	int *flag = (int *)p_user;
	*flag = 1;
	return 0;
}

// ------------------------------------------------------------------------
// the url exist in packet table - check when to block
static int callback_check_time(void *req, int argc, char **argv, char **az_col_name)
{
	struct Data *p_req = (struct Data *)req;
	// if exist	- work on every result line
	printf("I'm callback check if your time has finish\n");
	(*p_req).flag = 1;
	// if the time has passed - let's block the url & delete from DB
	// printf("%d\n ", (*p_req).flag);
	// printf("%ld\n ", (*p_req).enter_time);
	// printf("%s\n ", (*p_req).url);
	// printf("%s\n ", argv[0]);

	long result_time = strtol(argv[0], NULL, 10);
	printf("%ld\n", result_time);

	if (((*p_req).enter_time) >= (result_time + 30) && ((*p_req).enter_time) <= (result_time + TIME))
	{
		printf("befor block\n");
		blockPacket((*p_req).url);
		printf("after block\n");
		printf("%s\n", (*p_req).url);
		// drop from DB after 1 day
	}
	else if (((*p_req).enter_time) >= (result_time + TIME))
	{
		printf("%s\n ", p_req->url);
		freePacket(p_req->url);
	}

	printf("\n");
	return 0;
}

//
// insert url & enter_time to Packet table
int insert_url_to_DB(const char url[N], long enter_time)
{
	printf("I'm func insert_url_to_DB \n");
	char sql[SQL_LEN];
	char **err1 = 0;
	int rc;
	// create DB - open
	rc = sqlite3_open(FileName, &sniffer);
	if (rc) // if error open
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(sniffer));
		return 0;
	}
	else // succses open
	{
		sprintf(sql, "INSERT INTO PACKETS VALUES ('%s',%ld);", url, enter_time);
		// make func insert to URLS table DB
		rc = sqlite3_exec(sniffer, sql, callback_insert, 0, err1);
		if (rc != SQLITE_OK) // if error
		{
			printf(" error insert to url table \n");
			fprintf(stderr, "SQL error: %s\n", *err1);
			return 1;
		}
		else
		{
			printf("successfully insert to PACKETS\n");
		}
		sqlite3_free(err1);
	}
	return 0;
}

//
// check if url exist PACKET table
int is_exist_PACKETS_table(const char url[N], long enter_time)
{
	char sql[SQL_LEN];
	char **err1 = 0;
	int rc, is_had_result = 0;
	printf("I'm func is_exist_PACKETS_table \n");

	// open the DB
	rc = sqlite3_open(FileName, &sniffer);
	if (rc) // if error open
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(sniffer));
		return 0;
	}
	else // succses open
	{
		printf("opened the DB \n");
		struct Data d1;
		d1.enter_time = enter_time;
		d1.flag = 0;
		strcpy(d1.url, url);
		sprintf(sql, "SELECT TIME_ENTER FROM PACKETS WHERE URL_ADRESS = '%s' ;", url);
		rc = sqlite3_exec(sniffer, sql, callback_check_time, &d1, err1);
		if (rc != SQLITE_OK) // if error
		{
			printf(" can't check if need to block \n");
			// fprintf(stderr, "SQL error: %s\n", *err1);
			return 1;
		}
		else
		{
			if (d1.flag == 0) // the url didn't inserted to DB - let's insert it now!
			{
				insert_url_to_DB(url, enter_time);
			}
			sqlite3_free(err1);
			sqlite3_close(sniffer);
			return 1;
		}
	}
	return 1;
}

//
// begin thread
// check if this url need to be blocked any time
int is_exist_URLS_table(const char url[N], long enter_time)
{
	char sql[SQL_LEN];
	char *err1 = 0;
	int rc, is_had_result = 0;
	printf("I'm func is_exist_URLS_table \n");

	pthread_t tid = pthread_self();
	printf("tid=%ld \n", tid);

	// open the DB
	rc = sqlite3_open(FileName, &sniffer);
	if (rc) // if error open
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(sniffer));
		return 0;
	}
	else // succses open - start sniffing
	{	 // -1
		sprintf(sql, "SELECT URL_ADRESS FROM URLS WHERE URL_ADRESS = '%s'; ", url);
		rc = sqlite3_exec(sniffer, sql, callback_check_result, &is_had_result, &err1);
		if (rc != SQLITE_OK) // if error
		{
			printf("%d\n", rc);
			printf("error selecting url from URLS \n");
			fprintf(stderr, "SQL error: %s\n", *err1);
			return 1;
		}
		else
		{
			printf("I'm need block %s , %ld , %d \n", url, enter_time, is_had_result);
			if (is_had_result == 1) // was result - we need to check if block this url
			{
				printf("this url need to be blocked in some more time\n");
				is_exist_PACKETS_table(url, enter_time);
			}
			sqlite3_free(err1);
			sqlite3_close(sniffer);
			return 0;
		}
	}
}

//
// block url
int blockPacket(const char url[N])
{
	// open the hosts file from the OS
	urlBlockFile = fopen("/etc/hosts", "a+");
	if (urlBlockFile == NULL)
	{
		printf("Unable to open file . \n");
	}
	printf("--------in the function block packet-----------\n");
	// fprintf(urlBlockFile, "\n");
	printf("the pointer to the file is: %p \n", urlBlockFile);
	printf("i wrote the url to block\n");
	int x = fprintf(urlBlockFile, "\n 127.0.0.1 %s", url);
	fclose(urlBlockFile);
	return 0;
}

//
// pcap_loop send every packet to new instance
// void (*pcap_handler)(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
// {
// 	printf("I'm func process_packet \n");
// 	pthread_t thr;
// 	// int size = header->len;
// 	// // Get the IP Header part of this packet , excluding the ethernet header
// 	// struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
// 	// // u_char *url = extract_url_from_packet(buffer);
// 	// struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
// 	// int tcp_len, url_length;
// 	// u_char *url, *end_url, *final_url, *tcp_payload;

// 	// /* retireve the position of the tcp header */
// 	// ip_len = (ih->ver_ihl & 0xf) * 4;

// 	// /* retireve the position of the tcp payload */
// 	// tcp_len = (((u_char *)ih)[ip_len + 12] >> 4) * 4;
// 	// tcp_payload = (u_char *)ih + ip_len + tcp_len;

// 	// /* start of url - skip "GET " */
// 	// url = tcp_payload + 4;

// 	// /* length of url - lookfor space */
// 	// end_url = strchr((char *)url, ' ');
// 	// url_length = end_url - url;

// 	// /* copy the url to a null terminated c string */
// 	// final_url = (u_char *)malloc(url_length + 1);
// 	// strncpy((char *)final_url, (char *)url, url_length);
// 	// final_url[url_length] = '\0';

// 	// printf("\n\n%d\n\n", final_url);
// 	const char url[N] = "facebook.com";
// 	struct timeval enter = ih->ts;
// 	long enter_time = enter.tv_sec;
// 	struct Data *dt; // = (struct Data*) malloc(sizeof(struct Data));
// 	dt->enter_time = enter_time;
// 	dt->url = url;
// 	if (pthread_create(&thr, NULL, is_exist_URLS_table, dt) != 0)
// 	{
// 		printf("ERROR! cannot create thread.");
// 		exit(1);
// 	}
// 	pthread_join(thr, NULL);
// 	free(dt);
// 	// int result_exist = is_exist_URLS_table(url, enter_time);
// 	return;
// }

//
// free url
int freePacket(const char url[N])
{
	// 	// open the hosts file from the OS
	// 	urlBlockFile = fopen("/etc/hosts", "a+");
	// 	if (urlBlockFile == NULL)
	// 	{
	// 		printf("Unable to open file . \n");
	// 	}
	// 	printf("--------in the function free packet-----------\n");
	// 	printf("the pointer to the file is: %p \n", urlBlockFile);
	// 	printf("i free the url\n");
	// 	// int x = fprintf(urlBlockFile, "\n 127.0.0.1 %s" ,url);

	// 	fclose(urlBlockFile);
	return 0;
}

//
// callback to insert urls to the DB
static int callback_delete(void *not_used, int argc, char **argv, char **az_col_name)
{
	printf("I'm in callback delete from db\n");
	for (int i = 0; i < argc; i++)
		printf("%s = %s\n", az_col_name[i], argv[i] ? argv[i] : "NULL");
	printf("\n");
	return 0;
}

//
// insert url & enter_time to Packet table
int delete_url_from_DB(const char url[N])
{
	printf("I'm func delete_url_from_DB \n");

	char sql[SQL_LEN];
	char **err1 = 0;
	int rc;
	// create DB - open
	rc = sqlite3_open(FileName, &sniffer);
	if (rc) // if error open
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(sniffer));
		return 0;
	}
	else // succses open
	{
		sprintf(sql, "DELETE FROM PACKETS WHERE URL_ADRESS = '%s' ;", url);
		rc = sqlite3_exec(sniffer, sql, callback_delete, 0, err1);
		if (rc != SQLITE_OK) // if error
		{
			printf(" error delete to url table \n");
			// fprintf(stderr, "SQL error: %s\n", *err1);
			return 1;
		}
		else
		{
			printf("successfully delete from PACKETS\n");
		}
		sqlite3_free(err1);
	}
	return 0;
}

//??????????????????????????????????????????????
//
// check if this url need to be blocked any time
// int get_max_time_to_url(const char url[N])
// {
// 	char sql[SQL_LEN];
// 	char *err1 = 0;
// 	int rc, is_had_result = 0;
// 	printf("I'm func get_max_time_to_url \n");
// 	// open the DB
// 	rc = sqlite3_open(FileName, &sniffer);
// 	if (rc) // if error open
// 	{
// 		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(sniffer));
// 		return 0;
// 	}
// 	else // succses open - start sniffing
// 	{	 // -1
// 		sprintf(sql, "SELECT URL_TIME FROM URLS WHERE URL_ADRESS = '%s'; ", url);
// 		rc = sqlite3_exec(sniffer, sql, /*callback_check_result, &is_had_result*/, &err1);
// 		if (rc != SQLITE_OK) // if error
// 		{
// 			printf("%d\n", rc);
// 			printf("error selecting url from URLS \n");
// 			fprintf(stderr, "SQL error: %s\n", *err1);
// 			return 1;
// 		}
// 		else
// 		{
// 			printf("I'm need block %s , %ld , %d \n", url, enter_time, is_had_result);
// 			if (is_had_result == 1) // was result - we need to check if block this url
// 			{
// 				printf("this url need to be blocked in some more time\n");
// 				is_exist_PACKETS_table(url, enter_time);
// 			}
// 			sqlite3_free(err1);
// 			sqlite3_close(sniffer);
// 			return 0;
// 		}
// 	}
// }