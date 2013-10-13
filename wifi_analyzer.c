#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define STR_MAC_ADDR_LEN 20
#define MAX_FILENAME 128

#define IEEE80211_ACK 0x1d
#define IEEE80211_DATA 0x20
#define IEEE80211_RTS 0x1b
#define IEEE80211_CTS 0x1c

#define PLCP_TIME 29

#define US_TO_SEC(_US) (((long double)(_US)) / (1000000))
#define PERCENT(_a, _b) ((100.0 * (float)(_a)) / (_b))

typedef char macaddr[STR_MAC_ADDR_LEN];
#define BROADCAST_MAC "FF:FF:FF:FF:FF:FF"
#define STRING_EQUAL(_str1, _str2, _no) (strncasecmp((_str1), (_str2), (_no)) == 0)

#define IS_OUTLIER(packet_gap) (((packet_gap) > 100) || ((packet_gap) < 0))

struct packet {
	int type, rate, frmlen;
	long timestamp;
	macaddr dst, src, bssid;
	u_int8_t is_retry :1;
};

struct stats {
	unsigned long total_airtime, total_airtime_occupied,
		total_interpacket_gap, total_airtime_in_retries,
		total_data_pkts, total_retry_pkts, total_pkts;
	double average_data_rate;
};

int proto;
macaddr bssid = {0};
void parse_line(char *line, struct packet *packet)
{
	int i=0, pass=0, read_val = 1;
	char *cur, *ptr;

	for(cur = line; (cur - line) < 127;) {
		if(*cur == ',') {
			cur++;
			read_val = 1;
			if(*cur == ',')
				read_val = 0;
		}
		if(*cur == '\n')
			break;
		if(read_val) {
			switch(pass) {
			case 0:
				/* Type */
				packet->type = (int)strtol(cur, NULL, 0);
				break;
			case 2:
				/* Timestamp */
				packet->timestamp = (long)strtoll(cur, NULL, 0);
				break;
			case 4:
				if(proto == 'p')
					packet->rate = (int)strtol(cur, NULL, 0);
				else
					packet->rate = ((float)strtof(cur, NULL) * 2.0);
				break;
			case 5:
				/* frmlen */
				packet->frmlen = (int)strtol(cur, NULL, 0);
				break;
			case 6:
				/* dst */
				strncpy(packet->dst, cur, 17);
				packet->dst[17] = 0;
				break;
			case 7:
				/* bssid */
				strncpy(packet->bssid, cur, 17);
				packet->bssid[17] = 0;
				break;
			case 8:
				/* src */
				strncpy(packet->src, cur, 17);
				packet->src[17] = 0;
				break;
			case 9:
				/* receiver address in case of RTS/CTS/ACK */
				strncpy(packet->dst, cur, 17);
				packet->dst[17] = 0;
				break;
			case 10:
				/* retry bit*/
				packet->is_retry = (u_int8_t)strtol(cur, NULL, 0);
				break;
			default: break;
			}
			read_val = 0;
		}
		pass++;
		ptr = strchr(cur, ',');
		if(ptr)
			cur = ptr;
		else
			break;
	}
}

inline long time_for(struct packet *packet)
{
	if(packet->rate == 0)
		return 0;

	return (long)(((packet->frmlen * 8) * 1024.0 * 1024.0)/
			   (((double)packet->rate/2) * 1000.0 * 1000.0));
}

inline int is_ackable(int type)
{
	switch(type) {
	case IEEE80211_ACK:
	case IEEE80211_CTS:
	case IEEE80211_RTS:
		return 0;
	}
	return 1;
}

void dump_packet(struct packet *packet)
{
}

inline unsigned long
calculate_total_airtime(struct packet *first, struct packet *last)
{
	printf("%lu %lu\n", last->timestamp, first->timestamp);
	return (last->timestamp - (first->timestamp - time_for(first)));
}



struct stats
calculate_stats(char *input_file, int (*filter_pkt)(struct packet *))
{
	FILE *fp = NULL;
	char line[128];
	macaddr oldmac={0};
	struct packet old_packet, first, last, packet;
	int old_packet_acked;
	struct stats stats;
	unsigned long timestamp, timestamp_old = 0,
		total_airtime = 0, total_airtime_occupied = 0,
		total_interpacket_gap = 0,
		total_airtime_in_retries = 0,
		total_data_pkts = 0, total_retry_pkts = 0,
		total_pkts = 0;

	long ack_count = 0;
	long double sifs = 0.0;
	unsigned int sum_rates = 0;

	fp = fopen(input_file, "r+");
	if(!fp) {
		printf("Couldn't open input file : %s\n", input_file);
		exit(EXIT_FAILURE);
	}

	memset(&stats, 0, sizeof(struct stats));
	memset(&old_packet, 0, sizeof(struct packet));
	memset(&first, 0, sizeof(struct packet));
	memset(&last, 0, sizeof(struct packet));
	memset(&packet, 0, sizeof(struct packet));
	while(!feof(fp)) {
		fgets(line, 128, fp);	
		memset(&packet, 0, sizeof(struct packet));

		parse_line(line, &packet);
		if(filter_pkt && !(*filter_pkt)(&packet)) {
			memset(&packet, 0, sizeof(struct packet));
			continue;
		}

		if(total_pkts == 0) {
			/* Saving first packet */
			first = packet;
		} else {
			timestamp = packet.timestamp - time_for(&packet);
			timestamp_old = old_packet.timestamp;
		}

		total_airtime_occupied += time_for(&packet);
		old_packet = packet;

		if(packet.is_retry) {
			total_retry_pkts++;
			total_airtime_in_retries += time_for(&packet);
		}

		if(((packet.type & 0xf0) >> 4) == 0x2) {
			sum_rates += packet.rate;
			total_data_pkts++;
		}

		total_pkts++;
		last = packet;
	}

	total_airtime = calculate_total_airtime(&first, &last);
	total_interpacket_gap = total_airtime - total_airtime_occupied;

	stats.total_airtime = total_airtime;
	stats.total_airtime_occupied = total_airtime_occupied;
	stats.total_interpacket_gap = total_interpacket_gap;
	stats.total_airtime_in_retries = total_airtime_in_retries;
	stats.total_data_pkts = total_data_pkts;
	stats.total_retry_pkts = total_retry_pkts;
	stats.total_pkts = total_pkts;
	stats.average_data_rate = (total_data_pkts == 0) ? 0 :
		(sum_rates/(2 * total_data_pkts));
		

	return stats;
}

int is_valid(char *str)
{
	if(str[0] == 0)
		return 0;
	return 1;
}

void usage(void)
{
	printf("Usage: -i <input_file> -p <protocol p:prism r:radiotap>\n");
}

inline int filter_bssid(struct packet *packet)
{
	if(strcasecmp(packet->bssid, bssid) == 0)
		return 1;
	return 0;
}

void analyze(struct stats *total, struct stats *ap)
{
	/* printf("total_airtime = %lu\n", total_stats->total_airtime); */
	/* printf("total_airtime_occupied = %lu\n", total_stats->total_airtime_occupied); */
	/* printf("total_interpacket_gap = %lu\n", total_stats->total_interpacket_gap); */
	/* printf("total_airtime_in_retries = %lu\n", total_stats->total_airtime_in_retries); */
	/* printf("total_data_pkts = %lu\n", total_stats->total_data_pkts); */
	/* printf("total_retry_pkts = %lu\n", total_stats->total_retry_pkts); */
	/* printf("total_pkts = %lu\n", total_stats->total_pkts); */
	/* printf("average_data_rate = %lf\n", total_stats->average_data_rate); */

	/* printf("total_airtime = %lu\n", ap_stats->total_airtime); */
	/* printf("total_airtime_occupied = %lu\n", ap_stats->total_airtime_occupied); */
	/* printf("total_interpacket_gap = %lu\n", ap_stats->total_interpacket_gap); */
	/* printf("total_airtime_in_retries = %lu\n", ap_stats->total_airtime_in_retries); */
	/* printf("total_data_pkts = %lu\n", ap_stats->total_data_pkts); */
	/* printf("total_retry_pkts = %lu\n", ap_stats->total_retry_pkts); */
	/* printf("total_pkts = %lu\n", ap_stats->total_pkts); */
	/* printf("average_data_rate = %lf\n", ap_stats->average_data_rate); */

	printf("Results:\n");
	printf("---------------\n");

	printf("Total runtime of the trace is %.2Lfs, out of which %.2Lfs(%.1f%%)\n"
	       "was occupied by WiFi packets in the trace.\n",
	       US_TO_SEC(total->total_airtime),
	       US_TO_SEC(total->total_airtime_occupied),
	       PERCENT(total->total_airtime_occupied, total->total_airtime));
	printf("Your AP with bssid %s occupies %.2Lfs which is %.1f%% of total\n"
	       "airtime and %.1f%% of the total airtime of WiFi packets in this trace.\n",
	       bssid, US_TO_SEC(ap->total_airtime_occupied),
	       PERCENT(ap->total_airtime_occupied, total->total_airtime),
	       PERCENT(ap->total_airtime_occupied, total->total_airtime_occupied));

	printf("\nIn the trace about %.1f%% packets are retried frames.\n"
	       "out of which, your AP contributes to about %.1f%% total retries.\n",
	       PERCENT(total->total_retry_pkts, total->total_pkts),
	       PERCENT(ap->total_retry_pkts, total->total_retry_pkts));

	printf("Airtime wasted in retries is %.2Lfs which is %.1f%% of total WiFi "
	       "airtime.", US_TO_SEC(total->total_airtime_in_retries),
	       PERCENT(total->total_airtime_in_retries, total->total_airtime_occupied));
	printf("\nYour AP wastes %.1f%% of its total airtime in retries.\n",
	       PERCENT(ap->total_airtime_in_retries, ap->total_airtime_occupied));

	printf("\nAverage rate of data packets in the trace is %.1fmbps, where as \n"
	       "that of your AP is %.1fmbps.\n", total->average_data_rate,
	       ap->average_data_rate);
}

int main(int argc, char *argv[])
{
	char c;
	char input_file[MAX_FILENAME] = {0};
	struct stats r_total = {0}, r_ap = {0};

	proto = 0;
	while((c = getopt(argc, argv, "i:p:b:")) != -1) {
		switch(c) {
		case 'i':
			strcpy(input_file, optarg);
			break;
		case 'p':
			proto = (int)optarg;
			break;
		case 'b':
			strcpy(bssid, (char *)optarg);
			break;
		default:
			usage();
			return 0;
		}
	}
	if((!is_valid(input_file)) || (proto == 0)) {
		usage();
		return 0;
	}
	r_total = calculate_stats(input_file, NULL);
	r_ap = calculate_stats(input_file, filter_bssid);
	analyze(&r_total, &r_ap);

	return 0;
}
