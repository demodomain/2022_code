#include <iostream>
#include <iomanip>
using namespace std;

class Pcap_header {
public:
	uint32_t magic = 0xd4c3b2a1; //小端模式解决高低八位问题
	uint16_t major = 0x0200;
	uint16_t minor = 0x0400;
	uint32_t this_zone = 0;
	uint32_t sig_figs = 0;
	uint32_t snap_len = 65535;
	uint32_t link_type = 1;
};
class Packet_header
{
public:
	uint32_t timestamp = 0x61507a7d;
	uint32_t time_out_stamp = 0x014e78;
	uint32_t caplen = 66;
	uint32_t len = 66;
};

//以太网帧 目标地址6块，源地址6块，类型2块
class Ethernet
{
public:
	char destination[20] = "ff:ff:ff:ff:ff:ff";
	char source[20] = "54:89:98:be:27:ca";
	uint8_t type[2] = { 0x08, 0x00 };
	uint8_t address[6];
};
Ethernet get_ethernet_address(Ethernet el) {
	cout << "请输入目的mac地址(默认值为ff:ff:ff:ff:ff:ff):";
	if (getchar() == '\n')
	{
		cout << "输入结束";

	}
	else
	{
		cin >> el.destination;
	}
	cout << "请输入源mac地址(默认值为54:89:98:be:27:ca):";
	if (getchar() == '\n')
	{
		cout << "输入结束";

	}
	else
	{
		cin >> el.source;
	}
	return el;
}

class IP
{
public:
	uint8_t version_header = 0x45;
	uint8_t DSCP = 0xc0;
	uint16_t total_length = 52;
	uint16_t identification = 0x0024;
	uint16_t flag_offset = 0x0000;
	uint8_t time_to_live = 0x01;
	uint8_t protocol = 17;
	uint16_t header_checksum = 0xa9d0;
	char source[20] = "15.0.0.6";
	char destination[20] = "255.255.255.255";
	uint8_t address[4];
};
IP get_ip_address(IP ip) {
	cout << "请输入目标主机IP地址(默认值为255.255.255.255):";
	if (getchar() == '\n')
	{
		cout << "输入结束";

	}
	else
	{
		cin >> ip.destination;
	}
	cout << "请输入源主机IP地址(默认值为15.0.0.6):";
	if (getchar() == '\n')
	{
		cout << "输入结束";

	}
	else
	{
		cin >> ip.source;
	}
	return ip;
}

class UDP {
public:
	uint16_t source_port = 520;
	uint16_t destination_port = 520;
	uint16_t length = 32;
	uint16_t checksum = 0x29ec;
};

class RIP
{
public:
	uint8_t command = 2;
	uint8_t version = 1;
	uint8_t must_be_zero0[2] = { 0x00, 0x00 };
	uint16_t AFI = 2;
	uint8_t route_tag[2] = { 0x00, 0x00 };
	char ip_address[20] = "192.168.0.0";
	uint8_t address[4];
	uint8_t must_be_zero1[4] = { 0x00, 0x00, 0x00, 0x00 };
	uint8_t must_be_zero2[4] = { 0x00, 0x00, 0x00, 0x00 };
	uint32_t metric = 1;
};
RIP get_route_address(RIP rip) {
	cout << "请输入下一跳路由地址(默认路由为192.168.0.0):";
	//cin >> rip.ip_address;
	if (getchar() == '\n')
	{
		cout << "输入结束";

	}
	else
	{
		cin >> rip.ip_address;
	}
	return rip;
}

unsigned short swapShort16(unsigned short shortValue) {
	return ((shortValue & 0x00FF) << 8) | ((shortValue & 0xFF00) >> 8);
}

unsigned int swapInt32(unsigned int intValue) {
	int temp = 0;
	temp = ((intValue & 0x000000FF) << 24) + ((intValue & 0x0000FF00) << 8) + ((intValue & 0x00FF000) >> 8) + ((intValue & 0xFF000000) >> 24);
	return temp;
}


//16进制中2个0就是一字节8位
int main()
{
	FILE* fp;
	errno_t err;
	//err = fopen_s(&fp,"final.bin", "wb");
	err = fopen_s(&fp, "final.pcap", "wb");
	if (fp == NULL)
	{
		printf("can not open the file.\n");
		return -1;
	}
	//包头信息构造
	Pcap_header pcap;
	fwrite(&pcap.magic, 4, 1, fp);
	pcap.major = swapShort16(pcap.major);
	pcap.minor = swapShort16(pcap.minor);
	pcap.this_zone = swapInt32(pcap.this_zone);
	pcap.sig_figs = swapInt32(pcap.sig_figs);
	pcap.snap_len = swapInt32(pcap.snap_len);
	pcap.link_type = swapInt32(pcap.link_type);

	fwrite(&pcap.major, 2, 1, fp);
	fwrite(&pcap.minor, 2, 1, fp);
	fwrite(&pcap.this_zone, 4, 1, fp);
	fwrite(&pcap.sig_figs, 4, 1, fp);
	fwrite(&pcap.snap_len, 4, 1, fp);
	fwrite(&pcap.link_type, 4, 1, fp);

	//时间戳构造
	Packet_header pack;
	pack.timestamp = swapInt32(pack.timestamp);
	pack.time_out_stamp = swapInt32(pack.time_out_stamp);
	pack.caplen = swapInt32(pack.caplen);
	pack.len = swapInt32(pack.len);

	fwrite(&pack.timestamp, 4, 1, fp);
	fwrite(&pack.time_out_stamp, 4, 1, fp);
	fwrite(&pack.caplen, 4, 1, fp);
	fwrite(&pack.len, 4, 1, fp);

	//以太网帧构造
	Ethernet el;
	el = get_ethernet_address(el);
	//解决小端问题
	sscanf(el.destination, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &el.address[0], &el.address[1], &el.address[2], &el.address[3], &el.address[4], &el.address[5]);
	fwrite(&el.address, 6, 1, fp);
	sscanf(el.source, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &el.address[0], &el.address[1], &el.address[2], &el.address[3], &el.address[4], &el.address[5]);
	fwrite(&el.address, 6, 1, fp);
	fwrite(&el.type, 2, 1, fp);

	//ip构造
	IP ip;
	ip = get_ip_address(ip);
	ip.total_length = swapShort16(ip.total_length);
	ip.identification = swapShort16(ip.identification);
	ip.flag_offset = swapShort16(ip.flag_offset);
	ip.header_checksum = swapShort16(ip.header_checksum);

	fwrite(&ip.version_header, 1, 1, fp);
	fwrite(&ip.DSCP, 1, 1, fp);
	fwrite(&ip.total_length, 2, 1, fp);
	fwrite(&ip.identification, 2, 1, fp);
	fwrite(&ip.flag_offset, 2, 1, fp);
	fwrite(&ip.time_to_live, 1, 1, fp);
	fwrite(&ip.protocol, 1, 1, fp);
	fwrite(&ip.header_checksum, 2, 1, fp);
	sscanf(ip.source, "%d.%d.%d.%d", &ip.address[0], &ip.address[1], &ip.address[2], &ip.address[3]);
	fwrite(&ip.address, 4, 1, fp);
	sscanf(ip.destination, "%d.%d.%d.%d", &ip.address[0], &ip.address[1], &ip.address[2], &ip.address[3]);
	fwrite(&ip.address, 4, 1, fp);

	//udp构造
	UDP udp;
	udp.source_port = swapShort16(udp.source_port);
	udp.destination_port = swapShort16(udp.destination_port);
	udp.length = swapShort16(udp.length);
	udp.checksum = swapShort16(udp.checksum);

	fwrite(&udp.source_port, 2, 1, fp);
	fwrite(&udp.destination_port, 2, 1, fp);
	fwrite(&udp.length, 2, 1, fp);
	fwrite(&udp.checksum, 2, 1, fp);

	//rip构造
	RIP rip;
	rip.AFI = swapShort16(rip.AFI);
	rip.metric = swapInt32(rip.metric);

	fwrite(&rip.command, 1, 1, fp);
	fwrite(&rip.version, 1, 1, fp);
	fwrite(&rip.must_be_zero0, 2, 1, fp);
	fwrite(&rip.AFI, 2, 1, fp);
	fwrite(&rip.route_tag, 2, 1, fp);
	rip = get_route_address(rip);
	sscanf(rip.ip_address, "%d.%d.%d.%d", &rip.address[0], &rip.address[1], &rip.address[2], &rip.address[3]);
	fwrite(&rip.address, 4, 1, fp);
	fwrite(&rip.must_be_zero1, 4, 1, fp);
	fwrite(&rip.must_be_zero2, 4, 1, fp);
	fwrite(&rip.metric, 4, 1, fp);

	fclose(fp);
}
