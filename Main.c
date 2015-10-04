#define _CRT_SECURE_NO_DEPRECATE

#include <windows.h>
#include <stdio.h>
#include <signal.h>

// These definitions are required when using the older runtime library
long _ftol2(double x) {return 0;}
long _ftol2_sse(double x) { return _ftol2(x); }
void __fastcall __security_check_cookie(uintptr_t _StackCookie) {}
uintptr_t __security_cookie;

typedef struct
{
	unsigned char Magic[6];
	unsigned char Address[16][6];
	unsigned char Password[6];
} MAGIC_PACKET;

int main(int argc,const char** argv)
{
	WSADATA wsa;
	MAGIC_PACKET packet;
	SOCKET sock;
	BOOL option;
	struct sockaddr_in address;

	/* Skip first arg (current execution path) */
	argc--;
	argv++;

	/* Set magic number */
	packet.Magic[0] = packet.Magic[1] = packet.Magic[2] = packet.Magic[3] = packet.Magic[4] = packet.Magic[5] = 0xFF;

	/* Reset physical address */
	ZeroMemory(packet.Address[0],sizeof(packet.Address[0]));

	/* Check if mac address specified */
	if(!argc)
	{
		printf("Physical address: ");

		if(scanf("%X%*[:-]%X%*[:-]%X%*[:-]%X%*[:-]%X%*[:-]%X",&packet.Address[0][0],&packet.Address[0][1],&packet.Address[0][2],&packet.Address[0][3],&packet.Address[0][4],&packet.Address[0][5]) != 6)
		{
			printf("Error in physical address syntax. Addresses must be in the form XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX.\r\n");
			return 1;
		}
	}
	else if(!strcmp("/?",argv[0]))
	{
		printf("\r\nUSAGE:\r\n    wake [OPTION|PHYSICAL_ADDRESS]\r\n\r\nOPTIONS:\r\n   /?           Displays this help\r\n\r\nTo get a list of physical addresses for a computer use the \"getmac\" command.\r\n\r\nCopyright 2007 Marko Mihovilic. All Rights Reserved.\r\n");
		return 1;
	}
	else if(argv[0][0] == '/')
	{
		printf("Unknown option \"%s\". Use \"/?\" for help.\r\n",argv[0]);
		return 1;
	}
	else
	{
		if(sscanf(argv[0],"%X%*[:-]%X%*[:-]%X%*[:-]%X%*[:-]%X%*[:-]%X",&packet.Address[0][0],&packet.Address[0][1],&packet.Address[0][2],&packet.Address[0][3],&packet.Address[0][4],&packet.Address[0][5]) != 6)
		{
			printf("Error in physical address syntax. Addresses must be in the form XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX.\r\n");
			return 1;
		}
	}

	/* Repeat physical address 15 times */
	CopyMemory(packet.Address[1],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[2],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[3],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[4],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[5],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[6],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[7],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[8],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[9],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[10],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[11],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[12],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[13],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[14],packet.Address[0],sizeof(packet.Address[0]));
	CopyMemory(packet.Address[15],packet.Address[0],sizeof(packet.Address[0]));

	/* TODO Set password */
	ZeroMemory(packet.Password,sizeof(packet.Password));

	/* Initialize winsock */
	if(WSAStartup(MAKEWORD(2,0),&wsa))
	{
		printf("Error initializing Winsock version 2.0. Code %d.\r\n",WSAGetLastError());
        return 1;
	}

	/* Create udp socket */
	sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if(sock == INVALID_SOCKET)
	{
		printf("Error creating UDP socket. Code %d.\r\n",WSAGetLastError());
		WSACleanup();
		return 1;
	}

	/* Set socket as broadcast */
	option = TRUE;
	if(setsockopt(sock,SOL_SOCKET,SO_BROADCAST,(LPSTR)&option,sizeof(BOOL)) == SOCKET_ERROR)
	{
		printf("Error setting socket option to broadcast. Code %d.\r\n",WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	/* Set the address structure */
	address.sin_family = AF_INET;
	address.sin_port = htons(9);	/* Default port */
	address.sin_addr.S_un.S_addr = INADDR_BROADCAST;

	ZeroMemory(address.sin_zero,sizeof(address.sin_zero));
	
#ifdef _DEBUG
	printf("Network address is: %s\r\n",inet_ntoa(address.sin_addr));
#endif

	/* Broadcast the packet */
	if(sendto(sock,(LPCSTR)&packet,sizeof(packet),0,(struct sockaddr*)&address,sizeof(address)) == SOCKET_ERROR)
	{
		printf("Error sending magic packet. Code %d.\r\n",WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	/* Clean-up */
	closesocket(sock);

	WSACleanup();

	printf("The packet with address %02X-%02X-%02X-%02X-%02X-%02X was successfuly sent.\r\n",packet.Address[0][0],packet.Address[0][1],packet.Address[0][2],packet.Address[0][3],packet.Address[0][4],packet.Address[0][5]);

	return 0;
}