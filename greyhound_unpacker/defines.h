#define _CRT_SECURE_NO_DEPRECATE 1

#define _WIN32_WINNT	0x0501
//Comment to remove debug message
#define DEBUG 1

#ifndef DEF_MAXPATH
	#define DEF_MAXPATH		5000
#endif

#pragma once
enum supprted_unpackers
{
	PROD_REFLEXIVE,
	PROD_GAMEHOUSE,
	PROD_ALAWAR,
	PROD_PLAYRIX,
	PROD_POPCAP
};

enum mapping_mode
{
	MAP_READ,
	MAP_READWRITE
};