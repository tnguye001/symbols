#include "Windows.h"
#include "winnt.h"
#include <stdio.h>
#include <json/writer.h>
#include <fstream>

#define MAX_MEM_REGIONS 20

#define CM_RESOURCE_MEMORY_LARGE                            0x0E00
#define CM_RESOURCE_MEMORY_LARGE_40                         0x0200
#define CM_RESOURCE_MEMORY_LARGE_48                         0x0400
#define CM_RESOURCE_MEMORY_LARGE_64                         0x0800

#define CmResourceTypeNull 0 // ResType_All or ResType_None (0x0000)
#define CmResourceTypePort 1 // ResType_IO (0x0002)
#define CmResourceTypeInterrupt 2 // ResType_IRQ (0x0004)
#define CmResourceTypeMemory 3 // ResType_Mem (0x0001)
#define CmResourceTypeDma 4 // ResType_DMA (0x0003)
#define CmResourceTypeDeviceSpecific 5 // ResType_ClassSpecific (0xFFFF)
#define CmResourceTypeBusNumber 6 // ResType_BusNumber (0x0006)
#define CmResourceTypeMemoryLarge 7 // ResType_MemLarge (0x0007)
#define CmResourceTypeNonArbitrated 128 // Not arbitrated if 0x80 bit set
#define CmResourceTypeConfigData 128 // ResType_Reserved (0x8000)
#define CmResourceTypeDevicePrivate 129 // ResType_DevicePrivate (0x8001)
#define CmResourceTypePcCardConfig 130 // ResType_PcCardConfig (0x8002)
#define CmResourceTypeMfCardConfig 131 // ResType_MfCardConfig (0x8003)
#define CmResourceTypeConnection 132 // ResType_Connection (0x8004)


typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;

#pragma pack(push,4)
typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR {
	UCHAR Type;
	UCHAR ShareDisposition;
	USHORT Flags;
	union {
		struct {
			PHYSICAL_ADDRESS Start;
			ULONG Length;
		} Generic;

		struct {
			PHYSICAL_ADDRESS Start;
			ULONG Length;
		} Port;

		struct {
#if defined(NT_PROCESSOR_GROUPS)
			USHORT Level;
			USHORT Group;
#else
			ULONG Level;
#endif
			ULONG Vector;
			KAFFINITY Affinity;
		} Interrupt;

		struct {
			union {
				struct {
#if defined(NT_PROCESSOR_GROUPS)
					USHORT Group;
#else
					USHORT Reserved;
#endif
					USHORT MessageCount;
					ULONG Vector;
					KAFFINITY Affinity;
				} Raw;

				struct {
#if defined(NT_PROCESSOR_GROUPS)
					USHORT Level;
					USHORT Group;
#else
					ULONG Level;
#endif
					ULONG Vector;
					KAFFINITY Affinity;
				} Translated;
			} DUMMYUNIONNAME;
		} MessageInterrupt;

		struct {
			PHYSICAL_ADDRESS Start;
			ULONG Length;
		} Memory;

		struct {
			ULONG Channel;
			ULONG Port;
			ULONG Reserved1;
		} Dma;

		struct {
			ULONG Channel;
			ULONG RequestLine;
			UCHAR TransferWidth;
			UCHAR Reserved1;
			UCHAR Reserved2;
			UCHAR Reserved3;
		} DmaV3;

		struct {
			ULONG Data[3];
		} DevicePrivate;

		struct {
			ULONG Start;
			ULONG Length;
			ULONG Reserved;
		} BusNumber;

		struct {
			ULONG DataSize;
			ULONG Reserved1;
			ULONG Reserved2;
		} DeviceSpecificData;

		struct {
			PHYSICAL_ADDRESS Start;
			ULONG Length40;
		} Memory40;

		struct {
			PHYSICAL_ADDRESS Start;
			ULONG Length48;
		} Memory48;

		struct {
			PHYSICAL_ADDRESS Start;
			ULONG Length64;
		} Memory64;

		struct {
			UCHAR Class;
			UCHAR Type;
			UCHAR Reserved1;
			UCHAR Reserved2;
			ULONG IdLowPart;
			ULONG IdHighPart;
		} Connection;

	} u;
} CM_PARTIAL_RESOURCE_DESCRIPTOR, * PCM_PARTIAL_RESOURCE_DESCRIPTOR;
#pragma pack(pop,4)

typedef enum _INTERFACE_TYPE {
	InterfaceTypeUndefined,
	Internal,
	Isa,
	Eisa,
	MicroChannel,
	TurboChannel,
	PCIBus,
	VMEBus,
	NuBus,
	PCMCIABus,
	CBus,
	MPIBus,
	MPSABus,
	ProcessorInternal,
	InternalPowerBus,
	PNPISABus,
	PNPBus,
	Vmcs,
	ACPIBus,
	MaximumInterfaceType
} INTERFACE_TYPE, * PINTERFACE_TYPE;

typedef struct _CM_PARTIAL_RESOURCE_LIST {
	USHORT                         Version;
	USHORT                         Revision;
	ULONG                          Count;
	CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[1];
} CM_PARTIAL_RESOURCE_LIST, * PCM_PARTIAL_RESOURCE_LIST;

typedef struct _CM_FULL_RESOURCE_DESCRIPTOR {
	INTERFACE_TYPE           InterfaceType;
	ULONG                    BusNumber;
	CM_PARTIAL_RESOURCE_LIST PartialResourceList;
} *PCM_FULL_RESOURCE_DESCRIPTOR, CM_FULL_RESOURCE_DESCRIPTOR;

typedef struct _CM_RESOURCE_LIST {
	ULONG                       Count;
	CM_FULL_RESOURCE_DESCRIPTOR List[1];
} *PCM_RESOURCE_LIST, CM_RESOURCE_LIST;

struct memory_region {
	ULONG64 size;
	ULONG64 address;
};

DWORD parse_memory_map(struct memory_region* regions) {
	HKEY hKey = NULL;
	LPCWSTR pszSubKey = L"Hardware\\ResourceMap\\System Resources\\Physical Memory";
	LPCWSTR pszValueName = L".Translated";
	LPBYTE lpData = NULL;
	DWORD dwLength = 0, count = 0, type = 0;;

	if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, pszSubKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		printf("Could not get registry key\n");
		return 0;
	}

	if (!RegQueryValueEx(hKey, pszValueName, 0, &type, NULL, &dwLength) == ERROR_SUCCESS)
	{
		printf("Could not query hardware key\n");
		return 0;
	}

	lpData = (LPBYTE)malloc(dwLength);
	if (lpData == nullptr) {
		printf("Allocation error\n");
		return 0;
	}
	RegQueryValueEx(hKey, pszValueName, 0, &type, lpData, &dwLength);

	CM_RESOURCE_LIST* resource_list = (CM_RESOURCE_LIST*)lpData;

	for (unsigned int i = 0; i < resource_list->Count; i++) {
		for (unsigned int j = 0; j < resource_list->List[0].PartialResourceList.Count; j++) {
			if (resource_list->List[i].PartialResourceList.PartialDescriptors[j].Type == CmResourceTypeMemoryLarge ||
				resource_list->List[i].PartialResourceList.PartialDescriptors[j].Type == CmResourceTypeMemory) {

				regions->address = resource_list->List[i].PartialResourceList.PartialDescriptors[j].u.Memory.Start.QuadPart;
				regions->size = resource_list->List[i].PartialResourceList.PartialDescriptors[j].u.Memory.Length;

				if (resource_list->List[i].PartialResourceList.PartialDescriptors[j].Type == CmResourceTypeMemoryLarge) {
					switch (resource_list->List[i].PartialResourceList.PartialDescriptors[j].Flags)
					{
					case CM_RESOURCE_MEMORY_LARGE_40:
						regions->size <<= 8;
						break;
					case CM_RESOURCE_MEMORY_LARGE_48:
						regions->size <<= 16;
						break;
					case CM_RESOURCE_MEMORY_LARGE_64:
						regions->size <<= 32;
						break;
					default:
						break;
					}
				}
				regions++;
				count++;
			}
		}
	}
	if (!RegCloseKey(hKey) == ERROR_SUCCESS)
	{
		printf("Could not close key\n");
		return 0;
	}
	free(lpData);
	return count;
}

int main()
{

	DWORD count;

	// Parse registry for physical memory regions
	struct memory_region* regions = (struct memory_region*)malloc(sizeof(struct memory_region) * MAX_MEM_REGIONS);
	if (regions == nullptr) {
		printf("Allocation error\n");
		return -1;
	}

	count = parse_memory_map(regions);
	if (count == 0) {
		printf("Could not find physical memory regions\n");
		free(regions);
		return -1;
	}

	std::ofstream json_fd;
	json_fd.open("mem_regions.json", std::ofstream::out);
	Json::Value root;

	for (unsigned int i = 0; i < count; i++) {
		root["allowed_regions"][std::to_string(i)]["start"] = regions[i].address;
		root["allowed_regions"][std::to_string(i)]["length"] = regions[i].size;
		printf("Physical memory region %d: %p - %p\n", i, (void*) regions[i].address, (void*) (regions[i].address + regions[i].size));

	}

	Json::StreamWriterBuilder builder;
	json_fd << Json::writeString(builder, root);
	json_fd.close();

	free(regions);
	return 0;
}
