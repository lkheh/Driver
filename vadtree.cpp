extern "C"
{
#include "NTDDK.h"
}
 
 //---------------------//
 // MMVAD Structure simple Definition//
 //---------------------//
 typedef struct _MMVAD {
     ULONG StartingVpn;
     ULONG EndingVpn;
     struct _MMVAD * Parent;
     struct _MMVAD * LeftChild;
     struct _MMVAD * RightChild;
 }MMVAD,*PMMVAD;
 
 
 
 VOID Unload(IN PDRIVER_OBJECT pDriverObject) {
     DbgPrint("Driver UnLoad!");
 }
 
 //-----------//
 // Traversing VAD tree //
 //-----------//
 VOID vad_enum(PMMVAD pVad) {
     if (pVad) {
         DbgPrint("Start: %x | End: %x | \r\n", pVad->StartingVpn, pVad->EndingVpn);
         if (pVad->LeftChild)
             vad_enum(pVad->LeftChild);
         if (pVad->RightChild)
             vad_enum(pVad->RightChild);
     }
 }
 
 
 //-------------------------------------------------------------//
 //  The principle of process traversal in the kernel is to first get the system process EPROCESS structure.       //
 //        Then follow the linklist to get the other processes.        //
 //        Iterate in order                                           //
 //-------------------------------------------------------------//
 NTSTATUS process_enum() {
 
     PEPROCESS pEprocess = NULL; // Get the system process address
     PEPROCESS pFirstEprocess = NULL;
     ULONG ulProcessName = 0; // String pointer to process name
     ULONG ulProcessID = 0;    // Process ID
     ANSI_STRING target_str; // Name of the process with detection
     ANSI_STRING ansi_string; // 
     ULONG VadRoot;
 
     //----------------------------//
     // Get the EPROCESS of the current system process //
     //----------------------------//
     pEprocess = PsGetCurrentProcess();
     if (pEprocess == NULL) {
         DbgPrint("Get the current system process EPROCESS error..");
         return STATUS_SUCCESS;
     }
     DbgPrint("pEprocess addr is %x0x8\r\n", pEprocess);
     pFirstEprocess = pEprocess;
 
     while (pEprocess) {
 
         ulProcessName = (ULONG)pEprocess + 0x174;
         ulProcessID = *(ULONG*)((ULONG)pEprocess + 0x84);
         VadRoot = *(ULONG*)((ULONG)pEprocess + 0x11c);
 
         //--------------------------------------//
         // Compare the process name of the target process with that of the current process //
         //--------------------------------------//
         RtlInitAnsiString(&ansi_string, (PCSTR)ulProcessName);    
         RtlInitAnsiString(&target_str, "test.exe");
         if (RtlEqualString(&ansi_string, &target_str, TRUE)) {
             DbgPrint("Process string detected，%x", ulProcessID);
             vad_enum((PMMVAD)VadRoot); // Start traversing the VAD tree of the target process
             return STATUS_SUCCESS;
         }
         pEprocess = (PEPROCESS)(*(ULONG*)((ULONG)pEprocess + 0x88) - 0x88);
 
         if (pEprocess == pFirstEprocess || *(ULONG*)((ULONG)pEprocess + 0x84) <= 0) {
             DbgPrint("End of traversal! End of traversal! Process ID not detected!\r\n");
             break;
         }
     }
     return STATUS_SUCCESS;
 }
 
 NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING registeryPat) {
     DbgPrint("Driver Loaded!");
     pDriverObject->DriverUnload = Unload;
     process_enum();
     return STATUS_SUCCESS;
 }
//From:https://www.cnblogs.com/onetrainee/p/11741909.html
