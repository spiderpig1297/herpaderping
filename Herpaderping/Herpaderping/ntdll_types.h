#pragma once

#include <Windows.h>

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING;

typedef struct _STRING64 { 
    USHORT Length; 
    USHORT MaximumLength; 
    ULONGLONG Buffer; 
} STRING64, *PSTRING_64;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

struct _RTL_DRIVE_LETTER_CURDIR { 
    USHORT Flags; 
    USHORT Length;  
    ULONG TimeStamp; 
    struct _STRING DosPath; 
};

struct _CURDIR { 
    _UNICODE_STRING DosPath; 
    VOID* Handle; 
};

typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;                                            
    UCHAR ReadImageFileExecOptions;                                         
    UCHAR BeingDebugged;                                                    
    union
    {
        UCHAR BitField;                                                     
        struct
        {
            UCHAR ImageUsesLargePages : 1;         
            UCHAR IsProtectedProcess : 1;          
            UCHAR IsImageDynamicallyRelocated : 1; 
            UCHAR SkipPatchingUser32Forwarders : 1;
            UCHAR IsPackagedProcess : 1;           
            UCHAR IsAppContainer : 1;              
            UCHAR IsProtectedProcessLight : 1;     
            UCHAR IsLongPathAwareProcess : 1;      
        };
    };
    UCHAR Padding0[4];                  
    ULONGLONG Mutant;                   
    ULONGLONG ImageBaseAddress;         
    ULONGLONG Ldr;                      
    ULONGLONG ProcessParameters;        
    ULONGLONG SubSystemData;            
    ULONGLONG ProcessHeap;              
    ULONGLONG FastPebLock;              
    ULONGLONG AtlThunkSListPtr;         
    ULONGLONG IFEOKey;                  
    union
    {
        ULONG CrossProcessFlags;                                            
        struct
        {
            ULONG ProcessInJob : 1;               
            ULONG ProcessInitializing : 1;        
            ULONG ProcessUsingVEH : 1;            
            ULONG ProcessUsingVCH : 1;            
            ULONG ProcessUsingFTH : 1;            
            ULONG ProcessPreviouslyThrottled : 1; 
            ULONG ProcessCurrentlyThrottled : 1;  
            ULONG ProcessImagesHotPatched : 1;    
            ULONG ReservedBits0 : 24;             
        };
    };
    UCHAR Padding1[4];                                                      
    union
    {
        ULONGLONG KernelCallbackTable;                                      
        ULONGLONG UserSharedInfoPtr;                                        
    };
    ULONG SystemReserved;                                                   
    ULONG AtlThunkSListPtr32;                                               
    ULONGLONG ApiSetMap;                                                    
    ULONG TlsExpansionCounter;                                              
    UCHAR Padding2[4];                                                      
    ULONGLONG TlsBitmap;                                                    
    ULONG TlsBitmapBits[2];                                                 
    ULONGLONG ReadOnlySharedMemoryBase;                                     
    ULONGLONG SharedData;                                                   
    ULONGLONG ReadOnlyStaticServerData;                                     
    ULONGLONG AnsiCodePageData;                                             
    ULONGLONG OemCodePageData;                                              
    ULONGLONG UnicodeCaseTableData;                                         
    ULONG NumberOfProcessors;                                               
    ULONG NtGlobalFlag;                                                     
    union _LARGE_INTEGER CriticalSectionTimeout;                            
    ULONGLONG HeapSegmentReserve;                                           
    ULONGLONG HeapSegmentCommit;                                            
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               
    ULONG NumberOfHeaps;                                                    
    ULONG MaximumNumberOfHeaps;                                             
    ULONGLONG ProcessHeaps;                                                 
    ULONGLONG GdiSharedHandleTable;                                         
    ULONGLONG ProcessStarterHelper;                                         
    ULONG GdiDCAttributeList;                                               
    UCHAR Padding3[4];                                                      
    ULONGLONG LoaderLock;                                                   
    ULONG OSMajorVersion;                                                   
    ULONG OSMinorVersion;                                                   
    USHORT OSBuildNumber;                                                   
    USHORT OSCSDVersion;                                                    
    ULONG OSPlatformId;                                                     
    ULONG ImageSubsystem;                                                   
    ULONG ImageSubsystemMajorVersion;                                       
    ULONG ImageSubsystemMinorVersion;                                       
    UCHAR Padding4[4];                                                      
    ULONGLONG ActiveProcessAffinityMask;                                    
    ULONG GdiHandleBuffer[60];                                              
    ULONGLONG PostProcessInitRoutine;                                       
    ULONGLONG TlsExpansionBitmap;                                           
    ULONG TlsExpansionBitmapBits[32];                                       
    ULONG SessionId;                                                        
    UCHAR Padding5[4];                                                      
    union _ULARGE_INTEGER AppCompatFlags;                                   
    union _ULARGE_INTEGER AppCompatFlagsUser;                               
    ULONGLONG pShimData;                                                    
    ULONGLONG AppCompatInfo;                                                
    struct _STRING64 CSDVersion;                                            
    ULONGLONG ActivationContextData;                                        
    ULONGLONG ProcessAssemblyStorageMap;                                    
    ULONGLONG SystemDefaultActivationContextData;                           
    ULONGLONG SystemAssemblyStorageMap;                                     
    ULONGLONG MinimumStackCommit;                                           
    ULONGLONG SparePointers[4];                                             
    ULONG SpareUlongs[5];                                                   
    ULONGLONG WerRegistrationData;                                          
    ULONGLONG WerShipAssertPtr;                                             
    ULONGLONG pUnused;                                                      
    ULONGLONG pImageHeaderHash;                                             
    union
    {
        ULONG TracingFlags;                                
        struct
        {
            ULONG HeapTracingEnabled : 1;                  
            ULONG CritSecTracingEnabled : 1;               
            ULONG LibLoaderTracingEnabled : 1;             
            ULONG SpareTracingBits : 29;                   
        };
    };
    UCHAR Padding6[4];                                     
    ULONGLONG CsrServerReadOnlySharedMemoryBase;           
    ULONGLONG TppWorkerpListLock;                          
    struct LIST_ENTRY64 TppWorkerpList;                    
    ULONGLONG WaitOnAddressHashTable[128];                 
    ULONGLONG TelemetryCoverageHeader;                     
    ULONG CloudFileFlags;                                  
    ULONG CloudFileDiagFlags;                              
    CHAR PlaceholderCompatibilityMode;                     
    CHAR PlaceholderCompatibilityModeReserved[7];          
    ULONGLONG LeapSecondData;                              
    union
    {
        ULONG LeapSecondFlags;                             
        struct
        {
            ULONG SixtySecondEnabled : 1;                  
            ULONG Reserved : 31;                           
        };
    };
    ULONG NtGlobalFlag2;                                   
} PEB64, * PPEB64;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;                                         
    ULONG Length;                                                
    ULONG Flags;                                                 
    ULONG DebugFlags;                                            
    VOID* ConsoleHandle;                                         
    ULONG ConsoleFlags;                                          
    VOID* StandardInput;                                         
    VOID* StandardOutput;                                        
    VOID* StandardError;                                         
    struct _CURDIR CurrentDirectory;                             
    struct _UNICODE_STRING DllPath;                              
    struct _UNICODE_STRING ImagePathName;                        
    struct _UNICODE_STRING CommandLine;                          
    VOID* Environment;                                           
    ULONG StartingX;                                             
    ULONG StartingY;                                             
    ULONG CountX;                                                
    ULONG CountY;                                                
    ULONG CountCharsX;                                           
    ULONG CountCharsY;                                           
    ULONG FillAttribute;                                         
    ULONG WindowFlags;                                           
    ULONG ShowWindowFlags;                                       
    struct _UNICODE_STRING WindowTitle;                          
    struct _UNICODE_STRING DesktopInfo;                          
    struct _UNICODE_STRING ShellInfo;                            
    struct _UNICODE_STRING RuntimeData;                          
    struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];       
    ULONGLONG EnvironmentSize;                                   
    ULONGLONG EnvironmentVersion;                                
    VOID* PackageDependencyData;                                 
    ULONG ProcessGroupId;                                        
    ULONG LoaderThreads;                                         
    struct _UNICODE_STRING RedirectionDllName;                   
    struct _UNICODE_STRING HeapPartitionName;                    
    ULONGLONG* DefaultThreadpoolCpuSetMasks;                     
    ULONG DefaultThreadpoolCpuSetMaskCount;                      
    ULONG DefaultThreadpoolThreadMaximum;                        
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;


typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB64 PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;