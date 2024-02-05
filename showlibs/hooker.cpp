#include "framework.h"
#include "hooker.h"

#include <unordered_map>
#include <string>
#include <initializer_list>
#include <type_traits>

PIPEINST _pipeInst;
Tracking _track;
HMODULE _hKernel = NULL;

const std::initializer_list<const std::string> _funcNames = {
  "AcquireSRWLockExclusive",
  "AcquireSRWLockShared",
  "ActivateActCtx",
  "AddAtomA",
  "AddAtomW",
  "AddConsoleAliasA",
  "AddConsoleAliasW",
  "AddDllDirectory",
  "AddIntegrityLabelToBoundaryDescriptor",
  "AddLocalAlternateComputerNameA",
  "AddLocalAlternateComputerNameW",
  "AddRefActCtx",
  "AddResourceAttributeAce",
  "AddSIDToBoundaryDescriptor",
  "AddSecureMemoryCacheCallback",
  "AddVectoredContinueHandler",
  "AddVectoredExceptionHandler",
  "AllocConsole",
  "AllocateUserPhysicalPages",
  "AllocateUserPhysicalPagesNuma",
  "AppPolicyGetClrCompat",
  "AppPolicyGetMediaFoundationCodecLoading",
  "AppPolicyGetProcessTerminationMethod",
  "AppPolicyGetThreadInitializationType",
  "AppPolicyGetWindowingModel",
  "ApplicationRecoveryFinished",
  "ApplicationRecoveryInProgress",
  "AreFileApisANSI",
  "AssignProcessToJobObject",
  "AttachConsole",
  "BackupRead",
  "BackupSeek",
  "BackupWrite",
  "BaseFlushAppcompatCache",
  "Beep",
  "BeginUpdateResourceA",
  "BeginUpdateResourceW",
  "BindIoCompletionCallback",
  "BuildCommDCBA",
  "BuildCommDCBAndTimeoutsA",
  "BuildCommDCBAndTimeoutsW",
  "BuildCommDCBW",
  "CallNamedPipeA",
  "CallNamedPipeW",
  "CallbackMayRunLong",
  "CancelIo",
  "CancelIoEx",
  "CancelSynchronousIo",
  "CancelThreadpoolIo",
  "CancelWaitableTimer",
  "CeipIsOptedIn",
  "ChangeTimerQueueTimer",
  "CheckNameLegalDOS8Dot3A",
  "CheckNameLegalDOS8Dot3W",
  "CheckRemoteDebuggerPresent",
  "CheckTokenCapability",
  "CheckTokenMembershipEx",
  "ClearCommBreak",
  "ClearCommError",
  "CloseHandle",
  "ClosePackageInfo",
  "ClosePrivateNamespace",
  "ClosePseudoConsole",
  "CloseThreadpool",
  "CloseThreadpoolCleanupGroup",
  "CloseThreadpoolCleanupGroupMembers",
  "CloseThreadpoolIo",
  "CloseThreadpoolTimer",
  "CloseThreadpoolWait",
  "CloseThreadpoolWork",
  "CommConfigDialogA",
  "CommConfigDialogW",
  "CompareFileTime",
  "CompareStringA",
  "CompareStringEx",
  "CompareStringOrdinal",
  "CompareStringW",
  "ConnectNamedPipe",
  "ContinueDebugEvent",
  "ConvertDefaultLocale",
  "ConvertFiberToThread",
  "ConvertThreadToFiber",
  "ConvertThreadToFiberEx",
  "CopyContext",
  "CopyFile2",
  "CopyFileA",
  "CopyFileExA",
  "CopyFileExW",
  "CopyFileTransactedA",
  "CopyFileTransactedW",
  "CopyFileW",
  "CreateActCtxA",
  "CreateActCtxW",
  "CreateBoundaryDescriptorA",
  "CreateBoundaryDescriptorW",
  "CreateConsoleScreenBuffer",
  "CreateDirectoryA",
  "CreateDirectoryExA",
  "CreateDirectoryExW",
  "CreateDirectoryTransactedA",
  "CreateDirectoryTransactedW",
  "CreateDirectoryW",
  "CreateEnclave",
  "CreateEventA",
  "CreateEventExA",
  "CreateEventExW",
  "CreateEventW",
  "CreateFiber",
  "CreateFiberEx",
  "CreateFile2",
  "CreateFileA",
  "CreateFileMappingA",
  "CreateFileMappingFromApp",
  "CreateFileMappingNumaA",
  "CreateFileMappingNumaW",
  "CreateFileMappingW",
  "CreateFileTransactedA",
  "CreateFileTransactedW",
  "CreateFileW",
  "CreateHardLinkA",
  "CreateHardLinkTransactedA",
  "CreateHardLinkTransactedW",
  "CreateHardLinkW",
  "CreateIoCompletionPort",
  "CreateJobObjectA",
  "CreateJobObjectW",
  "CreateMailslotA",
  "CreateMailslotW",
  "CreateMemoryResourceNotification",
  "CreateMutexA",
  "CreateMutexExA",
  "CreateMutexExW",
  "CreateMutexW",
  "CreateNamedPipeA",
  "CreateNamedPipeW",
  "CreatePipe",
  "CreatePrivateNamespaceA",
  "CreatePrivateNamespaceW",
  "CreateProcessA",
  "CreateProcessAsUserA",
  "CreateProcessAsUserW",
  "CreateProcessW",
  "CreatePseudoConsole",
  "CreateRemoteThread",
  "CreateRemoteThreadEx",
  "CreateSemaphoreA",
  "CreateSemaphoreExA",
  "CreateSemaphoreExW",
  "CreateSemaphoreW",
  "CreateSymbolicLinkA",
  "CreateSymbolicLinkTransactedA",
  "CreateSymbolicLinkTransactedW",
  "CreateSymbolicLinkW",
  "CreateTapePartition",
  "CreateThread",
  "CreateThreadpool",
  "CreateThreadpoolCleanupGroup",
  "CreateThreadpoolIo",
  "CreateThreadpoolTimer",
  "CreateThreadpoolWait",
  "CreateThreadpoolWork",
  "CreateTimerQueue",
  "CreateTimerQueueTimer",
  "CreateToolhelp32Snapshot",
  "CreateUmsCompletionList",
  "CreateUmsThreadContext",
  "CreateWaitableTimerA",
  "CreateWaitableTimerExA",
  "CreateWaitableTimerExW",
  "CreateWaitableTimerW",
  "DeactivateActCtx",
  "DebugBreak",
  "DebugBreakProcess",
  "DebugSetProcessKillOnExit",
  "DecodePointer",
  "DecodeSystemPointer",
  "DefineDosDeviceA",
  "DefineDosDeviceW",
  "DelayLoadFailureHook",
  "DeleteAtom",
  "DeleteBoundaryDescriptor",
  "DeleteCriticalSection",
  "DeleteFiber",
  "DeleteFileA",
  "DeleteFileTransactedA",
  "DeleteFileTransactedW",
  "DeleteFileW",
  "DeleteProcThreadAttributeList",
  "DeleteSynchronizationBarrier",
  "DeleteTimerQueue",
  "DeleteTimerQueueEx",
  "DeleteTimerQueueTimer",
  "DeleteUmsCompletionList",
  "DeleteUmsThreadContext",
  "DeleteVolumeMountPointA",
  "DeleteVolumeMountPointW",
  "DequeueUmsCompletionListItems",
  "DeviceIoControl",
  "DisableThreadLibraryCalls",
  "DisableThreadProfiling",
  "DisassociateCurrentThreadFromCallback",
  "DiscardVirtualMemory",
  "DisconnectNamedPipe",
  "DnsHostnameToComputerNameA",
  "DnsHostnameToComputerNameW",
  "DosDateTimeToFileTime",
  "DuplicateHandle",
  "EnableThreadProfiling",
  "EncodePointer",
  "EncodeSystemPointer",
  "EndUpdateResourceA",
  "EndUpdateResourceW",
  "EnterCriticalSection",
  "EnterSynchronizationBarrier",
  "EnterUmsSchedulingMode",
  "EnumCalendarInfoA",
  "EnumCalendarInfoExA",
  "EnumCalendarInfoExEx",
  "EnumCalendarInfoExW",
  "EnumCalendarInfoW",
  "EnumDateFormatsA",
  "EnumDateFormatsExA",
  "EnumDateFormatsExEx",
  "EnumDateFormatsExW",
  "EnumDateFormatsW",
  "EnumLanguageGroupLocalesA",
  "EnumLanguageGroupLocalesW",
  "EnumResourceLanguagesA",
  "EnumResourceLanguagesExA",
  "EnumResourceLanguagesExW",
  "EnumResourceLanguagesW",
  "EnumResourceNamesA",
  "EnumResourceNamesExA",
  "EnumResourceNamesExW",
  "EnumResourceNamesW",
  "EnumResourceTypesA",
  "EnumResourceTypesExA",
  "EnumResourceTypesExW",
  "EnumResourceTypesW",
  "EnumSystemCodePagesA",
  "EnumSystemCodePagesW",
  "EnumSystemFirmwareTables",
  "EnumSystemGeoID",
  "EnumSystemGeoNames",
  "EnumSystemLanguageGroupsA",
  "EnumSystemLanguageGroupsW",
  "EnumSystemLocalesA",
  "EnumSystemLocalesEx",
  "EnumSystemLocalesW",
  "EnumTimeFormatsA",
  "EnumTimeFormatsEx",
  "EnumTimeFormatsW",
  "EnumUILanguagesA",
  "EnumUILanguagesW",
  "EraseTape",
  "EscapeCommFunction",
  "ExecuteUmsThread",
  "ExitProcess",
  "ExitThread",
  "ExpandEnvironmentStringsA",
  "ExpandEnvironmentStringsW",
  "FatalAppExitA",
  "FatalAppExitW",
  "FatalExit",
  "FileTimeToDosDateTime",
  "FileTimeToLocalFileTime",
  "FileTimeToSystemTime",
  "FillConsoleOutputAttribute",
  "FillConsoleOutputCharacterA",
  "FillConsoleOutputCharacterW",
  "FindActCtxSectionGuid",
  "FindActCtxSectionStringA",
  "FindActCtxSectionStringW",
  "FindAtomA",
  "FindAtomW",
  "FindClose",
  "FindCloseChangeNotification",
  "FindFirstChangeNotificationA",
  "FindFirstChangeNotificationW",
  "FindFirstFileA",
  "FindFirstFileExA",
  "FindFirstFileExW",
  "FindFirstFileNameTransactedW",
  "FindFirstFileNameW",
  "FindFirstFileTransactedA",
  "FindFirstFileTransactedW",
  "FindFirstFileW",
  "FindFirstStreamTransactedW",
  "FindFirstStreamW",
  "FindFirstVolumeA",
  "FindFirstVolumeMountPointA",
  "FindFirstVolumeMountPointW",
  "FindFirstVolumeW",
  "FindNLSString",
  "FindNLSStringEx",
  "FindNextChangeNotification",
  "FindNextFileA",
  "FindNextFileNameW",
  "FindNextFileW",
  "FindNextStreamW",
  "FindNextVolumeA",
  "FindNextVolumeMountPointA",
  "FindNextVolumeMountPointW",
  "FindNextVolumeW",
  "FindPackagesByPackageFamily",
  "FindResourceA",
  "FindResourceExA",
  "FindResourceExW",
  "FindResourceW",
  "FindStringOrdinal",
  "FindVolumeClose",
  "FindVolumeMountPointClose",
  "FlsAlloc",
  "FlsFree",
  "FlsGetValue",
  "FlsSetValue",
  "FlushConsoleInputBuffer",
  "FlushFileBuffers",
  "FlushInstructionCache",
  "FlushProcessWriteBuffers",
  "FlushViewOfFile",
  "FoldStringA",
  "FoldStringW",
  "FormatApplicationUserModelId",
  "FormatMessageA",
  "FormatMessageW",
  "FreeConsole",
  "FreeEnvironmentStringsA",
  "FreeEnvironmentStringsW",
  "FreeLibrary",
  "FreeLibraryAndExitThread",
  "FreeLibraryWhenCallbackReturns",
  "FreeMemoryJobObject",
  "FreeResource",
  "FreeUserPhysicalPages",
  "GenerateConsoleCtrlEvent",
  "GetACP",
  "GetActiveProcessorCount",
  "GetActiveProcessorGroupCount",
  "GetAppContainerAce",
  "GetAppContainerNamedObjectPath",
  "GetApplicationRecoveryCallback",
  "GetApplicationRestartSettings",
  "GetApplicationUserModelId",
  "GetAtomNameA",
  "GetAtomNameW",
  "GetBinaryTypeA",
  "GetBinaryTypeW",
  "GetCPInfo",
  "GetCPInfoExA",
  "GetCPInfoExW",
  "GetCachedSigningLevel",
  "GetCalendarDateFormatEx",
  "GetCalendarInfoA",
  "GetCalendarInfoEx",
  "GetCalendarInfoW",
  "GetCalendarSupportedDateRange",
  "GetComPlusPackageInstallStatus",
  "GetCommConfig",
  "GetCommMask",
  "GetCommModemStatus",
  "GetCommProperties",
  "GetCommState",
  "GetCommTimeouts",
  "GetCommandLineA",
  "GetCommandLineW",
  "GetCompressedFileSizeA",
  "GetCompressedFileSizeTransactedA",
  "GetCompressedFileSizeTransactedW",
  "GetCompressedFileSizeW",
  "GetComputerNameA",
  "GetComputerNameExA",
  "GetComputerNameExW",
  "GetComputerNameW",
  "GetConsoleAliasA",
  "GetConsoleAliasExesA",
  "GetConsoleAliasExesLengthA",
  "GetConsoleAliasExesLengthW",
  "GetConsoleAliasExesW",
  "GetConsoleAliasW",
  "GetConsoleAliasesA",
  "GetConsoleAliasesLengthA",
  "GetConsoleAliasesLengthW",
  "GetConsoleAliasesW",
  "GetConsoleCP",
  "GetConsoleCursorInfo",
  "GetConsoleDisplayMode",
  "GetConsoleFontSize",
  "GetConsoleHistoryInfo",
  "GetConsoleMode",
  "GetConsoleOriginalTitleA",
  "GetConsoleOriginalTitleW",
  "GetConsoleOutputCP",
  "GetConsoleProcessList",
  "GetConsoleScreenBufferInfo",
  "GetConsoleScreenBufferInfoEx",
  "GetConsoleSelectionInfo",
  "GetConsoleTitleA",
  "GetConsoleTitleW",
  "GetConsoleWindow",
  "GetCurrencyFormatA",
  "GetCurrencyFormatEx",
  "GetCurrencyFormatW",
  "GetCurrentActCtx",
  "GetCurrentApplicationUserModelId",
  "GetCurrentConsoleFont",
  "GetCurrentConsoleFontEx",
  "GetCurrentDirectoryA",
  "GetCurrentDirectoryW",
  "GetCurrentPackageFamilyName",
  "GetCurrentPackageFullName",
  "GetCurrentPackageId",
  "GetCurrentPackageInfo",
  "GetCurrentPackagePath",
  "GetCurrentProcess",
  "GetCurrentProcessId",
  "GetCurrentProcessorNumber",
  "GetCurrentProcessorNumberEx",
  "GetCurrentThread",
  "GetCurrentThreadId",
  "GetCurrentThreadStackLimits",
  "GetCurrentUmsThread",
  "GetDateFormatA",
  "GetDateFormatEx",
  "GetDateFormatW",
  "GetDefaultCommConfigA",
  "GetDefaultCommConfigW",
  "GetDevicePowerState",
  "GetDiskFreeSpaceA",
  "GetDiskFreeSpaceExA",
  "GetDiskFreeSpaceExW",
  "GetDiskFreeSpaceW",
  "GetDiskSpaceInformationA",
  "GetDiskSpaceInformationW",
  "GetDllDirectoryA",
  "GetDllDirectoryW",
  "GetDriveTypeA",
  "GetDriveTypeW",
  "GetDurationFormat",
  "GetDurationFormatEx",
  "GetDynamicTimeZoneInformation",
  "GetEnabledXStateFeatures",
  "GetEnvironmentStrings",
  "GetEnvironmentStringsW",
  "GetEnvironmentVariableA",
  "GetEnvironmentVariableW",
  "GetErrorMode",
  "GetExitCodeProcess",
  "GetExitCodeThread",
  "GetExpandedNameA",
  "GetExpandedNameW",
  "GetFileAttributesA",
  "GetFileAttributesExA",
  "GetFileAttributesExW",
  "GetFileAttributesTransactedA",
  "GetFileAttributesTransactedW",
  "GetFileAttributesW",
  "GetFileBandwidthReservation",
  "GetFileInformationByHandle",
  "GetFileInformationByHandleEx",
  "GetFileMUIInfo",
  "GetFileMUIPath",
  "GetFileSize",
  "GetFileSizeEx",
  "GetFileTime",
  "GetFileType",
  "GetFinalPathNameByHandleA",
  "GetFinalPathNameByHandleW",
  "GetFirmwareEnvironmentVariableA",
  "GetFirmwareEnvironmentVariableExA",
  "GetFirmwareEnvironmentVariableExW",
  "GetFirmwareEnvironmentVariableW",
  "GetFirmwareType",
  "GetFullPathNameA",
  "GetFullPathNameTransactedA",
  "GetFullPathNameTransactedW",
  "GetFullPathNameW",
  "GetGeoInfoA",
  "GetGeoInfoEx",
  "GetGeoInfoW",
  "GetHandleInformation",
  "GetLargePageMinimum",
  "GetLargestConsoleWindowSize",
  "GetLastError",
  "GetLocalTime",
  "GetLocaleInfoA",
  "GetLocaleInfoEx",
  "GetLocaleInfoW",
  "GetLogicalDriveStringsA",
  "GetLogicalDriveStringsW",
  "GetLogicalDrives",
  "GetLogicalProcessorInformation",
  "GetLogicalProcessorInformationEx",
  "GetLongPathNameA",
  "GetLongPathNameTransactedA",
  "GetLongPathNameTransactedW",
  "GetLongPathNameW",
  "GetMailslotInfo",
  "GetMaximumProcessorCount",
  "GetMaximumProcessorGroupCount",
  "GetMemoryErrorHandlingCapabilities",
  "GetModuleFileNameA",
  "GetModuleFileNameW",
  "GetModuleHandleA",
  "GetModuleHandleExA",
  "GetModuleHandleExW",
  "GetModuleHandleW",
  "GetNLSVersion",
  "GetNLSVersionEx",
  "GetNamedPipeClientComputerNameA",
  "GetNamedPipeClientComputerNameW",
  "GetNamedPipeClientProcessId",
  "GetNamedPipeClientSessionId",
  "GetNamedPipeHandleStateA",
  "GetNamedPipeHandleStateW",
  "GetNamedPipeInfo",
  "GetNamedPipeServerProcessId",
  "GetNamedPipeServerSessionId",
  "GetNativeSystemInfo",
  "GetNextUmsListItem",
  "GetNumaAvailableMemoryNode",
  "GetNumaAvailableMemoryNodeEx",
  "GetNumaHighestNodeNumber",
  "GetNumaNodeNumberFromHandle",
  "GetNumaNodeProcessorMask",
  "GetNumaNodeProcessorMaskEx",
  "GetNumaProcessorNode",
  "GetNumaProcessorNodeEx",
  "GetNumaProximityNode",
  "GetNumaProximityNodeEx",
  "GetNumberFormatA",
  "GetNumberFormatEx",
  "GetNumberFormatW",
  "GetNumberOfConsoleFonts",
  "GetNumberOfConsoleInputEvents",
  "GetNumberOfConsoleMouseButtons",
  "GetOEMCP",
  "GetOverlappedResult",
  "GetOverlappedResultEx",
  "GetPackageApplicationIds",
  "GetPackageFamilyName",
  "GetPackageFullName",
  "GetPackageId",
  "GetPackagePath",
  "GetPackagePathByFullName",
  "GetPackagesByPackageFamily",
  "GetPhysicallyInstalledSystemMemory",
  "GetPriorityClass",
  "GetPrivateProfileIntA",
  "GetPrivateProfileIntW",
  "GetPrivateProfileSectionA",
  "GetPrivateProfileSectionNamesA",
  "GetPrivateProfileSectionNamesW",
  "GetPrivateProfileSectionW",
  "GetPrivateProfileStringA",
  "GetPrivateProfileStringW",
  "GetPrivateProfileStructA",
  "GetPrivateProfileStructW",
  "GetProcAddress",
  "GetProcessAffinityMask",
  "GetProcessDEPPolicy",
  "GetProcessDefaultCpuSets",
  "GetProcessGroupAffinity",
  "GetProcessHandleCount",
  "GetProcessHeap",
  "GetProcessHeaps",
  "GetProcessId",
  "GetProcessIdOfThread",
  "GetProcessInformation",
  "GetProcessIoCounters",
  "GetProcessMitigationPolicy",
  "GetProcessPreferredUILanguages",
  "GetProcessPriorityBoost",
  "GetProcessShutdownParameters",
  "GetProcessTimes",
  "GetProcessVersion",
  "GetProcessWorkingSetSize",
  "GetProcessWorkingSetSizeEx",
  "GetProcessorSystemCycleTime",
  "GetProductInfo",
  "GetProfileIntA",
  "GetProfileIntW",
  "GetProfileSectionA",
  "GetProfileSectionW",
  "GetProfileStringA",
  "GetProfileStringW",
  "GetQueuedCompletionStatus",
  "GetQueuedCompletionStatusEx",
  "GetShortPathNameA",
  "GetShortPathNameW",
  "GetStagedPackagePathByFullName",
  "GetStartupInfoA",
  "GetStartupInfoW",
  "GetStdHandle",
  "GetStringScripts",
  "GetStringTypeA",
  "GetStringTypeExA",
  "GetStringTypeExW",
  "GetStringTypeW",
  "GetSystemCpuSetInformation",
  "GetSystemDEPPolicy",
  "GetSystemDefaultLCID",
  "GetSystemDefaultLangID",
  "GetSystemDefaultLocaleName",
  "GetSystemDefaultUILanguage",
  "GetSystemDirectoryA",
  "GetSystemDirectoryW",
  "GetSystemFileCacheSize",
  "GetSystemFirmwareTable",
  "GetSystemInfo",
  "GetSystemPowerStatus",
  "GetSystemPreferredUILanguages",
  "GetSystemRegistryQuota",
  "GetSystemTime",
  "GetSystemTimeAdjustment",
  "GetSystemTimeAsFileTime",
  "GetSystemTimePreciseAsFileTime",
  "GetSystemTimes",
  "GetSystemWindowsDirectoryA",
  "GetSystemWindowsDirectoryW",
  "GetSystemWow64DirectoryA",
  "GetSystemWow64DirectoryW",
  "GetTapeParameters",
  "GetTapePosition",
  "GetTapeStatus",
  "GetTempFileNameA",
  "GetTempFileNameW",
  "GetTempPathA",
  "GetTempPathW",
  "GetThreadContext",
  "GetThreadDescription",
  "GetThreadErrorMode",
  "GetThreadGroupAffinity",
  "GetThreadIOPendingFlag",
  "GetThreadId",
  "GetThreadIdealProcessorEx",
  "GetThreadInformation",
  "GetThreadLocale",
  "GetThreadPreferredUILanguages",
  "GetThreadPriority",
  "GetThreadPriorityBoost",
  "GetThreadSelectorEntry",
  "GetThreadTimes",
  "GetThreadUILanguage",
  "GetTickCount",
  "GetTickCount64",
  "GetTimeFormatA",
  "GetTimeFormatEx",
  "GetTimeFormatW",
  "GetTimeZoneInformation",
  "GetTimeZoneInformationForYear",
  "GetUILanguageInfo",
  "GetUmsCompletionListEvent",
  "GetUmsSystemThreadInformation",
  "GetUserDefaultGeoName",
  "GetUserDefaultLCID",
  "GetUserDefaultLangID",
  "GetUserDefaultLocaleName",
  "GetUserDefaultUILanguage",
  "GetUserGeoID",
  "GetUserPreferredUILanguages",
  "GetVersion",
  "GetVersionExA",
  "GetVersionExW",
  "GetVolumeInformationA",
  "GetVolumeInformationByHandleW",
  "GetVolumeInformationW",
  "GetVolumeNameForVolumeMountPointA",
  "GetVolumeNameForVolumeMountPointW",
  "GetVolumePathNameA",
  "GetVolumePathNameW",
  "GetVolumePathNamesForVolumeNameA",
  "GetVolumePathNamesForVolumeNameW",
  "GetWindowsDirectoryA",
  "GetWindowsDirectoryW",
  "GetWriteWatch",
  "GetXStateFeaturesMask",
  "GlobalAddAtomA",
  "GlobalAddAtomExA",
  "GlobalAddAtomExW",
  "GlobalAddAtomW",
  "GlobalAlloc",
  "GlobalDeleteAtom",
  "GlobalFindAtomA",
  "GlobalFindAtomW",
  "GlobalFlags",
  "GlobalFree",
  "GlobalGetAtomNameA",
  "GlobalGetAtomNameW",
  "GlobalHandle",
  "GlobalLock",
  "GlobalMemoryStatus",
  "GlobalMemoryStatusEx",
  "GlobalReAlloc",
  "GlobalSize",
  "GlobalUnlock",
  "Heap32First",
  "Heap32ListFirst",
  "Heap32ListNext",
  "Heap32Next",
  "HeapAlloc",
  "HeapCompact",
  "HeapCreate",
  "HeapDestroy",
  "HeapFree",
  "HeapLock",
  "HeapQueryInformation",
  "HeapReAlloc",
  "HeapSetInformation",
  "HeapSize",
  "HeapSummary",
  "HeapUnlock",
  "HeapValidate",
  "HeapWalk",
  "IdnToAscii",
  "IdnToNameprepUnicode",
  "IdnToUnicode",
  "InitAtomTable",
  "InitOnceBeginInitialize",
  "InitOnceComplete",
  "InitOnceExecuteOnce",
  "InitOnceInitialize",
  "InitializeConditionVariable",
  "InitializeContext",
  "InitializeContext2",
  "InitializeCriticalSection",
  "InitializeCriticalSectionAndSpinCount",
  "InitializeCriticalSectionEx",
  "InitializeEnclave",
  "InitializeProcThreadAttributeList",
  "InitializeSListHead",
  "InitializeSRWLock",
  "InitializeSynchronizationBarrier",
  "InstallELAMCertificateInfo",
  "InterlockedFlushSList",
  "InterlockedPopEntrySList",
  "InterlockedPushEntrySList",
  "InterlockedPushListSList",
  "InterlockedPushListSListEx",
  "InvalidateConsoleDIBits",
  "IsBadCodePtr",
  "IsBadReadPtr",
  "IsBadStringPtrA",
  "IsBadStringPtrW",
  "IsBadWritePtr",
  "IsCalendarLeapYear",
  "IsDBCSLeadByte",
  "IsDBCSLeadByteEx",
  "IsDebuggerPresent",
  "IsEnclaveTypeSupported",
  "IsNLSDefinedString",
  "IsNativeVhdBoot",
  "IsNormalizedString",
  "IsProcessCritical",
  "IsProcessInJob",
  "IsProcessorFeaturePresent",
  "IsSystemResumeAutomatic",
  "IsThreadAFiber",
  "IsThreadpoolTimerSet",
  "IsUserCetAvailableInEnvironment",
  "IsValidCodePage",
  "IsValidLanguageGroup",
  "IsValidLocale",
  "IsValidLocaleName",
  "IsValidNLSVersion",
  "IsWow64GuestMachineSupported",
  "IsWow64Process",
  "IsWow64Process2",
  "K32EmptyWorkingSet",
  "K32EnumDeviceDrivers",
  "K32EnumPageFilesA",
  "K32EnumPageFilesW",
  "K32EnumProcessModules",
  "K32EnumProcessModulesEx",
  "K32EnumProcesses",
  "K32GetDeviceDriverBaseNameA",
  "K32GetDeviceDriverBaseNameW",
  "K32GetDeviceDriverFileNameA",
  "K32GetDeviceDriverFileNameW",
  "K32GetMappedFileNameA",
  "K32GetMappedFileNameW",
  "K32GetModuleBaseNameA",
  "K32GetModuleBaseNameW",
  "K32GetModuleFileNameExA",
  "K32GetModuleFileNameExW",
  "K32GetModuleInformation",
  "K32GetPerformanceInfo",
  "K32GetProcessImageFileNameA",
  "K32GetProcessImageFileNameW",
  "K32GetProcessMemoryInfo",
  "K32GetWsChanges",
  "K32GetWsChangesEx",
  "K32InitializeProcessForWsWatch",
  "K32QueryWorkingSet",
  "K32QueryWorkingSetEx",
  "LCIDToLocaleName",
  "LCMapStringA",
  "LCMapStringEx",
  "LCMapStringW",
  "LZClose",
  "LZCopy",
  "LZInit",
  "LZOpenFileA",
  "LZOpenFileW",
  "LZRead",
  "LZSeek",
  "LeaveCriticalSection",
  "LeaveCriticalSectionWhenCallbackReturns",
  "LoadEnclaveData",
  "LoadLibraryA",
  "LoadLibraryExA",
  "LoadLibraryExW",
  "LoadLibraryW",
  "LoadModule",
  "LoadPackagedLibrary",
  "LoadResource",
  "LocalAlloc",
  "LocalFileTimeToFileTime",
  "LocalFlags",
  "LocalFree",
  "LocalHandle",
  "LocalLock",
  "LocalReAlloc",
  "LocalSize",
  "LocalUnlock",
  "LocaleNameToLCID",
  "LocateXStateFeature",
  "LockFile",
  "LockFileEx",
  "LockResource",
  "MapUserPhysicalPages",
  "MapUserPhysicalPagesScatter",
  "MapViewOfFile",
  "MapViewOfFileEx",
  "MapViewOfFileExNuma",
  "MapViewOfFileFromApp",
  "Module32First",
  "Module32FirstW",
  "Module32Next",
  "Module32NextW",
  "MoveFileA",
  "MoveFileExA",
  "MoveFileExW",
  "MoveFileTransactedA",
  "MoveFileTransactedW",
  "MoveFileW",
  "MoveFileWithProgressA",
  "MoveFileWithProgressW",
  "MulDiv",
  "MultiByteToWideChar",
  "NeedCurrentDirectoryForExePathA",
  "NeedCurrentDirectoryForExePathW",
  "NormalizeString",
  "NotifyUILanguageChange",
  "OOBEComplete",
  "OfferVirtualMemory",
  "OpenEventA",
  "OpenEventW",
  "OpenFile",
  "OpenFileById",
  "OpenFileMappingA",
  "OpenFileMappingW",
  "OpenJobObjectA",
  "OpenJobObjectW",
  "OpenMutexA",
  "OpenMutexW",
  "OpenPackageInfoByFullName",
  "OpenPrivateNamespaceA",
  "OpenPrivateNamespaceW",
  "OpenProcess",
  "OpenProcessToken",
  "OpenSemaphoreA",
  "OpenSemaphoreW",
  "OpenThread",
  "OpenThreadToken",
  "OpenWaitableTimerA",
  "OpenWaitableTimerW",
  "OutputDebugStringA",
  "OutputDebugStringW",
  "PackageFamilyNameFromFullName",
  "PackageFamilyNameFromId",
  "PackageFullNameFromId",
  "PackageIdFromFullName",
  "PackageNameAndPublisherIdFromFamilyName",
  "ParseApplicationUserModelId",
  "PeekConsoleInputA",
  "PeekConsoleInputW",
  "PeekNamedPipe",
  "PostQueuedCompletionStatus",
  "PowerClearRequest",
  "PowerCreateRequest",
  "PowerSetRequest",
  "PrefetchVirtualMemory",
  "PrepareTape",
  "Process32First",
  "Process32FirstW",
  "Process32Next",
  "Process32NextW",
  "ProcessIdToSessionId",
  "PssCaptureSnapshot",
  "PssDuplicateSnapshot",
  "PssFreeSnapshot",
  "PssQuerySnapshot",
  "PssWalkMarkerCreate",
  "PssWalkMarkerFree",
  "PssWalkMarkerGetPosition",
  "PssWalkMarkerSetPosition",
  "PssWalkSnapshot",
  "PulseEvent",
  "PurgeComm",
  "QueryActCtxSettingsW",
  "QueryActCtxW",
  "QueryDepthSList",
  "QueryDosDeviceA",
  "QueryDosDeviceW",
  "QueryFullProcessImageNameA",
  "QueryFullProcessImageNameW",
  "QueryIdleProcessorCycleTime",
  "QueryIdleProcessorCycleTimeEx",
  "QueryInformationJobObject",
  "QueryIoRateControlInformationJobObject",
  "QueryMemoryResourceNotification",
  "QueryPerformanceCounter",
  "QueryPerformanceFrequency",
  "QueryProcessAffinityUpdateMode",
  "QueryProcessCycleTime",
  "QueryProtectedPolicy",
  "QueryThreadCycleTime",
  "QueryThreadProfiling",
  "QueryThreadpoolStackInformation",
  "QueryUmsThreadInformation",
  "QueryUnbiasedInterruptTime",
  "QueueUserAPC",
  "QueueUserWorkItem",
  "RaiseException",
  "RaiseFailFastException",
  "RaiseInvalid16BitExeError",
  "ReOpenFile",
  "ReadConsoleA",
  "ReadConsoleInputA",
  "ReadConsoleInputExA",
  "ReadConsoleInputExW",
  "ReadConsoleInputW",
  "ReadConsoleOutputA",
  "ReadConsoleOutputAttribute",
  "ReadConsoleOutputCharacterA",
  "ReadConsoleOutputCharacterW",
  "ReadConsoleOutputW",
  "ReadConsoleW",
  "ReadDirectoryChangesExW",
  "ReadDirectoryChangesW",
  "ReadFile",
  "ReadFileEx",
  "ReadFileScatter",
  "ReadProcessMemory",
  "ReadThreadProfilingData",
  "ReclaimVirtualMemory",
  "RegCloseKey",
  "RegCopyTreeW",
  "RegCreateKeyExA",
  "RegCreateKeyExW",
  "RegDeleteKeyExA",
  "RegDeleteKeyExW",
  "RegDeleteTreeA",
  "RegDeleteTreeW",
  "RegDeleteValueA",
  "RegDeleteValueW",
  "RegDisablePredefinedCacheEx",
  "RegEnumKeyExA",
  "RegEnumKeyExW",
  "RegEnumValueA",
  "RegEnumValueW",
  "RegFlushKey",
  "RegGetKeySecurity",
  "RegGetValueA",
  "RegGetValueW",
  "RegLoadKeyA",
  "RegLoadKeyW",
  "RegLoadMUIStringA",
  "RegLoadMUIStringW",
  "RegNotifyChangeKeyValue",
  "RegOpenCurrentUser",
  "RegOpenKeyExA",
  "RegOpenKeyExW",
  "RegOpenUserClassesRoot",
  "RegQueryInfoKeyA",
  "RegQueryInfoKeyW",
  "RegQueryValueExA",
  "RegQueryValueExW",
  "RegRestoreKeyA",
  "RegRestoreKeyW",
  "RegSaveKeyExA",
  "RegSaveKeyExW",
  "RegSetKeySecurity",
  "RegSetValueExA",
  "RegSetValueExW",
  "RegUnLoadKeyA",
  "RegUnLoadKeyW",
  "RegisterApplicationRecoveryCallback",
  "RegisterApplicationRestart",
  "RegisterBadMemoryNotification",
  "RegisterWaitForInputIdle",
  "RegisterWaitForSingleObject",
  "RegisterWaitForSingleObjectEx",
  "RegisterWaitUntilOOBECompleted",
  "ReleaseActCtx",
  "ReleaseMutex",
  "ReleaseMutexWhenCallbackReturns",
  "ReleaseSRWLockExclusive",
  "ReleaseSRWLockShared",
  "ReleaseSemaphore",
  "ReleaseSemaphoreWhenCallbackReturns",
  "RemoveDirectoryA",
  "RemoveDirectoryTransactedA",
  "RemoveDirectoryTransactedW",
  "RemoveDirectoryW",
  "RemoveDllDirectory",
  "RemoveSecureMemoryCacheCallback",
  "RemoveVectoredContinueHandler",
  "RemoveVectoredExceptionHandler",
  "ReplaceFileA",
  "ReplaceFileW",
  "RequestWakeupLatency",
  "ResetEvent",
  "ResetWriteWatch",
  "ResizePseudoConsole",
  "ResolveDelayLoadedAPI",
  "ResolveDelayLoadsFromDll",
  "ResolveLocaleName",
  "ResumeThread",
  "RtlAddFunctionTable",
  "RtlCaptureContext",
  "RtlCaptureStackBackTrace",
  "RtlCompareMemory",
  "RtlCopyMemory",
  "RtlDeleteFunctionTable",
  "RtlFillMemory",
  "RtlInstallFunctionTableCallback",
  "RtlLookupFunctionEntry",
  "RtlMoveMemory",
  "RtlPcToFileHeader",
  "RtlRaiseException",
  "RtlRestoreContext",
  "RtlUnwind",
  "RtlUnwindEx",
  "RtlVirtualUnwind",
  "RtlZeroMemory",
  "ScrollConsoleScreenBufferA",
  "ScrollConsoleScreenBufferW",
  "SearchPathA",
  "SearchPathW",
  "SetCachedSigningLevel",
  "SetCalendarInfoA",
  "SetCalendarInfoW",
  "SetComPlusPackageInstallStatus",
  "SetCommBreak",
  "SetCommConfig",
  "SetCommMask",
  "SetCommState",
  "SetCommTimeouts",
  "SetComputerNameA",
  "SetComputerNameEx2W",
  "SetComputerNameExA",
  "SetComputerNameExW",
  "SetComputerNameW",
  "SetConsoleActiveScreenBuffer",
  "SetConsoleCP",
  "SetConsoleCtrlHandler",
  "SetConsoleCursor",
  "SetConsoleCursorInfo",
  "SetConsoleCursorMode",
  "SetConsoleDisplayMode",
  "SetConsoleHistoryInfo",
  "SetConsoleMaximumWindowSize",
  "SetConsoleMenuClose",
  "SetConsoleMode",
  "SetConsoleNlsMode",
  "SetConsoleOutputCP",
  "SetConsoleScreenBufferInfoEx",
  "SetConsoleScreenBufferSize",
  "SetConsoleTextAttribute",
  "SetConsoleTitleA",
  "SetConsoleTitleW",
  "SetConsoleWindowInfo",
  "SetCriticalSectionSpinCount",
  "SetCurrentConsoleFontEx",
  "SetCurrentDirectoryA",
  "SetCurrentDirectoryW",
  "SetDefaultCommConfigA",
  "SetDefaultCommConfigW",
  "SetDefaultDllDirectories",
  "SetDllDirectoryA",
  "SetDllDirectoryW",
  "SetDynamicTimeZoneInformation",
  "SetEndOfFile",
  "SetEnvironmentStringsW",
  "SetEnvironmentVariableA",
  "SetEnvironmentVariableW",
  "SetErrorMode",
  "SetEvent",
  "SetEventWhenCallbackReturns",
  "SetFileApisToANSI",
  "SetFileApisToOEM",
  "SetFileAttributesA",
  "SetFileAttributesTransactedA",
  "SetFileAttributesTransactedW",
  "SetFileAttributesW",
  "SetFileBandwidthReservation",
  "SetFileCompletionNotificationModes",
  "SetFileInformationByHandle",
  "SetFileIoOverlappedRange",
  "SetFilePointer",
  "SetFilePointerEx",
  "SetFileShortNameA",
  "SetFileShortNameW",
  "SetFileTime",
  "SetFileValidData",
  "SetFirmwareEnvironmentVariableA",
  "SetFirmwareEnvironmentVariableExA",
  "SetFirmwareEnvironmentVariableExW",
  "SetFirmwareEnvironmentVariableW",
  "SetHandleCount",
  "SetHandleInformation",
  "SetInformationJobObject",
  "SetIoRateControlInformationJobObject",
  "SetLastError",
  "SetLocalTime",
  "SetLocaleInfoA",
  "SetLocaleInfoW",
  "SetMailslotInfo",
  "SetNamedPipeHandleState",
  "SetPriorityClass",
  "SetProcessAffinityMask",
  "SetProcessAffinityUpdateMode",
  "SetProcessDEPPolicy",
  "SetProcessDefaultCpuSets",
  "SetProcessDynamicEHContinuationTargets",
  "SetProcessDynamicEnforcedCetCompatibleRanges",
  "SetProcessInformation",
  "SetProcessMitigationPolicy",
  "SetProcessPreferredUILanguages",
  "SetProcessPriorityBoost",
  "SetProcessShutdownParameters",
  "SetProcessWorkingSetSize",
  "SetProcessWorkingSetSizeEx",
  "SetProtectedPolicy",
  "SetSearchPathMode",
  "SetStdHandle",
  "SetStdHandleEx",
  "SetSystemFileCacheSize",
  "SetSystemPowerState",
  "SetSystemTime",
  "SetSystemTimeAdjustment",
  "SetTapeParameters",
  "SetTapePosition",
  "SetTermsrvAppInstallMode",
  "SetThreadAffinityMask",
  "SetThreadDescription",
  "SetThreadErrorMode",
  "SetThreadExecutionState",
  "SetThreadGroupAffinity",
  "SetThreadIdealProcessor",
  "SetThreadIdealProcessorEx",
  "SetThreadInformation",
  "SetThreadLocale",
  "SetThreadPreferredUILanguages",
  "SetThreadPriority",
  "SetThreadPriorityBoost",
  "SetThreadSelectedCpuSets",
  "SetThreadStackGuarantee",
  "SetThreadToken",
  "SetThreadUILanguage",
  "SetThreadpoolStackInformation",
  "SetThreadpoolThreadMaximum",
  "SetThreadpoolThreadMinimum",
  "SetThreadpoolTimer",
  "SetThreadpoolTimerEx",
  "SetThreadpoolWait",
  "SetThreadpoolWaitEx",
  "SetTimeZoneInformation",
  "SetTimerQueueTimer",
  "SetUmsThreadInformation",
  "SetUnhandledExceptionFilter",
  "SetUserGeoID",
  "SetUserGeoName",
  "SetVolumeLabelA",
  "SetVolumeLabelW",
  "SetVolumeMountPointA",
  "SetVolumeMountPointW",
  "SetWaitableTimer",
  "SetWaitableTimerEx",
  "SetXStateFeaturesMask",
  "SetupComm",
  "SignalObjectAndWait",
  "SizeofResource",
  "Sleep",
  "SleepConditionVariableCS",
  "SleepConditionVariableSRW",
  "SleepEx",
  "StartThreadpoolIo",
  "SubmitThreadpoolWork",
  "SuspendThread",
  "SwitchToFiber",
  "SwitchToThread",
  "SystemTimeToFileTime",
  "SystemTimeToTzSpecificLocalTime",
  "SystemTimeToTzSpecificLocalTimeEx",
  "TerminateJobObject",
  "TerminateProcess",
  "TerminateThread",
  "Thread32First",
  "Thread32Next",
  "TlsAlloc",
  "TlsFree",
  "TlsGetValue",
  "TlsSetValue",
  "Toolhelp32ReadProcessMemory",
  "TransactNamedPipe",
  "TransmitCommChar",
  "TryAcquireSRWLockExclusive",
  "TryAcquireSRWLockShared",
  "TryEnterCriticalSection",
  "TrySubmitThreadpoolCallback",
  "TzSpecificLocalTimeToSystemTime",
  "TzSpecificLocalTimeToSystemTimeEx",
  "UmsThreadYield",
  "UnhandledExceptionFilter",
  "UnlockFile",
  "UnlockFileEx",
  "UnmapViewOfFile",
  "UnmapViewOfFileEx",
  "UnregisterApplicationRecoveryCallback",
  "UnregisterApplicationRestart",
  "UnregisterBadMemoryNotification",
  "UnregisterWait",
  "UnregisterWaitEx",
  "UnregisterWaitUntilOOBECompleted",
  "UpdateCalendarDayOfWeek",
  "UpdateProcThreadAttribute",
  "UpdateResourceA",
  "UpdateResourceW",
  "VerLanguageNameA",
  "VerLanguageNameW",
  "VerSetConditionMask",
  "VerifyConsoleIoHandle",
  "VerifyVersionInfoA",
  "VerifyVersionInfoW",
  "VirtualAlloc",
  "VirtualAllocEx",
  "VirtualAllocExNuma",
  "VirtualFree",
  "VirtualFreeEx",
  "VirtualLock",
  "VirtualProtect",
  "VirtualProtectEx",
  "VirtualQuery",
  "VirtualQueryEx",
  "VirtualUnlock",
  "WTSGetActiveConsoleSessionId",
  "WaitCommEvent",
  "WaitForDebugEvent",
  "WaitForDebugEventEx",
  "WaitForMultipleObjects",
  "WaitForMultipleObjectsEx",
  "WaitForSingleObject",
  "WaitForSingleObjectEx",
  "WaitForThreadpoolIoCallbacks",
  "WaitForThreadpoolTimerCallbacks",
  "WaitForThreadpoolWaitCallbacks",
  "WaitForThreadpoolWorkCallbacks",
  "WaitNamedPipeA",
  "WaitNamedPipeW",
  "WakeAllConditionVariable",
  "WakeConditionVariable",
  "WerGetFlags",
  "WerRegisterAdditionalProcess",
  "WerRegisterAppLocalDump",
  "WerRegisterCustomMetadata",
  "WerRegisterExcludedMemoryBlock",
  "WerRegisterFile",
  "WerRegisterMemoryBlock",
  "WerRegisterRuntimeExceptionModule",
  "WerSetFlags",
  "WerUnregisterAdditionalProcess",
  "WerUnregisterAppLocalDump",
  "WerUnregisterCustomMetadata",
  "WerUnregisterExcludedMemoryBlock",
  "WerUnregisterFile",
  "WerUnregisterMemoryBlock",
  "WerUnregisterRuntimeExceptionModule",
  "WideCharToMultiByte",
  "WinExec",
  "Wow64DisableWow64FsRedirection",
  "Wow64EnableWow64FsRedirection",
  "Wow64GetThreadContext",
  "Wow64GetThreadSelectorEntry",
  "Wow64RevertWow64FsRedirection",
  "Wow64SetThreadContext",
  "Wow64SuspendThread",
  "WriteConsoleA",
  "WriteConsoleInputA",
  "WriteConsoleInputW",
  "WriteConsoleOutputA",
  "WriteConsoleOutputAttribute",
  "WriteConsoleOutputCharacterA",
  "WriteConsoleOutputCharacterW",
  "WriteConsoleOutputW",
  "WriteConsoleW",
  "WriteFile",
  "WriteFileEx",
  "WriteFileGather",
  "WritePrivateProfileSectionA",
  "WritePrivateProfileSectionW",
  "WritePrivateProfileStringA",
  "WritePrivateProfileStringW",
  "WritePrivateProfileStructA",
  "WritePrivateProfileStructW",
  "WriteProcessMemory",
  "WriteProfileSectionA",
  "WriteProfileSectionW",
  "WriteProfileStringA",
  "WriteProfileStringW",
  "WriteTapemark",
  "ZombifyActCtx",
  "lstrcatA",
  "lstrcatW",
  "lstrcmpA",
  "lstrcmpW",
  "lstrcmpiA",
  "lstrcmpiW",
  "lstrcpyA",
  "lstrcpyW",
  "lstrcpynA",
  "lstrcpynW",
  "lstrlenA",
  "lstrlenW",
  "timeBeginPeriod",
  "timeEndPeriod",
  "timeGetDevCaps",
  "timeGetSystemTime",
  "timeGetTime" 
};

std::unordered_map<std::string, FARPROC> _funcHooksMap = {
  {
    "AcquireSRWLockExclusive",
    reinterpret_cast<FARPROC>(MyAcquireSRWLockExclusive),
  },
  {
    "AcquireSRWLockShared",
    reinterpret_cast<FARPROC>(MyAcquireSRWLockShared),
  },
  {
    "ActivateActCtx",
    reinterpret_cast<FARPROC>(MyActivateActCtx),
  },
  {
    "AddAtomA",
    reinterpret_cast<FARPROC>(MyAddAtomA),
  },
  {
    "AddAtomW",
    reinterpret_cast<FARPROC>(MyAddAtomW),
  },
  {
    "AddConsoleAliasA",
    reinterpret_cast<FARPROC>(MyAddConsoleAliasA),
  },
  {
    "AddConsoleAliasW",
    reinterpret_cast<FARPROC>(MyAddConsoleAliasW),
  },
  {
    "AddDllDirectory",
    reinterpret_cast<FARPROC>(MyAddDllDirectory),
  },
  {
    "AddIntegrityLabelToBoundaryDescriptor",
    reinterpret_cast<FARPROC>(MyAddIntegrityLabelToBoundaryDescriptor),
  },
  {
    "AddLocalAlternateComputerNameA",
    reinterpret_cast<FARPROC>(MyAddLocalAlternateComputerNameA),
  },
  {
    "AddLocalAlternateComputerNameW",
    reinterpret_cast<FARPROC>(MyAddLocalAlternateComputerNameW),
  },
  {
    "AddRefActCtx",
    reinterpret_cast<FARPROC>(MyAddRefActCtx),
  },
  {
    "AddResourceAttributeAce",
    reinterpret_cast<FARPROC>(MyAddResourceAttributeAce),
  },
  {
    "AddSIDToBoundaryDescriptor",
    reinterpret_cast<FARPROC>(MyAddSIDToBoundaryDescriptor),
  },
  {
    "AddSecureMemoryCacheCallback",
    reinterpret_cast<FARPROC>(MyAddSecureMemoryCacheCallback),
  },
  {
    "AddVectoredContinueHandler",
    reinterpret_cast<FARPROC>(MyAddVectoredContinueHandler),
  },
  {
    "AddVectoredExceptionHandler",
    reinterpret_cast<FARPROC>(MyAddVectoredExceptionHandler),
  },
  {
    "AllocConsole",
    reinterpret_cast<FARPROC>(MyAllocConsole),
  },
  {
    "AllocateUserPhysicalPages",
    reinterpret_cast<FARPROC>(MyAllocateUserPhysicalPages),
  },
  {
    "AllocateUserPhysicalPagesNuma",
    reinterpret_cast<FARPROC>(MyAllocateUserPhysicalPagesNuma),
  },
  {
    "AppPolicyGetClrCompat",
    reinterpret_cast<FARPROC>(MyAppPolicyGetClrCompat),
  },
  {
    "AppPolicyGetMediaFoundationCodecLoading",
    reinterpret_cast<FARPROC>(MyAppPolicyGetMediaFoundationCodecLoading),
  },
  {
    "AppPolicyGetProcessTerminationMethod",
    reinterpret_cast<FARPROC>(MyAppPolicyGetProcessTerminationMethod),
  },
  {
    "AppPolicyGetThreadInitializationType",
    reinterpret_cast<FARPROC>(MyAppPolicyGetThreadInitializationType),
  },
  {
    "AppPolicyGetWindowingModel",
    reinterpret_cast<FARPROC>(MyAppPolicyGetWindowingModel),
  },
  {
    "ApplicationRecoveryFinished",
    reinterpret_cast<FARPROC>(MyApplicationRecoveryFinished),
  },
  {
    "ApplicationRecoveryInProgress",
    reinterpret_cast<FARPROC>(MyApplicationRecoveryInProgress),
  },
  {
    "AreFileApisANSI",
    reinterpret_cast<FARPROC>(MyAreFileApisANSI),
  },
  {
    "AssignProcessToJobObject",
    reinterpret_cast<FARPROC>(MyAssignProcessToJobObject),
  },
  {
    "AttachConsole",
    reinterpret_cast<FARPROC>(MyAttachConsole),
  },
  {
    "BackupRead",
    reinterpret_cast<FARPROC>(MyBackupRead),
  },
  {
    "BackupSeek",
    reinterpret_cast<FARPROC>(MyBackupSeek),
  },
  {
    "BackupWrite",
    reinterpret_cast<FARPROC>(MyBackupWrite),
  },
  {
    "BaseFlushAppcompatCache",
    reinterpret_cast<FARPROC>(MyBaseFlushAppcompatCache),
  },
  {
    "Beep",
    reinterpret_cast<FARPROC>(MyBeep),
  },
  {
    "BeginUpdateResourceA",
    reinterpret_cast<FARPROC>(MyBeginUpdateResourceA),
  },
  {
    "BeginUpdateResourceW",
    reinterpret_cast<FARPROC>(MyBeginUpdateResourceW),
  },
  {
    "BindIoCompletionCallback",
    reinterpret_cast<FARPROC>(MyBindIoCompletionCallback),
  },
  {
    "BuildCommDCBA",
    reinterpret_cast<FARPROC>(MyBuildCommDCBA),
  },
  {
    "BuildCommDCBAndTimeoutsA",
    reinterpret_cast<FARPROC>(MyBuildCommDCBAndTimeoutsA),
  },
  {
    "BuildCommDCBAndTimeoutsW",
    reinterpret_cast<FARPROC>(MyBuildCommDCBAndTimeoutsW),
  },
  {
    "BuildCommDCBW",
    reinterpret_cast<FARPROC>(MyBuildCommDCBW),
  },
  {
    "CallNamedPipeA",
    reinterpret_cast<FARPROC>(MyCallNamedPipeA),
  },
  {
    "CallNamedPipeW",
    reinterpret_cast<FARPROC>(MyCallNamedPipeW),
  },
  {
    "CallbackMayRunLong",
    reinterpret_cast<FARPROC>(MyCallbackMayRunLong),
  },
  {
    "CancelIo",
    reinterpret_cast<FARPROC>(MyCancelIo),
  },
  {
    "CancelIoEx",
    reinterpret_cast<FARPROC>(MyCancelIoEx),
  },
  {
    "CancelSynchronousIo",
    reinterpret_cast<FARPROC>(MyCancelSynchronousIo),
  },
  {
    "CancelThreadpoolIo",
    reinterpret_cast<FARPROC>(MyCancelThreadpoolIo),
  },
  {
    "CancelWaitableTimer",
    reinterpret_cast<FARPROC>(MyCancelWaitableTimer),
  },
  {
    "CeipIsOptedIn",
    reinterpret_cast<FARPROC>(MyCeipIsOptedIn),
  },
  {
    "ChangeTimerQueueTimer",
    reinterpret_cast<FARPROC>(MyChangeTimerQueueTimer),
  },
  {
    "CheckNameLegalDOS8Dot3A",
    reinterpret_cast<FARPROC>(MyCheckNameLegalDOS8Dot3A),
  },
  {
    "CheckNameLegalDOS8Dot3W",
    reinterpret_cast<FARPROC>(MyCheckNameLegalDOS8Dot3W),
  },
  {
    "CheckRemoteDebuggerPresent",
    reinterpret_cast<FARPROC>(MyCheckRemoteDebuggerPresent),
  },
  {
    "CheckTokenCapability",
    reinterpret_cast<FARPROC>(MyCheckTokenCapability),
  },
  {
    "CheckTokenMembershipEx",
    reinterpret_cast<FARPROC>(MyCheckTokenMembershipEx),
  },
  {
    "ClearCommBreak",
    reinterpret_cast<FARPROC>(MyClearCommBreak),
  },
  {
    "ClearCommError",
    reinterpret_cast<FARPROC>(MyClearCommError),
  },
  {
    "CloseHandle",
    reinterpret_cast<FARPROC>(MyCloseHandle),
  },
  {
    "ClosePackageInfo",
    reinterpret_cast<FARPROC>(MyClosePackageInfo),
  },
  {
    "ClosePrivateNamespace",
    reinterpret_cast<FARPROC>(MyClosePrivateNamespace),
  },
  {
    "ClosePseudoConsole",
    reinterpret_cast<FARPROC>(MyClosePseudoConsole),
  },
  {
    "CloseThreadpool",
    reinterpret_cast<FARPROC>(MyCloseThreadpool),
  },
  {
    "CloseThreadpoolCleanupGroup",
    reinterpret_cast<FARPROC>(MyCloseThreadpoolCleanupGroup),
  },
  {
    "CloseThreadpoolCleanupGroupMembers",
    reinterpret_cast<FARPROC>(MyCloseThreadpoolCleanupGroupMembers),
  },
  {
    "CloseThreadpoolIo",
    reinterpret_cast<FARPROC>(MyCloseThreadpoolIo),
  },
  {
    "CloseThreadpoolTimer",
    reinterpret_cast<FARPROC>(MyCloseThreadpoolTimer),
  },
  {
    "CloseThreadpoolWait",
    reinterpret_cast<FARPROC>(MyCloseThreadpoolWait),
  },
  {
    "CloseThreadpoolWork",
    reinterpret_cast<FARPROC>(MyCloseThreadpoolWork),
  },
  {
    "CommConfigDialogA",
    reinterpret_cast<FARPROC>(MyCommConfigDialogA),
  },
  {
    "CommConfigDialogW",
    reinterpret_cast<FARPROC>(MyCommConfigDialogW),
  },
  {
    "CompareFileTime",
    reinterpret_cast<FARPROC>(MyCompareFileTime),
  },
  {
    "CompareStringA",
    reinterpret_cast<FARPROC>(MyCompareStringA),
  },
  {
    "CompareStringEx",
    reinterpret_cast<FARPROC>(MyCompareStringEx),
  },
  {
    "CompareStringOrdinal",
    reinterpret_cast<FARPROC>(MyCompareStringOrdinal),
  },
  {
    "CompareStringW",
    reinterpret_cast<FARPROC>(MyCompareStringW),
  },
  {
    "ConnectNamedPipe",
    reinterpret_cast<FARPROC>(MyConnectNamedPipe),
  },
  {
    "ContinueDebugEvent",
    reinterpret_cast<FARPROC>(MyContinueDebugEvent),
  },
  {
    "ConvertDefaultLocale",
    reinterpret_cast<FARPROC>(MyConvertDefaultLocale),
  },
  {
    "ConvertFiberToThread",
    reinterpret_cast<FARPROC>(MyConvertFiberToThread),
  },
  {
    "ConvertThreadToFiber",
    reinterpret_cast<FARPROC>(MyConvertThreadToFiber),
  },
  {
    "ConvertThreadToFiberEx",
    reinterpret_cast<FARPROC>(MyConvertThreadToFiberEx),
  },
  {
    "CopyContext",
    reinterpret_cast<FARPROC>(MyCopyContext),
  },
  {
    "CopyFile2",
    reinterpret_cast<FARPROC>(MyCopyFile2),
  },
  {
    "CopyFileA",
    reinterpret_cast<FARPROC>(MyCopyFileA),
  },
  {
    "CopyFileExA",
    reinterpret_cast<FARPROC>(MyCopyFileExA),
  },
  {
    "CopyFileExW",
    reinterpret_cast<FARPROC>(MyCopyFileExW),
  },
  {
    "CopyFileTransactedA",
    reinterpret_cast<FARPROC>(MyCopyFileTransactedA),
  },
  {
    "CopyFileTransactedW",
    reinterpret_cast<FARPROC>(MyCopyFileTransactedW),
  },
  {
    "CopyFileW",
    reinterpret_cast<FARPROC>(MyCopyFileW),
  },
  {
    "CreateActCtxA",
    reinterpret_cast<FARPROC>(MyCreateActCtxA),
  },
  {
    "CreateActCtxW",
    reinterpret_cast<FARPROC>(MyCreateActCtxW),
  },
  {
    "CreateBoundaryDescriptorA",
    reinterpret_cast<FARPROC>(MyCreateBoundaryDescriptorA),
  },
  {
    "CreateBoundaryDescriptorW",
    reinterpret_cast<FARPROC>(MyCreateBoundaryDescriptorW),
  },
  {
    "CreateConsoleScreenBuffer",
    reinterpret_cast<FARPROC>(MyCreateConsoleScreenBuffer),
  },
  {
    "CreateDirectoryA",
    reinterpret_cast<FARPROC>(MyCreateDirectoryA),
  },
  {
    "CreateDirectoryExA",
    reinterpret_cast<FARPROC>(MyCreateDirectoryExA),
  },
  {
    "CreateDirectoryExW",
    reinterpret_cast<FARPROC>(MyCreateDirectoryExW),
  },
  {
    "CreateDirectoryTransactedA",
    reinterpret_cast<FARPROC>(MyCreateDirectoryTransactedA),
  },
  {
    "CreateDirectoryTransactedW",
    reinterpret_cast<FARPROC>(MyCreateDirectoryTransactedW),
  },
  {
    "CreateDirectoryW",
    reinterpret_cast<FARPROC>(MyCreateDirectoryW),
  },
  {
    "CreateEnclave",
    reinterpret_cast<FARPROC>(MyCreateEnclave),
  },
  {
    "CreateEventA",
    reinterpret_cast<FARPROC>(MyCreateEventA),
  },
  {
    "CreateEventExA",
    reinterpret_cast<FARPROC>(MyCreateEventExA),
  },
  {
    "CreateEventExW",
    reinterpret_cast<FARPROC>(MyCreateEventExW),
  },
  {
    "CreateEventW",
    reinterpret_cast<FARPROC>(MyCreateEventW),
  },
  {
    "CreateFiber",
    reinterpret_cast<FARPROC>(MyCreateFiber),
  },
  {
    "CreateFiberEx",
    reinterpret_cast<FARPROC>(MyCreateFiberEx),
  },
  {
    "CreateFile2",
    reinterpret_cast<FARPROC>(MyCreateFile2),
  },
  {
    "CreateFileA",
    reinterpret_cast<FARPROC>(MyCreateFileA),
  },
  {
    "CreateFileMappingA",
    reinterpret_cast<FARPROC>(MyCreateFileMappingA),
  },
  {
    "CreateFileMappingFromApp",
    reinterpret_cast<FARPROC>(MyCreateFileMappingFromApp),
  },
  {
    "CreateFileMappingNumaA",
    reinterpret_cast<FARPROC>(MyCreateFileMappingNumaA),
  },
  {
    "CreateFileMappingNumaW",
    reinterpret_cast<FARPROC>(MyCreateFileMappingNumaW),
  },
  {
    "CreateFileMappingW",
    reinterpret_cast<FARPROC>(MyCreateFileMappingW),
  },
  {
    "CreateFileTransactedA",
    reinterpret_cast<FARPROC>(MyCreateFileTransactedA),
  },
  {
    "CreateFileTransactedW",
    reinterpret_cast<FARPROC>(MyCreateFileTransactedW),
  },
  {
    "CreateFileW",
    reinterpret_cast<FARPROC>(MyCreateFileW),
  },
  {
    "CreateHardLinkA",
    reinterpret_cast<FARPROC>(MyCreateHardLinkA),
  },
  {
    "CreateHardLinkTransactedA",
    reinterpret_cast<FARPROC>(MyCreateHardLinkTransactedA),
  },
  {
    "CreateHardLinkTransactedW",
    reinterpret_cast<FARPROC>(MyCreateHardLinkTransactedW),
  },
  {
    "CreateHardLinkW",
    reinterpret_cast<FARPROC>(MyCreateHardLinkW),
  },
  {
    "CreateIoCompletionPort",
    reinterpret_cast<FARPROC>(MyCreateIoCompletionPort),
  },
  {
    "CreateJobObjectA",
    reinterpret_cast<FARPROC>(MyCreateJobObjectA),
  },
  {
    "CreateJobObjectW",
    reinterpret_cast<FARPROC>(MyCreateJobObjectW),
  },
  {
    "CreateMailslotA",
    reinterpret_cast<FARPROC>(MyCreateMailslotA),
  },
  {
    "CreateMailslotW",
    reinterpret_cast<FARPROC>(MyCreateMailslotW),
  },
  {
    "CreateMemoryResourceNotification",
    reinterpret_cast<FARPROC>(MyCreateMemoryResourceNotification),
  },
  {
    "CreateMutexA",
    reinterpret_cast<FARPROC>(MyCreateMutexA),
  },
  {
    "CreateMutexExA",
    reinterpret_cast<FARPROC>(MyCreateMutexExA),
  },
  {
    "CreateMutexExW",
    reinterpret_cast<FARPROC>(MyCreateMutexExW),
  },
  {
    "CreateMutexW",
    reinterpret_cast<FARPROC>(MyCreateMutexW),
  },
  {
    "CreateNamedPipeA",
    reinterpret_cast<FARPROC>(MyCreateNamedPipeA),
  },
  {
    "CreateNamedPipeW",
    reinterpret_cast<FARPROC>(MyCreateNamedPipeW),
  },
  {
    "CreatePipe",
    reinterpret_cast<FARPROC>(MyCreatePipe),
  },
  {
    "CreatePrivateNamespaceA",
    reinterpret_cast<FARPROC>(MyCreatePrivateNamespaceA),
  },
  {
    "CreatePrivateNamespaceW",
    reinterpret_cast<FARPROC>(MyCreatePrivateNamespaceW),
  },
  {
    "CreateProcessA",
    reinterpret_cast<FARPROC>(MyCreateProcessA),
  },
  {
    "CreateProcessAsUserA",
    reinterpret_cast<FARPROC>(MyCreateProcessAsUserA),
  },
  {
    "CreateProcessAsUserW",
    reinterpret_cast<FARPROC>(MyCreateProcessAsUserW),
  },
  {
    "CreateProcessW",
    reinterpret_cast<FARPROC>(MyCreateProcessW),
  },
  {
    "CreatePseudoConsole",
    reinterpret_cast<FARPROC>(MyCreatePseudoConsole),
  },
  {
    "CreateRemoteThread",
    reinterpret_cast<FARPROC>(MyCreateRemoteThread),
  },
  {
    "CreateRemoteThreadEx",
    reinterpret_cast<FARPROC>(MyCreateRemoteThreadEx),
  },
  {
    "CreateSemaphoreA",
    reinterpret_cast<FARPROC>(MyCreateSemaphoreA),
  },
  {
    "CreateSemaphoreExA",
    reinterpret_cast<FARPROC>(MyCreateSemaphoreExA),
  },
  {
    "CreateSemaphoreExW",
    reinterpret_cast<FARPROC>(MyCreateSemaphoreExW),
  },
  {
    "CreateSemaphoreW",
    reinterpret_cast<FARPROC>(MyCreateSemaphoreW),
  },
  {
    "CreateSymbolicLinkA",
    reinterpret_cast<FARPROC>(MyCreateSymbolicLinkA),
  },
  {
    "CreateSymbolicLinkTransactedA",
    reinterpret_cast<FARPROC>(MyCreateSymbolicLinkTransactedA),
  },
  {
    "CreateSymbolicLinkTransactedW",
    reinterpret_cast<FARPROC>(MyCreateSymbolicLinkTransactedW),
  },
  {
    "CreateSymbolicLinkW",
    reinterpret_cast<FARPROC>(MyCreateSymbolicLinkW),
  },
  {
    "CreateTapePartition",
    reinterpret_cast<FARPROC>(MyCreateTapePartition),
  },
  {
    "CreateThread",
    reinterpret_cast<FARPROC>(MyCreateThread),
  },
  {
    "CreateThreadpool",
    reinterpret_cast<FARPROC>(MyCreateThreadpool),
  },
  {
    "CreateThreadpoolCleanupGroup",
    reinterpret_cast<FARPROC>(MyCreateThreadpoolCleanupGroup),
  },
  {
    "CreateThreadpoolIo",
    reinterpret_cast<FARPROC>(MyCreateThreadpoolIo),
  },
  {
    "CreateThreadpoolTimer",
    reinterpret_cast<FARPROC>(MyCreateThreadpoolTimer),
  },
  {
    "CreateThreadpoolWait",
    reinterpret_cast<FARPROC>(MyCreateThreadpoolWait),
  },
  {
    "CreateThreadpoolWork",
    reinterpret_cast<FARPROC>(MyCreateThreadpoolWork),
  },
  {
    "CreateTimerQueue",
    reinterpret_cast<FARPROC>(MyCreateTimerQueue),
  },
  {
    "CreateTimerQueueTimer",
    reinterpret_cast<FARPROC>(MyCreateTimerQueueTimer),
  },
  {
    "CreateToolhelp32Snapshot",
    reinterpret_cast<FARPROC>(MyCreateToolhelp32Snapshot),
  },
  {
    "CreateUmsCompletionList",
    reinterpret_cast<FARPROC>(MyCreateUmsCompletionList),
  },
  {
    "CreateUmsThreadContext",
    reinterpret_cast<FARPROC>(MyCreateUmsThreadContext),
  },
  {
    "CreateWaitableTimerA",
    reinterpret_cast<FARPROC>(MyCreateWaitableTimerA),
  },
  {
    "CreateWaitableTimerExA",
    reinterpret_cast<FARPROC>(MyCreateWaitableTimerExA),
  },
  {
    "CreateWaitableTimerExW",
    reinterpret_cast<FARPROC>(MyCreateWaitableTimerExW),
  },
  {
    "CreateWaitableTimerW",
    reinterpret_cast<FARPROC>(MyCreateWaitableTimerW),
  },
  {
    "DeactivateActCtx",
    reinterpret_cast<FARPROC>(MyDeactivateActCtx),
  },
  {
    "DebugBreak",
    reinterpret_cast<FARPROC>(MyDebugBreak),
  },
  {
    "DebugBreakProcess",
    reinterpret_cast<FARPROC>(MyDebugBreakProcess),
  },
  {
    "DebugSetProcessKillOnExit",
    reinterpret_cast<FARPROC>(MyDebugSetProcessKillOnExit),
  },
  {
    "DecodePointer",
    reinterpret_cast<FARPROC>(MyDecodePointer),
  },
  {
    "DecodeSystemPointer",
    reinterpret_cast<FARPROC>(MyDecodeSystemPointer),
  },
  {
    "DefineDosDeviceA",
    reinterpret_cast<FARPROC>(MyDefineDosDeviceA),
  },
  {
    "DefineDosDeviceW",
    reinterpret_cast<FARPROC>(MyDefineDosDeviceW),
  },
  {
    "DelayLoadFailureHook",
    reinterpret_cast<FARPROC>(MyDelayLoadFailureHook),
  },
  {
    "DeleteAtom",
    reinterpret_cast<FARPROC>(MyDeleteAtom),
  },
  {
    "DeleteBoundaryDescriptor",
    reinterpret_cast<FARPROC>(MyDeleteBoundaryDescriptor),
  },
  {
    "DeleteCriticalSection",
    reinterpret_cast<FARPROC>(MyDeleteCriticalSection),
  },
  {
    "DeleteFiber",
    reinterpret_cast<FARPROC>(MyDeleteFiber),
  },
  {
    "DeleteFileA",
    reinterpret_cast<FARPROC>(MyDeleteFileA),
  },
  {
    "DeleteFileTransactedA",
    reinterpret_cast<FARPROC>(MyDeleteFileTransactedA),
  },
  {
    "DeleteFileTransactedW",
    reinterpret_cast<FARPROC>(MyDeleteFileTransactedW),
  },
  {
    "DeleteFileW",
    reinterpret_cast<FARPROC>(MyDeleteFileW),
  },
  {
    "DeleteProcThreadAttributeList",
    reinterpret_cast<FARPROC>(MyDeleteProcThreadAttributeList),
  },
  {
    "DeleteSynchronizationBarrier",
    reinterpret_cast<FARPROC>(MyDeleteSynchronizationBarrier),
  },
  {
    "DeleteTimerQueue",
    reinterpret_cast<FARPROC>(MyDeleteTimerQueue),
  },
  {
    "DeleteTimerQueueEx",
    reinterpret_cast<FARPROC>(MyDeleteTimerQueueEx),
  },
  {
    "DeleteTimerQueueTimer",
    reinterpret_cast<FARPROC>(MyDeleteTimerQueueTimer),
  },
  {
    "DeleteUmsCompletionList",
    reinterpret_cast<FARPROC>(MyDeleteUmsCompletionList),
  },
  {
    "DeleteUmsThreadContext",
    reinterpret_cast<FARPROC>(MyDeleteUmsThreadContext),
  },
  {
    "DeleteVolumeMountPointA",
    reinterpret_cast<FARPROC>(MyDeleteVolumeMountPointA),
  },
  {
    "DeleteVolumeMountPointW",
    reinterpret_cast<FARPROC>(MyDeleteVolumeMountPointW),
  },
  {
    "DequeueUmsCompletionListItems",
    reinterpret_cast<FARPROC>(MyDequeueUmsCompletionListItems),
  },
  {
    "DeviceIoControl",
    reinterpret_cast<FARPROC>(MyDeviceIoControl),
  },
  {
    "DisableThreadLibraryCalls",
    reinterpret_cast<FARPROC>(MyDisableThreadLibraryCalls),
  },
  {
    "DisableThreadProfiling",
    reinterpret_cast<FARPROC>(MyDisableThreadProfiling),
  },
  {
    "DisassociateCurrentThreadFromCallback",
    reinterpret_cast<FARPROC>(MyDisassociateCurrentThreadFromCallback),
  },
  {
    "DiscardVirtualMemory",
    reinterpret_cast<FARPROC>(MyDiscardVirtualMemory),
  },
  {
    "DisconnectNamedPipe",
    reinterpret_cast<FARPROC>(MyDisconnectNamedPipe),
  },
  {
    "DnsHostnameToComputerNameA",
    reinterpret_cast<FARPROC>(MyDnsHostnameToComputerNameA),
  },
  {
    "DnsHostnameToComputerNameW",
    reinterpret_cast<FARPROC>(MyDnsHostnameToComputerNameW),
  },
  {
    "DosDateTimeToFileTime",
    reinterpret_cast<FARPROC>(MyDosDateTimeToFileTime),
  },
  {
    "DuplicateHandle",
    reinterpret_cast<FARPROC>(MyDuplicateHandle),
  },
  {
    "EnableThreadProfiling",
    reinterpret_cast<FARPROC>(MyEnableThreadProfiling),
  },
  {
    "EncodePointer",
    reinterpret_cast<FARPROC>(MyEncodePointer),
  },
  {
    "EncodeSystemPointer",
    reinterpret_cast<FARPROC>(MyEncodeSystemPointer),
  },
  {
    "EndUpdateResourceA",
    reinterpret_cast<FARPROC>(MyEndUpdateResourceA),
  },
  {
    "EndUpdateResourceW",
    reinterpret_cast<FARPROC>(MyEndUpdateResourceW),
  },
  {
    "EnterCriticalSection",
    reinterpret_cast<FARPROC>(MyEnterCriticalSection),
  },
  {
    "EnterSynchronizationBarrier",
    reinterpret_cast<FARPROC>(MyEnterSynchronizationBarrier),
  },
  {
    "EnterUmsSchedulingMode",
    reinterpret_cast<FARPROC>(MyEnterUmsSchedulingMode),
  },
  {
    "EnumCalendarInfoA",
    reinterpret_cast<FARPROC>(MyEnumCalendarInfoA),
  },
  {
    "EnumCalendarInfoExA",
    reinterpret_cast<FARPROC>(MyEnumCalendarInfoExA),
  },
  {
    "EnumCalendarInfoExEx",
    reinterpret_cast<FARPROC>(MyEnumCalendarInfoExEx),
  },
  {
    "EnumCalendarInfoExW",
    reinterpret_cast<FARPROC>(MyEnumCalendarInfoExW),
  },
  {
    "EnumCalendarInfoW",
    reinterpret_cast<FARPROC>(MyEnumCalendarInfoW),
  },
  {
    "EnumDateFormatsA",
    reinterpret_cast<FARPROC>(MyEnumDateFormatsA),
  },
  {
    "EnumDateFormatsExA",
    reinterpret_cast<FARPROC>(MyEnumDateFormatsExA),
  },
  {
    "EnumDateFormatsExEx",
    reinterpret_cast<FARPROC>(MyEnumDateFormatsExEx),
  },
  {
    "EnumDateFormatsExW",
    reinterpret_cast<FARPROC>(MyEnumDateFormatsExW),
  },
  {
    "EnumDateFormatsW",
    reinterpret_cast<FARPROC>(MyEnumDateFormatsW),
  },
  {
    "EnumLanguageGroupLocalesA",
    reinterpret_cast<FARPROC>(MyEnumLanguageGroupLocalesA),
  },
  {
    "EnumLanguageGroupLocalesW",
    reinterpret_cast<FARPROC>(MyEnumLanguageGroupLocalesW),
  },
  {
    "EnumResourceLanguagesA",
    reinterpret_cast<FARPROC>(MyEnumResourceLanguagesA),
  },
  {
    "EnumResourceLanguagesExA",
    reinterpret_cast<FARPROC>(MyEnumResourceLanguagesExA),
  },
  {
    "EnumResourceLanguagesExW",
    reinterpret_cast<FARPROC>(MyEnumResourceLanguagesExW),
  },
  {
    "EnumResourceLanguagesW",
    reinterpret_cast<FARPROC>(MyEnumResourceLanguagesW),
  },
  {
    "EnumResourceNamesA",
    reinterpret_cast<FARPROC>(MyEnumResourceNamesA),
  },
  {
    "EnumResourceNamesExA",
    reinterpret_cast<FARPROC>(MyEnumResourceNamesExA),
  },
  {
    "EnumResourceNamesExW",
    reinterpret_cast<FARPROC>(MyEnumResourceNamesExW),
  },
  {
    "EnumResourceNamesW",
    reinterpret_cast<FARPROC>(MyEnumResourceNamesW),
  },
  {
    "EnumResourceTypesA",
    reinterpret_cast<FARPROC>(MyEnumResourceTypesA),
  },
  {
    "EnumResourceTypesExA",
    reinterpret_cast<FARPROC>(MyEnumResourceTypesExA),
  },
  {
    "EnumResourceTypesExW",
    reinterpret_cast<FARPROC>(MyEnumResourceTypesExW),
  },
  {
    "EnumResourceTypesW",
    reinterpret_cast<FARPROC>(MyEnumResourceTypesW),
  },
  {
    "EnumSystemCodePagesA",
    reinterpret_cast<FARPROC>(MyEnumSystemCodePagesA),
  },
  {
    "EnumSystemCodePagesW",
    reinterpret_cast<FARPROC>(MyEnumSystemCodePagesW),
  },
  {
    "EnumSystemFirmwareTables",
    reinterpret_cast<FARPROC>(MyEnumSystemFirmwareTables),
  },
  {
    "EnumSystemGeoID",
    reinterpret_cast<FARPROC>(MyEnumSystemGeoID),
  },
  {
    "EnumSystemGeoNames",
    reinterpret_cast<FARPROC>(MyEnumSystemGeoNames),
  },
  {
    "EnumSystemLanguageGroupsA",
    reinterpret_cast<FARPROC>(MyEnumSystemLanguageGroupsA),
  },
  {
    "EnumSystemLanguageGroupsW",
    reinterpret_cast<FARPROC>(MyEnumSystemLanguageGroupsW),
  },
  {
    "EnumSystemLocalesA",
    reinterpret_cast<FARPROC>(MyEnumSystemLocalesA),
  },
  {
    "EnumSystemLocalesEx",
    reinterpret_cast<FARPROC>(MyEnumSystemLocalesEx),
  },
  {
    "EnumSystemLocalesW",
    reinterpret_cast<FARPROC>(MyEnumSystemLocalesW),
  },
  {
    "EnumTimeFormatsA",
    reinterpret_cast<FARPROC>(MyEnumTimeFormatsA),
  },
  {
    "EnumTimeFormatsEx",
    reinterpret_cast<FARPROC>(MyEnumTimeFormatsEx),
  },
  {
    "EnumTimeFormatsW",
    reinterpret_cast<FARPROC>(MyEnumTimeFormatsW),
  },
  {
    "EnumUILanguagesA",
    reinterpret_cast<FARPROC>(MyEnumUILanguagesA),
  },
  {
    "EnumUILanguagesW",
    reinterpret_cast<FARPROC>(MyEnumUILanguagesW),
  },
  {
    "EraseTape",
    reinterpret_cast<FARPROC>(MyEraseTape),
  },
  {
    "EscapeCommFunction",
    reinterpret_cast<FARPROC>(MyEscapeCommFunction),
  },
  {
    "ExecuteUmsThread",
    reinterpret_cast<FARPROC>(MyExecuteUmsThread),
  },
  {
    "ExitProcess",
    reinterpret_cast<FARPROC>(MyExitProcess),
  },
  {
    "ExitThread",
    reinterpret_cast<FARPROC>(MyExitThread),
  },
  {
    "ExpandEnvironmentStringsA",
    reinterpret_cast<FARPROC>(MyExpandEnvironmentStringsA),
  },
  {
    "ExpandEnvironmentStringsW",
    reinterpret_cast<FARPROC>(MyExpandEnvironmentStringsW),
  },
  {
    "FatalAppExitA",
    reinterpret_cast<FARPROC>(MyFatalAppExitA),
  },
  {
    "FatalAppExitW",
    reinterpret_cast<FARPROC>(MyFatalAppExitW),
  },
  {
    "FatalExit",
    reinterpret_cast<FARPROC>(MyFatalExit),
  },
  {
    "FileTimeToDosDateTime",
    reinterpret_cast<FARPROC>(MyFileTimeToDosDateTime),
  },
  {
    "FileTimeToLocalFileTime",
    reinterpret_cast<FARPROC>(MyFileTimeToLocalFileTime),
  },
  {
    "FileTimeToSystemTime",
    reinterpret_cast<FARPROC>(MyFileTimeToSystemTime),
  },
  {
    "FillConsoleOutputAttribute",
    reinterpret_cast<FARPROC>(MyFillConsoleOutputAttribute),
  },
  {
    "FillConsoleOutputCharacterA",
    reinterpret_cast<FARPROC>(MyFillConsoleOutputCharacterA),
  },
  {
    "FillConsoleOutputCharacterW",
    reinterpret_cast<FARPROC>(MyFillConsoleOutputCharacterW),
  },
  {
    "FindActCtxSectionGuid",
    reinterpret_cast<FARPROC>(MyFindActCtxSectionGuid),
  },
  {
    "FindActCtxSectionStringA",
    reinterpret_cast<FARPROC>(MyFindActCtxSectionStringA),
  },
  {
    "FindActCtxSectionStringW",
    reinterpret_cast<FARPROC>(MyFindActCtxSectionStringW),
  },
  {
    "FindAtomA",
    reinterpret_cast<FARPROC>(MyFindAtomA),
  },
  {
    "FindAtomW",
    reinterpret_cast<FARPROC>(MyFindAtomW),
  },
  {
    "FindClose",
    reinterpret_cast<FARPROC>(MyFindClose),
  },
  {
    "FindCloseChangeNotification",
    reinterpret_cast<FARPROC>(MyFindCloseChangeNotification),
  },
  {
    "FindFirstChangeNotificationA",
    reinterpret_cast<FARPROC>(MyFindFirstChangeNotificationA),
  },
  {
    "FindFirstChangeNotificationW",
    reinterpret_cast<FARPROC>(MyFindFirstChangeNotificationW),
  },
  {
    "FindFirstFileA",
    reinterpret_cast<FARPROC>(MyFindFirstFileA),
  },
  {
    "FindFirstFileExA",
    reinterpret_cast<FARPROC>(MyFindFirstFileExA),
  },
  {
    "FindFirstFileExW",
    reinterpret_cast<FARPROC>(MyFindFirstFileExW),
  },
  {
    "FindFirstFileNameTransactedW",
    reinterpret_cast<FARPROC>(MyFindFirstFileNameTransactedW),
  },
  {
    "FindFirstFileNameW",
    reinterpret_cast<FARPROC>(MyFindFirstFileNameW),
  },
  {
    "FindFirstFileTransactedA",
    reinterpret_cast<FARPROC>(MyFindFirstFileTransactedA),
  },
  {
    "FindFirstFileTransactedW",
    reinterpret_cast<FARPROC>(MyFindFirstFileTransactedW),
  },
  {
    "FindFirstFileW",
    reinterpret_cast<FARPROC>(MyFindFirstFileW),
  },
  {
    "FindFirstStreamTransactedW",
    reinterpret_cast<FARPROC>(MyFindFirstStreamTransactedW),
  },
  {
    "FindFirstStreamW",
    reinterpret_cast<FARPROC>(MyFindFirstStreamW),
  },
  {
    "FindFirstVolumeA",
    reinterpret_cast<FARPROC>(MyFindFirstVolumeA),
  },
  {
    "FindFirstVolumeMountPointA",
    reinterpret_cast<FARPROC>(MyFindFirstVolumeMountPointA),
  },
  {
    "FindFirstVolumeMountPointW",
    reinterpret_cast<FARPROC>(MyFindFirstVolumeMountPointW),
  },
  {
    "FindFirstVolumeW",
    reinterpret_cast<FARPROC>(MyFindFirstVolumeW),
  },
  {
    "FindNLSString",
    reinterpret_cast<FARPROC>(MyFindNLSString),
  },
  {
    "FindNLSStringEx",
    reinterpret_cast<FARPROC>(MyFindNLSStringEx),
  },
  {
    "FindNextChangeNotification",
    reinterpret_cast<FARPROC>(MyFindNextChangeNotification),
  },
  {
    "FindNextFileA",
    reinterpret_cast<FARPROC>(MyFindNextFileA),
  },
  {
    "FindNextFileNameW",
    reinterpret_cast<FARPROC>(MyFindNextFileNameW),
  },
  {
    "FindNextFileW",
    reinterpret_cast<FARPROC>(MyFindNextFileW),
  },
  {
    "FindNextStreamW",
    reinterpret_cast<FARPROC>(MyFindNextStreamW),
  },
  {
    "FindNextVolumeA",
    reinterpret_cast<FARPROC>(MyFindNextVolumeA),
  },
  {
    "FindNextVolumeMountPointA",
    reinterpret_cast<FARPROC>(MyFindNextVolumeMountPointA),
  },
  {
    "FindNextVolumeMountPointW",
    reinterpret_cast<FARPROC>(MyFindNextVolumeMountPointW),
  },
  {
    "FindNextVolumeW",
    reinterpret_cast<FARPROC>(MyFindNextVolumeW),
  },
  {
    "FindPackagesByPackageFamily",
    reinterpret_cast<FARPROC>(MyFindPackagesByPackageFamily),
  },
  {
    "FindResourceA",
    reinterpret_cast<FARPROC>(MyFindResourceA),
  },
  {
    "FindResourceExA",
    reinterpret_cast<FARPROC>(MyFindResourceExA),
  },
  {
    "FindResourceExW",
    reinterpret_cast<FARPROC>(MyFindResourceExW),
  },
  {
    "FindResourceW",
    reinterpret_cast<FARPROC>(MyFindResourceW),
  },
  {
    "FindStringOrdinal",
    reinterpret_cast<FARPROC>(MyFindStringOrdinal),
  },
  {
    "FindVolumeClose",
    reinterpret_cast<FARPROC>(MyFindVolumeClose),
  },
  {
    "FindVolumeMountPointClose",
    reinterpret_cast<FARPROC>(MyFindVolumeMountPointClose),
  },
  {
    "FlsAlloc",
    reinterpret_cast<FARPROC>(MyFlsAlloc),
  },
  {
    "FlsFree",
    reinterpret_cast<FARPROC>(MyFlsFree),
  },
  {
    "FlsGetValue",
    reinterpret_cast<FARPROC>(MyFlsGetValue),
  },
  {
    "FlsSetValue",
    reinterpret_cast<FARPROC>(MyFlsSetValue),
  },
  {
    "FlushConsoleInputBuffer",
    reinterpret_cast<FARPROC>(MyFlushConsoleInputBuffer),
  },
  {
    "FlushFileBuffers",
    reinterpret_cast<FARPROC>(MyFlushFileBuffers),
  },
  {
    "FlushInstructionCache",
    reinterpret_cast<FARPROC>(MyFlushInstructionCache),
  },
  {
    "FlushProcessWriteBuffers",
    reinterpret_cast<FARPROC>(MyFlushProcessWriteBuffers),
  },
  {
    "FlushViewOfFile",
    reinterpret_cast<FARPROC>(MyFlushViewOfFile),
  },
  {
    "FoldStringA",
    reinterpret_cast<FARPROC>(MyFoldStringA),
  },
  {
    "FoldStringW",
    reinterpret_cast<FARPROC>(MyFoldStringW),
  },
  {
    "FormatApplicationUserModelId",
    reinterpret_cast<FARPROC>(MyFormatApplicationUserModelId),
  },
  {
    "FormatMessageA",
    reinterpret_cast<FARPROC>(MyFormatMessageA),
  },
  {
    "FormatMessageW",
    reinterpret_cast<FARPROC>(MyFormatMessageW),
  },
  {
    "FreeConsole",
    reinterpret_cast<FARPROC>(MyFreeConsole),
  },
  {
    "FreeEnvironmentStringsA",
    reinterpret_cast<FARPROC>(MyFreeEnvironmentStringsA),
  },
  {
    "FreeEnvironmentStringsW",
    reinterpret_cast<FARPROC>(MyFreeEnvironmentStringsW),
  },
  {
    "FreeLibrary",
    reinterpret_cast<FARPROC>(MyFreeLibrary),
  },
  {
    "FreeLibraryAndExitThread",
    reinterpret_cast<FARPROC>(MyFreeLibraryAndExitThread),
  },
  {
    "FreeLibraryWhenCallbackReturns",
    reinterpret_cast<FARPROC>(MyFreeLibraryWhenCallbackReturns),
  },
  {
    "FreeMemoryJobObject",
    reinterpret_cast<FARPROC>(MyFreeMemoryJobObject),
  },
  {
    "FreeResource",
    reinterpret_cast<FARPROC>(MyFreeResource),
  },
  {
    "FreeUserPhysicalPages",
    reinterpret_cast<FARPROC>(MyFreeUserPhysicalPages),
  },
  {
    "GenerateConsoleCtrlEvent",
    reinterpret_cast<FARPROC>(MyGenerateConsoleCtrlEvent),
  },
  {
    "GetACP",
    reinterpret_cast<FARPROC>(MyGetACP),
  },
  {
    "GetActiveProcessorCount",
    reinterpret_cast<FARPROC>(MyGetActiveProcessorCount),
  },
  {
    "GetActiveProcessorGroupCount",
    reinterpret_cast<FARPROC>(MyGetActiveProcessorGroupCount),
  },
  {
    "GetAppContainerAce",
    reinterpret_cast<FARPROC>(MyGetAppContainerAce),
  },
  {
    "GetAppContainerNamedObjectPath",
    reinterpret_cast<FARPROC>(MyGetAppContainerNamedObjectPath),
  },
  {
    "GetApplicationRecoveryCallback",
    reinterpret_cast<FARPROC>(MyGetApplicationRecoveryCallback),
  },
  {
    "GetApplicationRestartSettings",
    reinterpret_cast<FARPROC>(MyGetApplicationRestartSettings),
  },
  {
    "GetApplicationUserModelId",
    reinterpret_cast<FARPROC>(MyGetApplicationUserModelId),
  },
  {
    "GetAtomNameA",
    reinterpret_cast<FARPROC>(MyGetAtomNameA),
  },
  {
    "GetAtomNameW",
    reinterpret_cast<FARPROC>(MyGetAtomNameW),
  },
  {
    "GetBinaryTypeA",
    reinterpret_cast<FARPROC>(MyGetBinaryTypeA),
  },
  {
    "GetBinaryTypeW",
    reinterpret_cast<FARPROC>(MyGetBinaryTypeW),
  },
  {
    "GetCPInfo",
    reinterpret_cast<FARPROC>(MyGetCPInfo),
  },
  {
    "GetCPInfoExA",
    reinterpret_cast<FARPROC>(MyGetCPInfoExA),
  },
  {
    "GetCPInfoExW",
    reinterpret_cast<FARPROC>(MyGetCPInfoExW),
  },
  {
    "GetCachedSigningLevel",
    reinterpret_cast<FARPROC>(MyGetCachedSigningLevel),
  },
  {
    "GetCalendarDateFormatEx",
    reinterpret_cast<FARPROC>(MyGetCalendarDateFormatEx),
  },
  {
    "GetCalendarInfoA",
    reinterpret_cast<FARPROC>(MyGetCalendarInfoA),
  },
  {
    "GetCalendarInfoEx",
    reinterpret_cast<FARPROC>(MyGetCalendarInfoEx),
  },
  {
    "GetCalendarInfoW",
    reinterpret_cast<FARPROC>(MyGetCalendarInfoW),
  },
  {
    "GetCalendarSupportedDateRange",
    reinterpret_cast<FARPROC>(MyGetCalendarSupportedDateRange),
  },
  {
    "GetComPlusPackageInstallStatus",
    reinterpret_cast<FARPROC>(MyGetComPlusPackageInstallStatus),
  },
  {
    "GetCommConfig",
    reinterpret_cast<FARPROC>(MyGetCommConfig),
  },
  {
    "GetCommMask",
    reinterpret_cast<FARPROC>(MyGetCommMask),
  },
  {
    "GetCommModemStatus",
    reinterpret_cast<FARPROC>(MyGetCommModemStatus),
  },
  {
    "GetCommProperties",
    reinterpret_cast<FARPROC>(MyGetCommProperties),
  },
  {
    "GetCommState",
    reinterpret_cast<FARPROC>(MyGetCommState),
  },
  {
    "GetCommTimeouts",
    reinterpret_cast<FARPROC>(MyGetCommTimeouts),
  },
  {
    "GetCommandLineA",
    reinterpret_cast<FARPROC>(MyGetCommandLineA),
  },
  {
    "GetCommandLineW",
    reinterpret_cast<FARPROC>(MyGetCommandLineW),
  },
  {
    "GetCompressedFileSizeA",
    reinterpret_cast<FARPROC>(MyGetCompressedFileSizeA),
  },
  {
    "GetCompressedFileSizeTransactedA",
    reinterpret_cast<FARPROC>(MyGetCompressedFileSizeTransactedA),
  },
  {
    "GetCompressedFileSizeTransactedW",
    reinterpret_cast<FARPROC>(MyGetCompressedFileSizeTransactedW),
  },
  {
    "GetCompressedFileSizeW",
    reinterpret_cast<FARPROC>(MyGetCompressedFileSizeW),
  },
  {
    "GetComputerNameA",
    reinterpret_cast<FARPROC>(MyGetComputerNameA),
  },
  {
    "GetComputerNameExA",
    reinterpret_cast<FARPROC>(MyGetComputerNameExA),
  },
  {
    "GetComputerNameExW",
    reinterpret_cast<FARPROC>(MyGetComputerNameExW),
  },
  {
    "GetComputerNameW",
    reinterpret_cast<FARPROC>(MyGetComputerNameW),
  },
  {
    "GetConsoleAliasA",
    reinterpret_cast<FARPROC>(MyGetConsoleAliasA),
  },
  {
    "GetConsoleAliasExesA",
    reinterpret_cast<FARPROC>(MyGetConsoleAliasExesA),
  },
  {
    "GetConsoleAliasExesLengthA",
    reinterpret_cast<FARPROC>(MyGetConsoleAliasExesLengthA),
  },
  {
    "GetConsoleAliasExesLengthW",
    reinterpret_cast<FARPROC>(MyGetConsoleAliasExesLengthW),
  },
  {
    "GetConsoleAliasExesW",
    reinterpret_cast<FARPROC>(MyGetConsoleAliasExesW),
  },
  {
    "GetConsoleAliasW",
    reinterpret_cast<FARPROC>(MyGetConsoleAliasW),
  },
  {
    "GetConsoleAliasesA",
    reinterpret_cast<FARPROC>(MyGetConsoleAliasesA),
  },
  {
    "GetConsoleAliasesLengthA",
    reinterpret_cast<FARPROC>(MyGetConsoleAliasesLengthA),
  },
  {
    "GetConsoleAliasesLengthW",
    reinterpret_cast<FARPROC>(MyGetConsoleAliasesLengthW),
  },
  {
    "GetConsoleAliasesW",
    reinterpret_cast<FARPROC>(MyGetConsoleAliasesW),
  },
  {
    "GetConsoleCP",
    reinterpret_cast<FARPROC>(MyGetConsoleCP),
  },
  {
    "GetConsoleCursorInfo",
    reinterpret_cast<FARPROC>(MyGetConsoleCursorInfo),
  },
  {
    "GetConsoleDisplayMode",
    reinterpret_cast<FARPROC>(MyGetConsoleDisplayMode),
  },
  {
    "GetConsoleFontSize",
    reinterpret_cast<FARPROC>(MyGetConsoleFontSize),
  },
  {
    "GetConsoleHistoryInfo",
    reinterpret_cast<FARPROC>(MyGetConsoleHistoryInfo),
  },
  {
    "GetConsoleMode",
    reinterpret_cast<FARPROC>(MyGetConsoleMode),
  },
  {
    "GetConsoleOriginalTitleA",
    reinterpret_cast<FARPROC>(MyGetConsoleOriginalTitleA),
  },
  {
    "GetConsoleOriginalTitleW",
    reinterpret_cast<FARPROC>(MyGetConsoleOriginalTitleW),
  },
  {
    "GetConsoleOutputCP",
    reinterpret_cast<FARPROC>(MyGetConsoleOutputCP),
  },
  {
    "GetConsoleProcessList",
    reinterpret_cast<FARPROC>(MyGetConsoleProcessList),
  },
  {
    "GetConsoleScreenBufferInfo",
    reinterpret_cast<FARPROC>(MyGetConsoleScreenBufferInfo),
  },
  {
    "GetConsoleScreenBufferInfoEx",
    reinterpret_cast<FARPROC>(MyGetConsoleScreenBufferInfoEx),
  },
  {
    "GetConsoleSelectionInfo",
    reinterpret_cast<FARPROC>(MyGetConsoleSelectionInfo),
  },
  {
    "GetConsoleTitleA",
    reinterpret_cast<FARPROC>(MyGetConsoleTitleA),
  },
  {
    "GetConsoleTitleW",
    reinterpret_cast<FARPROC>(MyGetConsoleTitleW),
  },
  {
    "GetConsoleWindow",
    reinterpret_cast<FARPROC>(MyGetConsoleWindow),
  },
  {
    "GetCurrencyFormatA",
    reinterpret_cast<FARPROC>(MyGetCurrencyFormatA),
  },
  {
    "GetCurrencyFormatEx",
    reinterpret_cast<FARPROC>(MyGetCurrencyFormatEx),
  },
  {
    "GetCurrencyFormatW",
    reinterpret_cast<FARPROC>(MyGetCurrencyFormatW),
  },
  {
    "GetCurrentActCtx",
    reinterpret_cast<FARPROC>(MyGetCurrentActCtx),
  },
  {
    "GetCurrentApplicationUserModelId",
    reinterpret_cast<FARPROC>(MyGetCurrentApplicationUserModelId),
  },
  {
    "GetCurrentConsoleFont",
    reinterpret_cast<FARPROC>(MyGetCurrentConsoleFont),
  },
  {
    "GetCurrentConsoleFontEx",
    reinterpret_cast<FARPROC>(MyGetCurrentConsoleFontEx),
  },
  {
    "GetCurrentDirectoryA",
    reinterpret_cast<FARPROC>(MyGetCurrentDirectoryA),
  },
  {
    "GetCurrentDirectoryW",
    reinterpret_cast<FARPROC>(MyGetCurrentDirectoryW),
  },
  {
    "GetCurrentPackageFamilyName",
    reinterpret_cast<FARPROC>(MyGetCurrentPackageFamilyName),
  },
  {
    "GetCurrentPackageFullName",
    reinterpret_cast<FARPROC>(MyGetCurrentPackageFullName),
  },
  {
    "GetCurrentPackageId",
    reinterpret_cast<FARPROC>(MyGetCurrentPackageId),
  },
  {
    "GetCurrentPackageInfo",
    reinterpret_cast<FARPROC>(MyGetCurrentPackageInfo),
  },
  {
    "GetCurrentPackagePath",
    reinterpret_cast<FARPROC>(MyGetCurrentPackagePath),
  },
  {
    "GetCurrentProcess",
    reinterpret_cast<FARPROC>(MyGetCurrentProcess),
  },
  {
    "GetCurrentProcessId",
    reinterpret_cast<FARPROC>(MyGetCurrentProcessId),
  },
  {
    "GetCurrentProcessorNumber",
    reinterpret_cast<FARPROC>(MyGetCurrentProcessorNumber),
  },
  {
    "GetCurrentProcessorNumberEx",
    reinterpret_cast<FARPROC>(MyGetCurrentProcessorNumberEx),
  },
  {
    "GetCurrentThread",
    reinterpret_cast<FARPROC>(MyGetCurrentThread),
  },
  {
    "GetCurrentThreadId",
    reinterpret_cast<FARPROC>(MyGetCurrentThreadId),
  },
  {
    "GetCurrentThreadStackLimits",
    reinterpret_cast<FARPROC>(MyGetCurrentThreadStackLimits),
  },
  {
    "GetCurrentUmsThread",
    reinterpret_cast<FARPROC>(MyGetCurrentUmsThread),
  },
  {
    "GetDateFormatA",
    reinterpret_cast<FARPROC>(MyGetDateFormatA),
  },
  {
    "GetDateFormatEx",
    reinterpret_cast<FARPROC>(MyGetDateFormatEx),
  },
  {
    "GetDateFormatW",
    reinterpret_cast<FARPROC>(MyGetDateFormatW),
  },
  {
    "GetDefaultCommConfigA",
    reinterpret_cast<FARPROC>(MyGetDefaultCommConfigA),
  },
  {
    "GetDefaultCommConfigW",
    reinterpret_cast<FARPROC>(MyGetDefaultCommConfigW),
  },
  {
    "GetDevicePowerState",
    reinterpret_cast<FARPROC>(MyGetDevicePowerState),
  },
  {
    "GetDiskFreeSpaceA",
    reinterpret_cast<FARPROC>(MyGetDiskFreeSpaceA),
  },
  {
    "GetDiskFreeSpaceExA",
    reinterpret_cast<FARPROC>(MyGetDiskFreeSpaceExA),
  },
  {
    "GetDiskFreeSpaceExW",
    reinterpret_cast<FARPROC>(MyGetDiskFreeSpaceExW),
  },
  {
    "GetDiskFreeSpaceW",
    reinterpret_cast<FARPROC>(MyGetDiskFreeSpaceW),
  },
  {
    "GetDiskSpaceInformationA",
    reinterpret_cast<FARPROC>(MyGetDiskSpaceInformationA),
  },
  {
    "GetDiskSpaceInformationW",
    reinterpret_cast<FARPROC>(MyGetDiskSpaceInformationW),
  },
  {
    "GetDllDirectoryA",
    reinterpret_cast<FARPROC>(MyGetDllDirectoryA),
  },
  {
    "GetDllDirectoryW",
    reinterpret_cast<FARPROC>(MyGetDllDirectoryW),
  },
  {
    "GetDriveTypeA",
    reinterpret_cast<FARPROC>(MyGetDriveTypeA),
  },
  {
    "GetDriveTypeW",
    reinterpret_cast<FARPROC>(MyGetDriveTypeW),
  },
  {
    "GetDurationFormat",
    reinterpret_cast<FARPROC>(MyGetDurationFormat),
  },
  {
    "GetDurationFormatEx",
    reinterpret_cast<FARPROC>(MyGetDurationFormatEx),
  },
  {
    "GetDynamicTimeZoneInformation",
    reinterpret_cast<FARPROC>(MyGetDynamicTimeZoneInformation),
  },
  {
    "GetEnabledXStateFeatures",
    reinterpret_cast<FARPROC>(MyGetEnabledXStateFeatures),
  },
  {
    "GetEnvironmentStrings",
    reinterpret_cast<FARPROC>(MyGetEnvironmentStrings),
  },
  {
    "GetEnvironmentStringsW",
    reinterpret_cast<FARPROC>(MyGetEnvironmentStringsW),
  },
  {
    "GetEnvironmentVariableA",
    reinterpret_cast<FARPROC>(MyGetEnvironmentVariableA),
  },
  {
    "GetEnvironmentVariableW",
    reinterpret_cast<FARPROC>(MyGetEnvironmentVariableW),
  },
  {
    "GetErrorMode",
    reinterpret_cast<FARPROC>(MyGetErrorMode),
  },
  {
    "GetExitCodeProcess",
    reinterpret_cast<FARPROC>(MyGetExitCodeProcess),
  },
  {
    "GetExitCodeThread",
    reinterpret_cast<FARPROC>(MyGetExitCodeThread),
  },
  {
    "GetExpandedNameA",
    reinterpret_cast<FARPROC>(MyGetExpandedNameA),
  },
  {
    "GetExpandedNameW",
    reinterpret_cast<FARPROC>(MyGetExpandedNameW),
  },
  {
    "GetFileAttributesA",
    reinterpret_cast<FARPROC>(MyGetFileAttributesA),
  },
  {
    "GetFileAttributesExA",
    reinterpret_cast<FARPROC>(MyGetFileAttributesExA),
  },
  {
    "GetFileAttributesExW",
    reinterpret_cast<FARPROC>(MyGetFileAttributesExW),
  },
  {
    "GetFileAttributesTransactedA",
    reinterpret_cast<FARPROC>(MyGetFileAttributesTransactedA),
  },
  {
    "GetFileAttributesTransactedW",
    reinterpret_cast<FARPROC>(MyGetFileAttributesTransactedW),
  },
  {
    "GetFileAttributesW",
    reinterpret_cast<FARPROC>(MyGetFileAttributesW),
  },
  {
    "GetFileBandwidthReservation",
    reinterpret_cast<FARPROC>(MyGetFileBandwidthReservation),
  },
  {
    "GetFileInformationByHandle",
    reinterpret_cast<FARPROC>(MyGetFileInformationByHandle),
  },
  {
    "GetFileInformationByHandleEx",
    reinterpret_cast<FARPROC>(MyGetFileInformationByHandleEx),
  },
  {
    "GetFileMUIInfo",
    reinterpret_cast<FARPROC>(MyGetFileMUIInfo),
  },
  {
    "GetFileMUIPath",
    reinterpret_cast<FARPROC>(MyGetFileMUIPath),
  },
  {
    "GetFileSize",
    reinterpret_cast<FARPROC>(MyGetFileSize),
  },
  {
    "GetFileSizeEx",
    reinterpret_cast<FARPROC>(MyGetFileSizeEx),
  },
  {
    "GetFileTime",
    reinterpret_cast<FARPROC>(MyGetFileTime),
  },
  {
    "GetFileType",
    reinterpret_cast<FARPROC>(MyGetFileType),
  },
  {
    "GetFinalPathNameByHandleA",
    reinterpret_cast<FARPROC>(MyGetFinalPathNameByHandleA),
  },
  {
    "GetFinalPathNameByHandleW",
    reinterpret_cast<FARPROC>(MyGetFinalPathNameByHandleW),
  },
  {
    "GetFirmwareEnvironmentVariableA",
    reinterpret_cast<FARPROC>(MyGetFirmwareEnvironmentVariableA),
  },
  {
    "GetFirmwareEnvironmentVariableExA",
    reinterpret_cast<FARPROC>(MyGetFirmwareEnvironmentVariableExA),
  },
  {
    "GetFirmwareEnvironmentVariableExW",
    reinterpret_cast<FARPROC>(MyGetFirmwareEnvironmentVariableExW),
  },
  {
    "GetFirmwareEnvironmentVariableW",
    reinterpret_cast<FARPROC>(MyGetFirmwareEnvironmentVariableW),
  },
  {
    "GetFirmwareType",
    reinterpret_cast<FARPROC>(MyGetFirmwareType),
  },
  {
    "GetFullPathNameA",
    reinterpret_cast<FARPROC>(MyGetFullPathNameA),
  },
  {
    "GetFullPathNameTransactedA",
    reinterpret_cast<FARPROC>(MyGetFullPathNameTransactedA),
  },
  {
    "GetFullPathNameTransactedW",
    reinterpret_cast<FARPROC>(MyGetFullPathNameTransactedW),
  },
  {
    "GetFullPathNameW",
    reinterpret_cast<FARPROC>(MyGetFullPathNameW),
  },
  {
    "GetGeoInfoA",
    reinterpret_cast<FARPROC>(MyGetGeoInfoA),
  },
  {
    "GetGeoInfoEx",
    reinterpret_cast<FARPROC>(MyGetGeoInfoEx),
  },
  {
    "GetGeoInfoW",
    reinterpret_cast<FARPROC>(MyGetGeoInfoW),
  },
  {
    "GetHandleInformation",
    reinterpret_cast<FARPROC>(MyGetHandleInformation),
  },
  {
    "GetLargePageMinimum",
    reinterpret_cast<FARPROC>(MyGetLargePageMinimum),
  },
  {
    "GetLargestConsoleWindowSize",
    reinterpret_cast<FARPROC>(MyGetLargestConsoleWindowSize),
  },
  {
    "GetLastError",
    reinterpret_cast<FARPROC>(MyGetLastError),
  },
  {
    "GetLocalTime",
    reinterpret_cast<FARPROC>(MyGetLocalTime),
  },
  {
    "GetLocaleInfoA",
    reinterpret_cast<FARPROC>(MyGetLocaleInfoA),
  },
  {
    "GetLocaleInfoEx",
    reinterpret_cast<FARPROC>(MyGetLocaleInfoEx),
  },
  {
    "GetLocaleInfoW",
    reinterpret_cast<FARPROC>(MyGetLocaleInfoW),
  },
  {
    "GetLogicalDriveStringsA",
    reinterpret_cast<FARPROC>(MyGetLogicalDriveStringsA),
  },
  {
    "GetLogicalDriveStringsW",
    reinterpret_cast<FARPROC>(MyGetLogicalDriveStringsW),
  },
  {
    "GetLogicalDrives",
    reinterpret_cast<FARPROC>(MyGetLogicalDrives),
  },
  {
    "GetLogicalProcessorInformation",
    reinterpret_cast<FARPROC>(MyGetLogicalProcessorInformation),
  },
  {
    "GetLogicalProcessorInformationEx",
    reinterpret_cast<FARPROC>(MyGetLogicalProcessorInformationEx),
  },
  {
    "GetLongPathNameA",
    reinterpret_cast<FARPROC>(MyGetLongPathNameA),
  },
  {
    "GetLongPathNameTransactedA",
    reinterpret_cast<FARPROC>(MyGetLongPathNameTransactedA),
  },
  {
    "GetLongPathNameTransactedW",
    reinterpret_cast<FARPROC>(MyGetLongPathNameTransactedW),
  },
  {
    "GetLongPathNameW",
    reinterpret_cast<FARPROC>(MyGetLongPathNameW),
  },
  {
    "GetMailslotInfo",
    reinterpret_cast<FARPROC>(MyGetMailslotInfo),
  },
  {
    "GetMaximumProcessorCount",
    reinterpret_cast<FARPROC>(MyGetMaximumProcessorCount),
  },
  {
    "GetMaximumProcessorGroupCount",
    reinterpret_cast<FARPROC>(MyGetMaximumProcessorGroupCount),
  },
  {
    "GetMemoryErrorHandlingCapabilities",
    reinterpret_cast<FARPROC>(MyGetMemoryErrorHandlingCapabilities),
  },
  {
    "GetModuleFileNameA",
    reinterpret_cast<FARPROC>(MyGetModuleFileNameA),
  },
  {
    "GetModuleFileNameW",
    reinterpret_cast<FARPROC>(MyGetModuleFileNameW),
  },
  {
    "GetModuleHandleA",
    reinterpret_cast<FARPROC>(MyGetModuleHandleA),
  },
  {
    "GetModuleHandleExA",
    reinterpret_cast<FARPROC>(MyGetModuleHandleExA),
  },
  {
    "GetModuleHandleExW",
    reinterpret_cast<FARPROC>(MyGetModuleHandleExW),
  },
  {
    "GetModuleHandleW",
    reinterpret_cast<FARPROC>(MyGetModuleHandleW),
  },
  {
    "GetNLSVersion",
    reinterpret_cast<FARPROC>(MyGetNLSVersion),
  },
  {
    "GetNLSVersionEx",
    reinterpret_cast<FARPROC>(MyGetNLSVersionEx),
  },
  {
    "GetNamedPipeClientComputerNameA",
    reinterpret_cast<FARPROC>(MyGetNamedPipeClientComputerNameA),
  },
  {
    "GetNamedPipeClientComputerNameW",
    reinterpret_cast<FARPROC>(MyGetNamedPipeClientComputerNameW),
  },
  {
    "GetNamedPipeClientProcessId",
    reinterpret_cast<FARPROC>(MyGetNamedPipeClientProcessId),
  },
  {
    "GetNamedPipeClientSessionId",
    reinterpret_cast<FARPROC>(MyGetNamedPipeClientSessionId),
  },
  {
    "GetNamedPipeHandleStateA",
    reinterpret_cast<FARPROC>(MyGetNamedPipeHandleStateA),
  },
  {
    "GetNamedPipeHandleStateW",
    reinterpret_cast<FARPROC>(MyGetNamedPipeHandleStateW),
  },
  {
    "GetNamedPipeInfo",
    reinterpret_cast<FARPROC>(MyGetNamedPipeInfo),
  },
  {
    "GetNamedPipeServerProcessId",
    reinterpret_cast<FARPROC>(MyGetNamedPipeServerProcessId),
  },
  {
    "GetNamedPipeServerSessionId",
    reinterpret_cast<FARPROC>(MyGetNamedPipeServerSessionId),
  },
  {
    "GetNativeSystemInfo",
    reinterpret_cast<FARPROC>(MyGetNativeSystemInfo),
  },
  {
    "GetNextUmsListItem",
    reinterpret_cast<FARPROC>(MyGetNextUmsListItem),
  },
  {
    "GetNumaAvailableMemoryNode",
    reinterpret_cast<FARPROC>(MyGetNumaAvailableMemoryNode),
  },
  {
    "GetNumaAvailableMemoryNodeEx",
    reinterpret_cast<FARPROC>(MyGetNumaAvailableMemoryNodeEx),
  },
  {
    "GetNumaHighestNodeNumber",
    reinterpret_cast<FARPROC>(MyGetNumaHighestNodeNumber),
  },
  {
    "GetNumaNodeNumberFromHandle",
    reinterpret_cast<FARPROC>(MyGetNumaNodeNumberFromHandle),
  },
  {
    "GetNumaNodeProcessorMask",
    reinterpret_cast<FARPROC>(MyGetNumaNodeProcessorMask),
  },
  {
    "GetNumaNodeProcessorMaskEx",
    reinterpret_cast<FARPROC>(MyGetNumaNodeProcessorMaskEx),
  },
  {
    "GetNumaProcessorNode",
    reinterpret_cast<FARPROC>(MyGetNumaProcessorNode),
  },
  {
    "GetNumaProcessorNodeEx",
    reinterpret_cast<FARPROC>(MyGetNumaProcessorNodeEx),
  },
  {
    "GetNumaProximityNode",
    reinterpret_cast<FARPROC>(MyGetNumaProximityNode),
  },
  {
    "GetNumaProximityNodeEx",
    reinterpret_cast<FARPROC>(MyGetNumaProximityNodeEx),
  },
  {
    "GetNumberFormatA",
    reinterpret_cast<FARPROC>(MyGetNumberFormatA),
  },
  {
    "GetNumberFormatEx",
    reinterpret_cast<FARPROC>(MyGetNumberFormatEx),
  },
  {
    "GetNumberFormatW",
    reinterpret_cast<FARPROC>(MyGetNumberFormatW),
  },
  {
    "GetNumberOfConsoleFonts",
    reinterpret_cast<FARPROC>(MyGetNumberOfConsoleFonts),
  },
  {
    "GetNumberOfConsoleInputEvents",
    reinterpret_cast<FARPROC>(MyGetNumberOfConsoleInputEvents),
  },
  {
    "GetNumberOfConsoleMouseButtons",
    reinterpret_cast<FARPROC>(MyGetNumberOfConsoleMouseButtons),
  },
  {
    "GetOEMCP",
    reinterpret_cast<FARPROC>(MyGetOEMCP),
  },
  {
    "GetOverlappedResult",
    reinterpret_cast<FARPROC>(MyGetOverlappedResult),
  },
  {
    "GetOverlappedResultEx",
    reinterpret_cast<FARPROC>(MyGetOverlappedResultEx),
  },
  {
    "GetPackageApplicationIds",
    reinterpret_cast<FARPROC>(MyGetPackageApplicationIds),
  },
  {
    "GetPackageFamilyName",
    reinterpret_cast<FARPROC>(MyGetPackageFamilyName),
  },
  {
    "GetPackageFullName",
    reinterpret_cast<FARPROC>(MyGetPackageFullName),
  },
  {
    "GetPackageId",
    reinterpret_cast<FARPROC>(MyGetPackageId),
  },
  {
    "GetPackagePath",
    reinterpret_cast<FARPROC>(MyGetPackagePath),
  },
  {
    "GetPackagePathByFullName",
    reinterpret_cast<FARPROC>(MyGetPackagePathByFullName),
  },
  {
    "GetPackagesByPackageFamily",
    reinterpret_cast<FARPROC>(MyGetPackagesByPackageFamily),
  },
  {
    "GetPhysicallyInstalledSystemMemory",
    reinterpret_cast<FARPROC>(MyGetPhysicallyInstalledSystemMemory),
  },
  {
    "GetPriorityClass",
    reinterpret_cast<FARPROC>(MyGetPriorityClass),
  },
  {
    "GetPrivateProfileIntA",
    reinterpret_cast<FARPROC>(MyGetPrivateProfileIntA),
  },
  {
    "GetPrivateProfileIntW",
    reinterpret_cast<FARPROC>(MyGetPrivateProfileIntW),
  },
  {
    "GetPrivateProfileSectionA",
    reinterpret_cast<FARPROC>(MyGetPrivateProfileSectionA),
  },
  {
    "GetPrivateProfileSectionNamesA",
    reinterpret_cast<FARPROC>(MyGetPrivateProfileSectionNamesA),
  },
  {
    "GetPrivateProfileSectionNamesW",
    reinterpret_cast<FARPROC>(MyGetPrivateProfileSectionNamesW),
  },
  {
    "GetPrivateProfileSectionW",
    reinterpret_cast<FARPROC>(MyGetPrivateProfileSectionW),
  },
  {
    "GetPrivateProfileStringA",
    reinterpret_cast<FARPROC>(MyGetPrivateProfileStringA),
  },
  {
    "GetPrivateProfileStringW",
    reinterpret_cast<FARPROC>(MyGetPrivateProfileStringW),
  },
  {
    "GetPrivateProfileStructA",
    reinterpret_cast<FARPROC>(MyGetPrivateProfileStructA),
  },
  {
    "GetPrivateProfileStructW",
    reinterpret_cast<FARPROC>(MyGetPrivateProfileStructW),
  },
  {
    "GetProcAddress",
    reinterpret_cast<FARPROC>(MyGetProcAddress),
  },
  {
    "GetProcessAffinityMask",
    reinterpret_cast<FARPROC>(MyGetProcessAffinityMask),
  },
  {
    "GetProcessDEPPolicy",
    reinterpret_cast<FARPROC>(MyGetProcessDEPPolicy),
  },
  {
    "GetProcessDefaultCpuSets",
    reinterpret_cast<FARPROC>(MyGetProcessDefaultCpuSets),
  },
  {
    "GetProcessGroupAffinity",
    reinterpret_cast<FARPROC>(MyGetProcessGroupAffinity),
  },
  {
    "GetProcessHandleCount",
    reinterpret_cast<FARPROC>(MyGetProcessHandleCount),
  },
  {
    "GetProcessHeap",
    reinterpret_cast<FARPROC>(MyGetProcessHeap),
  },
  {
    "GetProcessHeaps",
    reinterpret_cast<FARPROC>(MyGetProcessHeaps),
  },
  {
    "GetProcessId",
    reinterpret_cast<FARPROC>(MyGetProcessId),
  },
  {
    "GetProcessIdOfThread",
    reinterpret_cast<FARPROC>(MyGetProcessIdOfThread),
  },
  {
    "GetProcessInformation",
    reinterpret_cast<FARPROC>(MyGetProcessInformation),
  },
  {
    "GetProcessIoCounters",
    reinterpret_cast<FARPROC>(MyGetProcessIoCounters),
  },
  {
    "GetProcessMitigationPolicy",
    reinterpret_cast<FARPROC>(MyGetProcessMitigationPolicy),
  },
  {
    "GetProcessPreferredUILanguages",
    reinterpret_cast<FARPROC>(MyGetProcessPreferredUILanguages),
  },
  {
    "GetProcessPriorityBoost",
    reinterpret_cast<FARPROC>(MyGetProcessPriorityBoost),
  },
  {
    "GetProcessShutdownParameters",
    reinterpret_cast<FARPROC>(MyGetProcessShutdownParameters),
  },
  {
    "GetProcessTimes",
    reinterpret_cast<FARPROC>(MyGetProcessTimes),
  },
  {
    "GetProcessVersion",
    reinterpret_cast<FARPROC>(MyGetProcessVersion),
  },
  {
    "GetProcessWorkingSetSize",
    reinterpret_cast<FARPROC>(MyGetProcessWorkingSetSize),
  },
  {
    "GetProcessWorkingSetSizeEx",
    reinterpret_cast<FARPROC>(MyGetProcessWorkingSetSizeEx),
  },
  {
    "GetProcessorSystemCycleTime",
    reinterpret_cast<FARPROC>(MyGetProcessorSystemCycleTime),
  },
  {
    "GetProductInfo",
    reinterpret_cast<FARPROC>(MyGetProductInfo),
  },
  {
    "GetProfileIntA",
    reinterpret_cast<FARPROC>(MyGetProfileIntA),
  },
  {
    "GetProfileIntW",
    reinterpret_cast<FARPROC>(MyGetProfileIntW),
  },
  {
    "GetProfileSectionA",
    reinterpret_cast<FARPROC>(MyGetProfileSectionA),
  },
  {
    "GetProfileSectionW",
    reinterpret_cast<FARPROC>(MyGetProfileSectionW),
  },
  {
    "GetProfileStringA",
    reinterpret_cast<FARPROC>(MyGetProfileStringA),
  },
  {
    "GetProfileStringW",
    reinterpret_cast<FARPROC>(MyGetProfileStringW),
  },
  {
    "GetQueuedCompletionStatus",
    reinterpret_cast<FARPROC>(MyGetQueuedCompletionStatus),
  },
  {
    "GetQueuedCompletionStatusEx",
    reinterpret_cast<FARPROC>(MyGetQueuedCompletionStatusEx),
  },
  {
    "GetShortPathNameA",
    reinterpret_cast<FARPROC>(MyGetShortPathNameA),
  },
  {
    "GetShortPathNameW",
    reinterpret_cast<FARPROC>(MyGetShortPathNameW),
  },
  {
    "GetStagedPackagePathByFullName",
    reinterpret_cast<FARPROC>(MyGetStagedPackagePathByFullName),
  },
  {
    "GetStartupInfoA",
    reinterpret_cast<FARPROC>(MyGetStartupInfoA),
  },
  {
    "GetStartupInfoW",
    reinterpret_cast<FARPROC>(MyGetStartupInfoW),
  },
  {
    "GetStdHandle",
    reinterpret_cast<FARPROC>(MyGetStdHandle),
  },
  {
    "GetStringScripts",
    reinterpret_cast<FARPROC>(MyGetStringScripts),
  },
  {
    "GetStringTypeA",
    reinterpret_cast<FARPROC>(MyGetStringTypeA),
  },
  {
    "GetStringTypeExA",
    reinterpret_cast<FARPROC>(MyGetStringTypeExA),
  },
  {
    "GetStringTypeExW",
    reinterpret_cast<FARPROC>(MyGetStringTypeExW),
  },
  {
    "GetStringTypeW",
    reinterpret_cast<FARPROC>(MyGetStringTypeW),
  },
  {
    "GetSystemCpuSetInformation",
    reinterpret_cast<FARPROC>(MyGetSystemCpuSetInformation),
  },
  {
    "GetSystemDEPPolicy",
    reinterpret_cast<FARPROC>(MyGetSystemDEPPolicy),
  },
  {
    "GetSystemDefaultLCID",
    reinterpret_cast<FARPROC>(MyGetSystemDefaultLCID),
  },
  {
    "GetSystemDefaultLangID",
    reinterpret_cast<FARPROC>(MyGetSystemDefaultLangID),
  },
  {
    "GetSystemDefaultLocaleName",
    reinterpret_cast<FARPROC>(MyGetSystemDefaultLocaleName),
  },
  {
    "GetSystemDefaultUILanguage",
    reinterpret_cast<FARPROC>(MyGetSystemDefaultUILanguage),
  },
  {
    "GetSystemDirectoryA",
    reinterpret_cast<FARPROC>(MyGetSystemDirectoryA),
  },
  {
    "GetSystemDirectoryW",
    reinterpret_cast<FARPROC>(MyGetSystemDirectoryW),
  },
  {
    "GetSystemFileCacheSize",
    reinterpret_cast<FARPROC>(MyGetSystemFileCacheSize),
  },
  {
    "GetSystemFirmwareTable",
    reinterpret_cast<FARPROC>(MyGetSystemFirmwareTable),
  },
  {
    "GetSystemInfo",
    reinterpret_cast<FARPROC>(MyGetSystemInfo),
  },
  {
    "GetSystemPowerStatus",
    reinterpret_cast<FARPROC>(MyGetSystemPowerStatus),
  },
  {
    "GetSystemPreferredUILanguages",
    reinterpret_cast<FARPROC>(MyGetSystemPreferredUILanguages),
  },
  {
    "GetSystemRegistryQuota",
    reinterpret_cast<FARPROC>(MyGetSystemRegistryQuota),
  },
  {
    "GetSystemTime",
    reinterpret_cast<FARPROC>(MyGetSystemTime),
  },
  {
    "GetSystemTimeAdjustment",
    reinterpret_cast<FARPROC>(MyGetSystemTimeAdjustment),
  },
  {
    "GetSystemTimeAsFileTime",
    reinterpret_cast<FARPROC>(MyGetSystemTimeAsFileTime),
  },
  {
    "GetSystemTimePreciseAsFileTime",
    reinterpret_cast<FARPROC>(MyGetSystemTimePreciseAsFileTime),
  },
  {
    "GetSystemTimes",
    reinterpret_cast<FARPROC>(MyGetSystemTimes),
  },
  {
    "GetSystemWindowsDirectoryA",
    reinterpret_cast<FARPROC>(MyGetSystemWindowsDirectoryA),
  },
  {
    "GetSystemWindowsDirectoryW",
    reinterpret_cast<FARPROC>(MyGetSystemWindowsDirectoryW),
  },
  {
    "GetSystemWow64DirectoryA",
    reinterpret_cast<FARPROC>(MyGetSystemWow64DirectoryA),
  },
  {
    "GetSystemWow64DirectoryW",
    reinterpret_cast<FARPROC>(MyGetSystemWow64DirectoryW),
  },
  {
    "GetTapeParameters",
    reinterpret_cast<FARPROC>(MyGetTapeParameters),
  },
  {
    "GetTapePosition",
    reinterpret_cast<FARPROC>(MyGetTapePosition),
  },
  {
    "GetTapeStatus",
    reinterpret_cast<FARPROC>(MyGetTapeStatus),
  },
  {
    "GetTempFileNameA",
    reinterpret_cast<FARPROC>(MyGetTempFileNameA),
  },
  {
    "GetTempFileNameW",
    reinterpret_cast<FARPROC>(MyGetTempFileNameW),
  },
  {
    "GetTempPathA",
    reinterpret_cast<FARPROC>(MyGetTempPathA),
  },
  {
    "GetTempPathW",
    reinterpret_cast<FARPROC>(MyGetTempPathW),
  },
  {
    "GetThreadContext",
    reinterpret_cast<FARPROC>(MyGetThreadContext),
  },
  {
    "GetThreadDescription",
    reinterpret_cast<FARPROC>(MyGetThreadDescription),
  },
  {
    "GetThreadErrorMode",
    reinterpret_cast<FARPROC>(MyGetThreadErrorMode),
  },
  {
    "GetThreadGroupAffinity",
    reinterpret_cast<FARPROC>(MyGetThreadGroupAffinity),
  },
  {
    "GetThreadIOPendingFlag",
    reinterpret_cast<FARPROC>(MyGetThreadIOPendingFlag),
  },
  {
    "GetThreadId",
    reinterpret_cast<FARPROC>(MyGetThreadId),
  },
  {
    "GetThreadIdealProcessorEx",
    reinterpret_cast<FARPROC>(MyGetThreadIdealProcessorEx),
  },
  {
    "GetThreadInformation",
    reinterpret_cast<FARPROC>(MyGetThreadInformation),
  },
  {
    "GetThreadLocale",
    reinterpret_cast<FARPROC>(MyGetThreadLocale),
  },
  {
    "GetThreadPreferredUILanguages",
    reinterpret_cast<FARPROC>(MyGetThreadPreferredUILanguages),
  },
  {
    "GetThreadPriority",
    reinterpret_cast<FARPROC>(MyGetThreadPriority),
  },
  {
    "GetThreadPriorityBoost",
    reinterpret_cast<FARPROC>(MyGetThreadPriorityBoost),
  },
  {
    "GetThreadSelectorEntry",
    reinterpret_cast<FARPROC>(MyGetThreadSelectorEntry),
  },
  {
    "GetThreadTimes",
    reinterpret_cast<FARPROC>(MyGetThreadTimes),
  },
  {
    "GetThreadUILanguage",
    reinterpret_cast<FARPROC>(MyGetThreadUILanguage),
  },
  {
    "GetTickCount",
    reinterpret_cast<FARPROC>(MyGetTickCount),
  },
  {
    "GetTickCount64",
    reinterpret_cast<FARPROC>(MyGetTickCount64),
  },
  {
    "GetTimeFormatA",
    reinterpret_cast<FARPROC>(MyGetTimeFormatA),
  },
  {
    "GetTimeFormatEx",
    reinterpret_cast<FARPROC>(MyGetTimeFormatEx),
  },
  {
    "GetTimeFormatW",
    reinterpret_cast<FARPROC>(MyGetTimeFormatW),
  },
  {
    "GetTimeZoneInformation",
    reinterpret_cast<FARPROC>(MyGetTimeZoneInformation),
  },
  {
    "GetTimeZoneInformationForYear",
    reinterpret_cast<FARPROC>(MyGetTimeZoneInformationForYear),
  },
  {
    "GetUILanguageInfo",
    reinterpret_cast<FARPROC>(MyGetUILanguageInfo),
  },
  {
    "GetUmsCompletionListEvent",
    reinterpret_cast<FARPROC>(MyGetUmsCompletionListEvent),
  },
  {
    "GetUmsSystemThreadInformation",
    reinterpret_cast<FARPROC>(MyGetUmsSystemThreadInformation),
  },
  {
    "GetUserDefaultGeoName",
    reinterpret_cast<FARPROC>(MyGetUserDefaultGeoName),
  },
  {
    "GetUserDefaultLCID",
    reinterpret_cast<FARPROC>(MyGetUserDefaultLCID),
  },
  {
    "GetUserDefaultLangID",
    reinterpret_cast<FARPROC>(MyGetUserDefaultLangID),
  },
  {
    "GetUserDefaultLocaleName",
    reinterpret_cast<FARPROC>(MyGetUserDefaultLocaleName),
  },
  {
    "GetUserDefaultUILanguage",
    reinterpret_cast<FARPROC>(MyGetUserDefaultUILanguage),
  },
  {
    "GetUserGeoID",
    reinterpret_cast<FARPROC>(MyGetUserGeoID),
  },
  {
    "GetUserPreferredUILanguages",
    reinterpret_cast<FARPROC>(MyGetUserPreferredUILanguages),
  },
  {
    "GetVersion",
    reinterpret_cast<FARPROC>(MyGetVersion),
  },
  {
    "GetVersionExA",
    reinterpret_cast<FARPROC>(MyGetVersionExA),
  },
  {
    "GetVersionExW",
    reinterpret_cast<FARPROC>(MyGetVersionExW),
  },
  {
    "GetVolumeInformationA",
    reinterpret_cast<FARPROC>(MyGetVolumeInformationA),
  },
  {
    "GetVolumeInformationByHandleW",
    reinterpret_cast<FARPROC>(MyGetVolumeInformationByHandleW),
  },
  {
    "GetVolumeInformationW",
    reinterpret_cast<FARPROC>(MyGetVolumeInformationW),
  },
  {
    "GetVolumeNameForVolumeMountPointA",
    reinterpret_cast<FARPROC>(MyGetVolumeNameForVolumeMountPointA),
  },
  {
    "GetVolumeNameForVolumeMountPointW",
    reinterpret_cast<FARPROC>(MyGetVolumeNameForVolumeMountPointW),
  },
  {
    "GetVolumePathNameA",
    reinterpret_cast<FARPROC>(MyGetVolumePathNameA),
  },
  {
    "GetVolumePathNameW",
    reinterpret_cast<FARPROC>(MyGetVolumePathNameW),
  },
  {
    "GetVolumePathNamesForVolumeNameA",
    reinterpret_cast<FARPROC>(MyGetVolumePathNamesForVolumeNameA),
  },
  {
    "GetVolumePathNamesForVolumeNameW",
    reinterpret_cast<FARPROC>(MyGetVolumePathNamesForVolumeNameW),
  },
  {
    "GetWindowsDirectoryA",
    reinterpret_cast<FARPROC>(MyGetWindowsDirectoryA),
  },
  {
    "GetWindowsDirectoryW",
    reinterpret_cast<FARPROC>(MyGetWindowsDirectoryW),
  },
  {
    "GetWriteWatch",
    reinterpret_cast<FARPROC>(MyGetWriteWatch),
  },
  {
    "GetXStateFeaturesMask",
    reinterpret_cast<FARPROC>(MyGetXStateFeaturesMask),
  },
  {
    "GlobalAddAtomA",
    reinterpret_cast<FARPROC>(MyGlobalAddAtomA),
  },
  {
    "GlobalAddAtomExA",
    reinterpret_cast<FARPROC>(MyGlobalAddAtomExA),
  },
  {
    "GlobalAddAtomExW",
    reinterpret_cast<FARPROC>(MyGlobalAddAtomExW),
  },
  {
    "GlobalAddAtomW",
    reinterpret_cast<FARPROC>(MyGlobalAddAtomW),
  },
  {
    "GlobalAlloc",
    reinterpret_cast<FARPROC>(MyGlobalAlloc),
  },
  {
    "GlobalDeleteAtom",
    reinterpret_cast<FARPROC>(MyGlobalDeleteAtom),
  },
  {
    "GlobalFindAtomA",
    reinterpret_cast<FARPROC>(MyGlobalFindAtomA),
  },
  {
    "GlobalFindAtomW",
    reinterpret_cast<FARPROC>(MyGlobalFindAtomW),
  },
  {
    "GlobalFlags",
    reinterpret_cast<FARPROC>(MyGlobalFlags),
  },
  {
    "GlobalFree",
    reinterpret_cast<FARPROC>(MyGlobalFree),
  },
  {
    "GlobalGetAtomNameA",
    reinterpret_cast<FARPROC>(MyGlobalGetAtomNameA),
  },
  {
    "GlobalGetAtomNameW",
    reinterpret_cast<FARPROC>(MyGlobalGetAtomNameW),
  },
  {
    "GlobalHandle",
    reinterpret_cast<FARPROC>(MyGlobalHandle),
  },
  {
    "GlobalLock",
    reinterpret_cast<FARPROC>(MyGlobalLock),
  },
  {
    "GlobalMemoryStatus",
    reinterpret_cast<FARPROC>(MyGlobalMemoryStatus),
  },
  {
    "GlobalMemoryStatusEx",
    reinterpret_cast<FARPROC>(MyGlobalMemoryStatusEx),
  },
  {
    "GlobalReAlloc",
    reinterpret_cast<FARPROC>(MyGlobalReAlloc),
  },
  {
    "GlobalSize",
    reinterpret_cast<FARPROC>(MyGlobalSize),
  },
  {
    "GlobalUnlock",
    reinterpret_cast<FARPROC>(MyGlobalUnlock),
  },
  {
    "Heap32First",
    reinterpret_cast<FARPROC>(MyHeap32First),
  },
  {
    "Heap32ListFirst",
    reinterpret_cast<FARPROC>(MyHeap32ListFirst),
  },
  {
    "Heap32ListNext",
    reinterpret_cast<FARPROC>(MyHeap32ListNext),
  },
  {
    "Heap32Next",
    reinterpret_cast<FARPROC>(MyHeap32Next),
  },
  {
    "HeapAlloc",
    reinterpret_cast<FARPROC>(MyHeapAlloc),
  },
  {
    "HeapCompact",
    reinterpret_cast<FARPROC>(MyHeapCompact),
  },
  {
    "HeapCreate",
    reinterpret_cast<FARPROC>(MyHeapCreate),
  },
  {
    "HeapDestroy",
    reinterpret_cast<FARPROC>(MyHeapDestroy),
  },
  {
    "HeapFree",
    reinterpret_cast<FARPROC>(MyHeapFree),
  },
  {
    "HeapLock",
    reinterpret_cast<FARPROC>(MyHeapLock),
  },
  {
    "HeapQueryInformation",
    reinterpret_cast<FARPROC>(MyHeapQueryInformation),
  },
  {
    "HeapReAlloc",
    reinterpret_cast<FARPROC>(MyHeapReAlloc),
  },
  {
    "HeapSetInformation",
    reinterpret_cast<FARPROC>(MyHeapSetInformation),
  },
  {
    "HeapSize",
    reinterpret_cast<FARPROC>(MyHeapSize),
  },
  {
    "HeapSummary",
    reinterpret_cast<FARPROC>(MyHeapSummary),
  },
  {
    "HeapUnlock",
    reinterpret_cast<FARPROC>(MyHeapUnlock),
  },
  {
    "HeapValidate",
    reinterpret_cast<FARPROC>(MyHeapValidate),
  },
  {
    "HeapWalk",
    reinterpret_cast<FARPROC>(MyHeapWalk),
  },
  {
    "IdnToAscii",
    reinterpret_cast<FARPROC>(MyIdnToAscii),
  },
  {
    "IdnToNameprepUnicode",
    reinterpret_cast<FARPROC>(MyIdnToNameprepUnicode),
  },
  {
    "IdnToUnicode",
    reinterpret_cast<FARPROC>(MyIdnToUnicode),
  },
  {
    "InitAtomTable",
    reinterpret_cast<FARPROC>(MyInitAtomTable),
  },
  {
    "InitOnceBeginInitialize",
    reinterpret_cast<FARPROC>(MyInitOnceBeginInitialize),
  },
  {
    "InitOnceComplete",
    reinterpret_cast<FARPROC>(MyInitOnceComplete),
  },
  {
    "InitOnceExecuteOnce",
    reinterpret_cast<FARPROC>(MyInitOnceExecuteOnce),
  },
  {
    "InitOnceInitialize",
    reinterpret_cast<FARPROC>(MyInitOnceInitialize),
  },
  {
    "InitializeConditionVariable",
    reinterpret_cast<FARPROC>(MyInitializeConditionVariable),
  },
  {
    "InitializeContext",
    reinterpret_cast<FARPROC>(MyInitializeContext),
  },
  {
    "InitializeContext2",
    reinterpret_cast<FARPROC>(MyInitializeContext2),
  },
  {
    "InitializeCriticalSection",
    reinterpret_cast<FARPROC>(MyInitializeCriticalSection),
  },
  {
    "InitializeCriticalSectionAndSpinCount",
    reinterpret_cast<FARPROC>(MyInitializeCriticalSectionAndSpinCount),
  },
  {
    "InitializeCriticalSectionEx",
    reinterpret_cast<FARPROC>(MyInitializeCriticalSectionEx),
  },
  {
    "InitializeEnclave",
    reinterpret_cast<FARPROC>(MyInitializeEnclave),
  },
  {
    "InitializeProcThreadAttributeList",
    reinterpret_cast<FARPROC>(MyInitializeProcThreadAttributeList),
  },
  {
    "InitializeSListHead",
    reinterpret_cast<FARPROC>(MyInitializeSListHead),
  },
  {
    "InitializeSRWLock",
    reinterpret_cast<FARPROC>(MyInitializeSRWLock),
  },
  {
    "InitializeSynchronizationBarrier",
    reinterpret_cast<FARPROC>(MyInitializeSynchronizationBarrier),
  },
  {
    "InstallELAMCertificateInfo",
    reinterpret_cast<FARPROC>(MyInstallELAMCertificateInfo),
  },
  {
    "InterlockedFlushSList",
    reinterpret_cast<FARPROC>(MyInterlockedFlushSList),
  },
  {
    "InterlockedPopEntrySList",
    reinterpret_cast<FARPROC>(MyInterlockedPopEntrySList),
  },
  {
    "InterlockedPushEntrySList",
    reinterpret_cast<FARPROC>(MyInterlockedPushEntrySList),
  },
  {
    "InterlockedPushListSList",
    reinterpret_cast<FARPROC>(MyInterlockedPushListSList),
  },
  {
    "InterlockedPushListSListEx",
    reinterpret_cast<FARPROC>(MyInterlockedPushListSListEx),
  },
  {
    "InvalidateConsoleDIBits",
    reinterpret_cast<FARPROC>(MyInvalidateConsoleDIBits),
  },
  {
    "IsBadCodePtr",
    reinterpret_cast<FARPROC>(MyIsBadCodePtr),
  },
  {
    "IsBadReadPtr",
    reinterpret_cast<FARPROC>(MyIsBadReadPtr),
  },
  {
    "IsBadStringPtrA",
    reinterpret_cast<FARPROC>(MyIsBadStringPtrA),
  },
  {
    "IsBadStringPtrW",
    reinterpret_cast<FARPROC>(MyIsBadStringPtrW),
  },
  {
    "IsBadWritePtr",
    reinterpret_cast<FARPROC>(MyIsBadWritePtr),
  },
  {
    "IsCalendarLeapYear",
    reinterpret_cast<FARPROC>(MyIsCalendarLeapYear),
  },
  {
    "IsDBCSLeadByte",
    reinterpret_cast<FARPROC>(MyIsDBCSLeadByte),
  },
  {
    "IsDBCSLeadByteEx",
    reinterpret_cast<FARPROC>(MyIsDBCSLeadByteEx),
  },
  {
    "IsDebuggerPresent",
    reinterpret_cast<FARPROC>(MyIsDebuggerPresent),
  },
  {
    "IsEnclaveTypeSupported",
    reinterpret_cast<FARPROC>(MyIsEnclaveTypeSupported),
  },
  {
    "IsNLSDefinedString",
    reinterpret_cast<FARPROC>(MyIsNLSDefinedString),
  },
  {
    "IsNativeVhdBoot",
    reinterpret_cast<FARPROC>(MyIsNativeVhdBoot),
  },
  {
    "IsNormalizedString",
    reinterpret_cast<FARPROC>(MyIsNormalizedString),
  },
  {
    "IsProcessCritical",
    reinterpret_cast<FARPROC>(MyIsProcessCritical),
  },
  {
    "IsProcessInJob",
    reinterpret_cast<FARPROC>(MyIsProcessInJob),
  },
  {
    "IsProcessorFeaturePresent",
    reinterpret_cast<FARPROC>(MyIsProcessorFeaturePresent),
  },
  {
    "IsSystemResumeAutomatic",
    reinterpret_cast<FARPROC>(MyIsSystemResumeAutomatic),
  },
  {
    "IsThreadAFiber",
    reinterpret_cast<FARPROC>(MyIsThreadAFiber),
  },
  {
    "IsThreadpoolTimerSet",
    reinterpret_cast<FARPROC>(MyIsThreadpoolTimerSet),
  },
  {
    "IsUserCetAvailableInEnvironment",
    reinterpret_cast<FARPROC>(MyIsUserCetAvailableInEnvironment),
  },
  {
    "IsValidCodePage",
    reinterpret_cast<FARPROC>(MyIsValidCodePage),
  },
  {
    "IsValidLanguageGroup",
    reinterpret_cast<FARPROC>(MyIsValidLanguageGroup),
  },
  {
    "IsValidLocale",
    reinterpret_cast<FARPROC>(MyIsValidLocale),
  },
  {
    "IsValidLocaleName",
    reinterpret_cast<FARPROC>(MyIsValidLocaleName),
  },
  {
    "IsValidNLSVersion",
    reinterpret_cast<FARPROC>(MyIsValidNLSVersion),
  },
  {
    "IsWow64GuestMachineSupported",
    reinterpret_cast<FARPROC>(MyIsWow64GuestMachineSupported),
  },
  {
    "IsWow64Process",
    reinterpret_cast<FARPROC>(MyIsWow64Process),
  },
  {
    "IsWow64Process2",
    reinterpret_cast<FARPROC>(MyIsWow64Process2),
  },
  {
    "K32EmptyWorkingSet",
    reinterpret_cast<FARPROC>(MyK32EmptyWorkingSet),
  },
  {
    "K32EnumDeviceDrivers",
    reinterpret_cast<FARPROC>(MyK32EnumDeviceDrivers),
  },
  {
    "K32EnumPageFilesA",
    reinterpret_cast<FARPROC>(MyK32EnumPageFilesA),
  },
  {
    "K32EnumPageFilesW",
    reinterpret_cast<FARPROC>(MyK32EnumPageFilesW),
  },
  {
    "K32EnumProcessModules",
    reinterpret_cast<FARPROC>(MyK32EnumProcessModules),
  },
  {
    "K32EnumProcessModulesEx",
    reinterpret_cast<FARPROC>(MyK32EnumProcessModulesEx),
  },
  {
    "K32EnumProcesses",
    reinterpret_cast<FARPROC>(MyK32EnumProcesses),
  },
  {
    "K32GetDeviceDriverBaseNameA",
    reinterpret_cast<FARPROC>(MyK32GetDeviceDriverBaseNameA),
  },
  {
    "K32GetDeviceDriverBaseNameW",
    reinterpret_cast<FARPROC>(MyK32GetDeviceDriverBaseNameW),
  },
  {
    "K32GetDeviceDriverFileNameA",
    reinterpret_cast<FARPROC>(MyK32GetDeviceDriverFileNameA),
  },
  {
    "K32GetDeviceDriverFileNameW",
    reinterpret_cast<FARPROC>(MyK32GetDeviceDriverFileNameW),
  },
  {
    "K32GetMappedFileNameA",
    reinterpret_cast<FARPROC>(MyK32GetMappedFileNameA),
  },
  {
    "K32GetMappedFileNameW",
    reinterpret_cast<FARPROC>(MyK32GetMappedFileNameW),
  },
  {
    "K32GetModuleBaseNameA",
    reinterpret_cast<FARPROC>(MyK32GetModuleBaseNameA),
  },
  {
    "K32GetModuleBaseNameW",
    reinterpret_cast<FARPROC>(MyK32GetModuleBaseNameW),
  },
  {
    "K32GetModuleFileNameExA",
    reinterpret_cast<FARPROC>(MyK32GetModuleFileNameExA),
  },
  {
    "K32GetModuleFileNameExW",
    reinterpret_cast<FARPROC>(MyK32GetModuleFileNameExW),
  },
  {
    "K32GetModuleInformation",
    reinterpret_cast<FARPROC>(MyK32GetModuleInformation),
  },
  {
    "K32GetPerformanceInfo",
    reinterpret_cast<FARPROC>(MyK32GetPerformanceInfo),
  },
  {
    "K32GetProcessImageFileNameA",
    reinterpret_cast<FARPROC>(MyK32GetProcessImageFileNameA),
  },
  {
    "K32GetProcessImageFileNameW",
    reinterpret_cast<FARPROC>(MyK32GetProcessImageFileNameW),
  },
  {
    "K32GetProcessMemoryInfo",
    reinterpret_cast<FARPROC>(MyK32GetProcessMemoryInfo),
  },
  {
    "K32GetWsChanges",
    reinterpret_cast<FARPROC>(MyK32GetWsChanges),
  },
  {
    "K32GetWsChangesEx",
    reinterpret_cast<FARPROC>(MyK32GetWsChangesEx),
  },
  {
    "K32InitializeProcessForWsWatch",
    reinterpret_cast<FARPROC>(MyK32InitializeProcessForWsWatch),
  },
  {
    "K32QueryWorkingSet",
    reinterpret_cast<FARPROC>(MyK32QueryWorkingSet),
  },
  {
    "K32QueryWorkingSetEx",
    reinterpret_cast<FARPROC>(MyK32QueryWorkingSetEx),
  },
  {
    "LCIDToLocaleName",
    reinterpret_cast<FARPROC>(MyLCIDToLocaleName),
  },
  {
    "LCMapStringA",
    reinterpret_cast<FARPROC>(MyLCMapStringA),
  },
  {
    "LCMapStringEx",
    reinterpret_cast<FARPROC>(MyLCMapStringEx),
  },
  {
    "LCMapStringW",
    reinterpret_cast<FARPROC>(MyLCMapStringW),
  },
  {
    "LZClose",
    reinterpret_cast<FARPROC>(MyLZClose),
  },
  {
    "LZCopy",
    reinterpret_cast<FARPROC>(MyLZCopy),
  },
  {
    "LZInit",
    reinterpret_cast<FARPROC>(MyLZInit),
  },
  {
    "LZOpenFileA",
    reinterpret_cast<FARPROC>(MyLZOpenFileA),
  },
  {
    "LZOpenFileW",
    reinterpret_cast<FARPROC>(MyLZOpenFileW),
  },
  {
    "LZRead",
    reinterpret_cast<FARPROC>(MyLZRead),
  },
  {
    "LZSeek",
    reinterpret_cast<FARPROC>(MyLZSeek),
  },
  {
    "LeaveCriticalSection",
    reinterpret_cast<FARPROC>(MyLeaveCriticalSection),
  },
  {
    "LeaveCriticalSectionWhenCallbackReturns",
    reinterpret_cast<FARPROC>(MyLeaveCriticalSectionWhenCallbackReturns),
  },
  {
    "LoadEnclaveData",
    reinterpret_cast<FARPROC>(MyLoadEnclaveData),
  },
  {
    "LoadLibraryA",
    reinterpret_cast<FARPROC>(MyLoadLibraryA),
  },
  {
    "LoadLibraryExA",
    reinterpret_cast<FARPROC>(MyLoadLibraryExA),
  },
  {
    "LoadLibraryExW",
    reinterpret_cast<FARPROC>(MyLoadLibraryExW),
  },
  {
    "LoadLibraryW",
    reinterpret_cast<FARPROC>(MyLoadLibraryW),
  },
  {
    "LoadModule",
    reinterpret_cast<FARPROC>(MyLoadModule),
  },
  {
    "LoadPackagedLibrary",
    reinterpret_cast<FARPROC>(MyLoadPackagedLibrary),
  },
  {
    "LoadResource",
    reinterpret_cast<FARPROC>(MyLoadResource),
  },
  {
    "LocalAlloc",
    reinterpret_cast<FARPROC>(MyLocalAlloc),
  },
  {
    "LocalFileTimeToFileTime",
    reinterpret_cast<FARPROC>(MyLocalFileTimeToFileTime),
  },
  {
    "LocalFlags",
    reinterpret_cast<FARPROC>(MyLocalFlags),
  },
  {
    "LocalFree",
    reinterpret_cast<FARPROC>(MyLocalFree),
  },
  {
    "LocalHandle",
    reinterpret_cast<FARPROC>(MyLocalHandle),
  },
  {
    "LocalLock",
    reinterpret_cast<FARPROC>(MyLocalLock),
  },
  {
    "LocalReAlloc",
    reinterpret_cast<FARPROC>(MyLocalReAlloc),
  },
  {
    "LocalSize",
    reinterpret_cast<FARPROC>(MyLocalSize),
  },
  {
    "LocalUnlock",
    reinterpret_cast<FARPROC>(MyLocalUnlock),
  },
  {
    "LocaleNameToLCID",
    reinterpret_cast<FARPROC>(MyLocaleNameToLCID),
  },
  {
    "LocateXStateFeature",
    reinterpret_cast<FARPROC>(MyLocateXStateFeature),
  },
  {
    "LockFile",
    reinterpret_cast<FARPROC>(MyLockFile),
  },
  {
    "LockFileEx",
    reinterpret_cast<FARPROC>(MyLockFileEx),
  },
  {
    "LockResource",
    reinterpret_cast<FARPROC>(MyLockResource),
  },
  {
    "MapUserPhysicalPages",
    reinterpret_cast<FARPROC>(MyMapUserPhysicalPages),
  },
  {
    "MapUserPhysicalPagesScatter",
    reinterpret_cast<FARPROC>(MyMapUserPhysicalPagesScatter),
  },
  {
    "MapViewOfFile",
    reinterpret_cast<FARPROC>(MyMapViewOfFile),
  },
  {
    "MapViewOfFileEx",
    reinterpret_cast<FARPROC>(MyMapViewOfFileEx),
  },
  {
    "MapViewOfFileExNuma",
    reinterpret_cast<FARPROC>(MyMapViewOfFileExNuma),
  },
  {
    "MapViewOfFileFromApp",
    reinterpret_cast<FARPROC>(MyMapViewOfFileFromApp),
  },
  {
    "Module32First",
    reinterpret_cast<FARPROC>(MyModule32First),
  },
  {
    "Module32FirstW",
    reinterpret_cast<FARPROC>(MyModule32FirstW),
  },
  {
    "Module32Next",
    reinterpret_cast<FARPROC>(MyModule32Next),
  },
  {
    "Module32NextW",
    reinterpret_cast<FARPROC>(MyModule32NextW),
  },
  {
    "MoveFileA",
    reinterpret_cast<FARPROC>(MyMoveFileA),
  },
  {
    "MoveFileExA",
    reinterpret_cast<FARPROC>(MyMoveFileExA),
  },
  {
    "MoveFileExW",
    reinterpret_cast<FARPROC>(MyMoveFileExW),
  },
  {
    "MoveFileTransactedA",
    reinterpret_cast<FARPROC>(MyMoveFileTransactedA),
  },
  {
    "MoveFileTransactedW",
    reinterpret_cast<FARPROC>(MyMoveFileTransactedW),
  },
  {
    "MoveFileW",
    reinterpret_cast<FARPROC>(MyMoveFileW),
  },
  {
    "MoveFileWithProgressA",
    reinterpret_cast<FARPROC>(MyMoveFileWithProgressA),
  },
  {
    "MoveFileWithProgressW",
    reinterpret_cast<FARPROC>(MyMoveFileWithProgressW),
  },
  {
    "MulDiv",
    reinterpret_cast<FARPROC>(MyMulDiv),
  },
  {
    "MultiByteToWideChar",
    reinterpret_cast<FARPROC>(MyMultiByteToWideChar),
  },
  {
    "NeedCurrentDirectoryForExePathA",
    reinterpret_cast<FARPROC>(MyNeedCurrentDirectoryForExePathA),
  },
  {
    "NeedCurrentDirectoryForExePathW",
    reinterpret_cast<FARPROC>(MyNeedCurrentDirectoryForExePathW),
  },
  {
    "NormalizeString",
    reinterpret_cast<FARPROC>(MyNormalizeString),
  },
  {
    "NotifyUILanguageChange",
    reinterpret_cast<FARPROC>(MyNotifyUILanguageChange),
  },
  {
    "OOBEComplete",
    reinterpret_cast<FARPROC>(MyOOBEComplete),
  },
  {
    "OfferVirtualMemory",
    reinterpret_cast<FARPROC>(MyOfferVirtualMemory),
  },
  {
    "OpenEventA",
    reinterpret_cast<FARPROC>(MyOpenEventA),
  },
  {
    "OpenEventW",
    reinterpret_cast<FARPROC>(MyOpenEventW),
  },
  {
    "OpenFile",
    reinterpret_cast<FARPROC>(MyOpenFile),
  },
  {
    "OpenFileById",
    reinterpret_cast<FARPROC>(MyOpenFileById),
  },
  {
    "OpenFileMappingA",
    reinterpret_cast<FARPROC>(MyOpenFileMappingA),
  },
  {
    "OpenFileMappingW",
    reinterpret_cast<FARPROC>(MyOpenFileMappingW),
  },
  {
    "OpenJobObjectA",
    reinterpret_cast<FARPROC>(MyOpenJobObjectA),
  },
  {
    "OpenJobObjectW",
    reinterpret_cast<FARPROC>(MyOpenJobObjectW),
  },
  {
    "OpenMutexA",
    reinterpret_cast<FARPROC>(MyOpenMutexA),
  },
  {
    "OpenMutexW",
    reinterpret_cast<FARPROC>(MyOpenMutexW),
  },
  {
    "OpenPackageInfoByFullName",
    reinterpret_cast<FARPROC>(MyOpenPackageInfoByFullName),
  },
  {
    "OpenPrivateNamespaceA",
    reinterpret_cast<FARPROC>(MyOpenPrivateNamespaceA),
  },
  {
    "OpenPrivateNamespaceW",
    reinterpret_cast<FARPROC>(MyOpenPrivateNamespaceW),
  },
  {
    "OpenProcess",
    reinterpret_cast<FARPROC>(MyOpenProcess),
  },
  {
    "OpenProcessToken",
    reinterpret_cast<FARPROC>(MyOpenProcessToken),
  },
  {
    "OpenSemaphoreA",
    reinterpret_cast<FARPROC>(MyOpenSemaphoreA),
  },
  {
    "OpenSemaphoreW",
    reinterpret_cast<FARPROC>(MyOpenSemaphoreW),
  },
  {
    "OpenThread",
    reinterpret_cast<FARPROC>(MyOpenThread),
  },
  {
    "OpenThreadToken",
    reinterpret_cast<FARPROC>(MyOpenThreadToken),
  },
  {
    "OpenWaitableTimerA",
    reinterpret_cast<FARPROC>(MyOpenWaitableTimerA),
  },
  {
    "OpenWaitableTimerW",
    reinterpret_cast<FARPROC>(MyOpenWaitableTimerW),
  },
  {
    "OutputDebugStringA",
    reinterpret_cast<FARPROC>(MyOutputDebugStringA),
  },
  {
    "OutputDebugStringW",
    reinterpret_cast<FARPROC>(MyOutputDebugStringW),
  },
  {
    "PackageFamilyNameFromFullName",
    reinterpret_cast<FARPROC>(MyPackageFamilyNameFromFullName),
  },
  {
    "PackageFamilyNameFromId",
    reinterpret_cast<FARPROC>(MyPackageFamilyNameFromId),
  },
  {
    "PackageFullNameFromId",
    reinterpret_cast<FARPROC>(MyPackageFullNameFromId),
  },
  {
    "PackageIdFromFullName",
    reinterpret_cast<FARPROC>(MyPackageIdFromFullName),
  },
  {
    "PackageNameAndPublisherIdFromFamilyName",
    reinterpret_cast<FARPROC>(MyPackageNameAndPublisherIdFromFamilyName),
  },
  {
    "ParseApplicationUserModelId",
    reinterpret_cast<FARPROC>(MyParseApplicationUserModelId),
  },
  {
    "PeekConsoleInputA",
    reinterpret_cast<FARPROC>(MyPeekConsoleInputA),
  },
  {
    "PeekConsoleInputW",
    reinterpret_cast<FARPROC>(MyPeekConsoleInputW),
  },
  {
    "PeekNamedPipe",
    reinterpret_cast<FARPROC>(MyPeekNamedPipe),
  },
  {
    "PostQueuedCompletionStatus",
    reinterpret_cast<FARPROC>(MyPostQueuedCompletionStatus),
  },
  {
    "PowerClearRequest",
    reinterpret_cast<FARPROC>(MyPowerClearRequest),
  },
  {
    "PowerCreateRequest",
    reinterpret_cast<FARPROC>(MyPowerCreateRequest),
  },
  {
    "PowerSetRequest",
    reinterpret_cast<FARPROC>(MyPowerSetRequest),
  },
  {
    "PrefetchVirtualMemory",
    reinterpret_cast<FARPROC>(MyPrefetchVirtualMemory),
  },
  {
    "PrepareTape",
    reinterpret_cast<FARPROC>(MyPrepareTape),
  },
  {
    "Process32First",
    reinterpret_cast<FARPROC>(MyProcess32First),
  },
  {
    "Process32FirstW",
    reinterpret_cast<FARPROC>(MyProcess32FirstW),
  },
  {
    "Process32Next",
    reinterpret_cast<FARPROC>(MyProcess32Next),
  },
  {
    "Process32NextW",
    reinterpret_cast<FARPROC>(MyProcess32NextW),
  },
  {
    "ProcessIdToSessionId",
    reinterpret_cast<FARPROC>(MyProcessIdToSessionId),
  },
  {
    "PssCaptureSnapshot",
    reinterpret_cast<FARPROC>(MyPssCaptureSnapshot),
  },
  {
    "PssDuplicateSnapshot",
    reinterpret_cast<FARPROC>(MyPssDuplicateSnapshot),
  },
  {
    "PssFreeSnapshot",
    reinterpret_cast<FARPROC>(MyPssFreeSnapshot),
  },
  {
    "PssQuerySnapshot",
    reinterpret_cast<FARPROC>(MyPssQuerySnapshot),
  },
  {
    "PssWalkMarkerCreate",
    reinterpret_cast<FARPROC>(MyPssWalkMarkerCreate),
  },
  {
    "PssWalkMarkerFree",
    reinterpret_cast<FARPROC>(MyPssWalkMarkerFree),
  },
  {
    "PssWalkMarkerGetPosition",
    reinterpret_cast<FARPROC>(MyPssWalkMarkerGetPosition),
  },
  {
    "PssWalkMarkerSetPosition",
    reinterpret_cast<FARPROC>(MyPssWalkMarkerSetPosition),
  },
  {
    "PssWalkSnapshot",
    reinterpret_cast<FARPROC>(MyPssWalkSnapshot),
  },
  {
    "PulseEvent",
    reinterpret_cast<FARPROC>(MyPulseEvent),
  },
  {
    "PurgeComm",
    reinterpret_cast<FARPROC>(MyPurgeComm),
  },
  {
    "QueryActCtxSettingsW",
    reinterpret_cast<FARPROC>(MyQueryActCtxSettingsW),
  },
  {
    "QueryActCtxW",
    reinterpret_cast<FARPROC>(MyQueryActCtxW),
  },
  {
    "QueryDepthSList",
    reinterpret_cast<FARPROC>(MyQueryDepthSList),
  },
  {
    "QueryDosDeviceA",
    reinterpret_cast<FARPROC>(MyQueryDosDeviceA),
  },
  {
    "QueryDosDeviceW",
    reinterpret_cast<FARPROC>(MyQueryDosDeviceW),
  },
  {
    "QueryFullProcessImageNameA",
    reinterpret_cast<FARPROC>(MyQueryFullProcessImageNameA),
  },
  {
    "QueryFullProcessImageNameW",
    reinterpret_cast<FARPROC>(MyQueryFullProcessImageNameW),
  },
  {
    "QueryIdleProcessorCycleTime",
    reinterpret_cast<FARPROC>(MyQueryIdleProcessorCycleTime),
  },
  {
    "QueryIdleProcessorCycleTimeEx",
    reinterpret_cast<FARPROC>(MyQueryIdleProcessorCycleTimeEx),
  },
  {
    "QueryInformationJobObject",
    reinterpret_cast<FARPROC>(MyQueryInformationJobObject),
  },
  {
    "QueryIoRateControlInformationJobObject",
    reinterpret_cast<FARPROC>(MyQueryIoRateControlInformationJobObject),
  },
  {
    "QueryMemoryResourceNotification",
    reinterpret_cast<FARPROC>(MyQueryMemoryResourceNotification),
  },
  {
    "QueryPerformanceCounter",
    reinterpret_cast<FARPROC>(MyQueryPerformanceCounter),
  },
  {
    "QueryPerformanceFrequency",
    reinterpret_cast<FARPROC>(MyQueryPerformanceFrequency),
  },
  {
    "QueryProcessAffinityUpdateMode",
    reinterpret_cast<FARPROC>(MyQueryProcessAffinityUpdateMode),
  },
  {
    "QueryProcessCycleTime",
    reinterpret_cast<FARPROC>(MyQueryProcessCycleTime),
  },
  {
    "QueryProtectedPolicy",
    reinterpret_cast<FARPROC>(MyQueryProtectedPolicy),
  },
  {
    "QueryThreadCycleTime",
    reinterpret_cast<FARPROC>(MyQueryThreadCycleTime),
  },
  {
    "QueryThreadProfiling",
    reinterpret_cast<FARPROC>(MyQueryThreadProfiling),
  },
  {
    "QueryThreadpoolStackInformation",
    reinterpret_cast<FARPROC>(MyQueryThreadpoolStackInformation),
  },
  {
    "QueryUmsThreadInformation",
    reinterpret_cast<FARPROC>(MyQueryUmsThreadInformation),
  },
  {
    "QueryUnbiasedInterruptTime",
    reinterpret_cast<FARPROC>(MyQueryUnbiasedInterruptTime),
  },
  {
    "QueueUserAPC",
    reinterpret_cast<FARPROC>(MyQueueUserAPC),
  },
  {
    "QueueUserWorkItem",
    reinterpret_cast<FARPROC>(MyQueueUserWorkItem),
  },
  {
    "RaiseException",
    reinterpret_cast<FARPROC>(MyRaiseException),
  },
  {
    "RaiseFailFastException",
    reinterpret_cast<FARPROC>(MyRaiseFailFastException),
  },
  {
    "RaiseInvalid16BitExeError",
    reinterpret_cast<FARPROC>(MyRaiseInvalid16BitExeError),
  },
  {
    "ReOpenFile",
    reinterpret_cast<FARPROC>(MyReOpenFile),
  },
  {
    "ReadConsoleA",
    reinterpret_cast<FARPROC>(MyReadConsoleA),
  },
  {
    "ReadConsoleInputA",
    reinterpret_cast<FARPROC>(MyReadConsoleInputA),
  },
  {
    "ReadConsoleInputExA",
    reinterpret_cast<FARPROC>(MyReadConsoleInputExA),
  },
  {
    "ReadConsoleInputExW",
    reinterpret_cast<FARPROC>(MyReadConsoleInputExW),
  },
  {
    "ReadConsoleInputW",
    reinterpret_cast<FARPROC>(MyReadConsoleInputW),
  },
  {
    "ReadConsoleOutputA",
    reinterpret_cast<FARPROC>(MyReadConsoleOutputA),
  },
  {
    "ReadConsoleOutputAttribute",
    reinterpret_cast<FARPROC>(MyReadConsoleOutputAttribute),
  },
  {
    "ReadConsoleOutputCharacterA",
    reinterpret_cast<FARPROC>(MyReadConsoleOutputCharacterA),
  },
  {
    "ReadConsoleOutputCharacterW",
    reinterpret_cast<FARPROC>(MyReadConsoleOutputCharacterW),
  },
  {
    "ReadConsoleOutputW",
    reinterpret_cast<FARPROC>(MyReadConsoleOutputW),
  },
  {
    "ReadConsoleW",
    reinterpret_cast<FARPROC>(MyReadConsoleW),
  },
  {
    "ReadDirectoryChangesExW",
    reinterpret_cast<FARPROC>(MyReadDirectoryChangesExW),
  },
  {
    "ReadDirectoryChangesW",
    reinterpret_cast<FARPROC>(MyReadDirectoryChangesW),
  },
  {
    "ReadFile",
    reinterpret_cast<FARPROC>(MyReadFile),
  },
  {
    "ReadFileEx",
    reinterpret_cast<FARPROC>(MyReadFileEx),
  },
  {
    "ReadFileScatter",
    reinterpret_cast<FARPROC>(MyReadFileScatter),
  },
  {
    "ReadProcessMemory",
    reinterpret_cast<FARPROC>(MyReadProcessMemory),
  },
  {
    "ReadThreadProfilingData",
    reinterpret_cast<FARPROC>(MyReadThreadProfilingData),
  },
  {
    "ReclaimVirtualMemory",
    reinterpret_cast<FARPROC>(MyReclaimVirtualMemory),
  },
  {
    "RegCloseKey",
    reinterpret_cast<FARPROC>(MyRegCloseKey),
  },
  {
    "RegCopyTreeW",
    reinterpret_cast<FARPROC>(MyRegCopyTreeW),
  },
  {
    "RegCreateKeyExA",
    reinterpret_cast<FARPROC>(MyRegCreateKeyExA),
  },
  {
    "RegCreateKeyExW",
    reinterpret_cast<FARPROC>(MyRegCreateKeyExW),
  },
  {
    "RegDeleteKeyExA",
    reinterpret_cast<FARPROC>(MyRegDeleteKeyExA),
  },
  {
    "RegDeleteKeyExW",
    reinterpret_cast<FARPROC>(MyRegDeleteKeyExW),
  },
  {
    "RegDeleteTreeA",
    reinterpret_cast<FARPROC>(MyRegDeleteTreeA),
  },
  {
    "RegDeleteTreeW",
    reinterpret_cast<FARPROC>(MyRegDeleteTreeW),
  },
  {
    "RegDeleteValueA",
    reinterpret_cast<FARPROC>(MyRegDeleteValueA),
  },
  {
    "RegDeleteValueW",
    reinterpret_cast<FARPROC>(MyRegDeleteValueW),
  },
  {
    "RegDisablePredefinedCacheEx",
    reinterpret_cast<FARPROC>(MyRegDisablePredefinedCacheEx),
  },
  {
    "RegEnumKeyExA",
    reinterpret_cast<FARPROC>(MyRegEnumKeyExA),
  },
  {
    "RegEnumKeyExW",
    reinterpret_cast<FARPROC>(MyRegEnumKeyExW),
  },
  {
    "RegEnumValueA",
    reinterpret_cast<FARPROC>(MyRegEnumValueA),
  },
  {
    "RegEnumValueW",
    reinterpret_cast<FARPROC>(MyRegEnumValueW),
  },
  {
    "RegFlushKey",
    reinterpret_cast<FARPROC>(MyRegFlushKey),
  },
  {
    "RegGetKeySecurity",
    reinterpret_cast<FARPROC>(MyRegGetKeySecurity),
  },
  {
    "RegGetValueA",
    reinterpret_cast<FARPROC>(MyRegGetValueA),
  },
  {
    "RegGetValueW",
    reinterpret_cast<FARPROC>(MyRegGetValueW),
  },
  {
    "RegLoadKeyA",
    reinterpret_cast<FARPROC>(MyRegLoadKeyA),
  },
  {
    "RegLoadKeyW",
    reinterpret_cast<FARPROC>(MyRegLoadKeyW),
  },
  {
    "RegLoadMUIStringA",
    reinterpret_cast<FARPROC>(MyRegLoadMUIStringA),
  },
  {
    "RegLoadMUIStringW",
    reinterpret_cast<FARPROC>(MyRegLoadMUIStringW),
  },
  {
    "RegNotifyChangeKeyValue",
    reinterpret_cast<FARPROC>(MyRegNotifyChangeKeyValue),
  },
  {
    "RegOpenCurrentUser",
    reinterpret_cast<FARPROC>(MyRegOpenCurrentUser),
  },
  {
    "RegOpenKeyExA",
    reinterpret_cast<FARPROC>(MyRegOpenKeyExA),
  },
  {
    "RegOpenKeyExW",
    reinterpret_cast<FARPROC>(MyRegOpenKeyExW),
  },
  {
    "RegOpenUserClassesRoot",
    reinterpret_cast<FARPROC>(MyRegOpenUserClassesRoot),
  },
  {
    "RegQueryInfoKeyA",
    reinterpret_cast<FARPROC>(MyRegQueryInfoKeyA),
  },
  {
    "RegQueryInfoKeyW",
    reinterpret_cast<FARPROC>(MyRegQueryInfoKeyW),
  },
  {
    "RegQueryValueExA",
    reinterpret_cast<FARPROC>(MyRegQueryValueExA),
  },
  {
    "RegQueryValueExW",
    reinterpret_cast<FARPROC>(MyRegQueryValueExW),
  },
  {
    "RegRestoreKeyA",
    reinterpret_cast<FARPROC>(MyRegRestoreKeyA),
  },
  {
    "RegRestoreKeyW",
    reinterpret_cast<FARPROC>(MyRegRestoreKeyW),
  },
  {
    "RegSaveKeyExA",
    reinterpret_cast<FARPROC>(MyRegSaveKeyExA),
  },
  {
    "RegSaveKeyExW",
    reinterpret_cast<FARPROC>(MyRegSaveKeyExW),
  },
  {
    "RegSetKeySecurity",
    reinterpret_cast<FARPROC>(MyRegSetKeySecurity),
  },
  {
    "RegSetValueExA",
    reinterpret_cast<FARPROC>(MyRegSetValueExA),
  },
  {
    "RegSetValueExW",
    reinterpret_cast<FARPROC>(MyRegSetValueExW),
  },
  {
    "RegUnLoadKeyA",
    reinterpret_cast<FARPROC>(MyRegUnLoadKeyA),
  },
  {
    "RegUnLoadKeyW",
    reinterpret_cast<FARPROC>(MyRegUnLoadKeyW),
  },
  {
    "RegisterApplicationRecoveryCallback",
    reinterpret_cast<FARPROC>(MyRegisterApplicationRecoveryCallback),
  },
  {
    "RegisterApplicationRestart",
    reinterpret_cast<FARPROC>(MyRegisterApplicationRestart),
  },
  {
    "RegisterBadMemoryNotification",
    reinterpret_cast<FARPROC>(MyRegisterBadMemoryNotification),
  },
  {
    "RegisterWaitForInputIdle",
    reinterpret_cast<FARPROC>(MyRegisterWaitForInputIdle),
  },
  {
    "RegisterWaitForSingleObject",
    reinterpret_cast<FARPROC>(MyRegisterWaitForSingleObject),
  },
  {
    "RegisterWaitForSingleObjectEx",
    reinterpret_cast<FARPROC>(MyRegisterWaitForSingleObjectEx),
  },
  {
    "RegisterWaitUntilOOBECompleted",
    reinterpret_cast<FARPROC>(MyRegisterWaitUntilOOBECompleted),
  },
  {
    "ReleaseActCtx",
    reinterpret_cast<FARPROC>(MyReleaseActCtx),
  },
  {
    "ReleaseMutex",
    reinterpret_cast<FARPROC>(MyReleaseMutex),
  },
  {
    "ReleaseMutexWhenCallbackReturns",
    reinterpret_cast<FARPROC>(MyReleaseMutexWhenCallbackReturns),
  },
  {
    "ReleaseSRWLockExclusive",
    reinterpret_cast<FARPROC>(MyReleaseSRWLockExclusive),
  },
  {
    "ReleaseSRWLockShared",
    reinterpret_cast<FARPROC>(MyReleaseSRWLockShared),
  },
  {
    "ReleaseSemaphore",
    reinterpret_cast<FARPROC>(MyReleaseSemaphore),
  },
  {
    "ReleaseSemaphoreWhenCallbackReturns",
    reinterpret_cast<FARPROC>(MyReleaseSemaphoreWhenCallbackReturns),
  },
  {
    "RemoveDirectoryA",
    reinterpret_cast<FARPROC>(MyRemoveDirectoryA),
  },
  {
    "RemoveDirectoryTransactedA",
    reinterpret_cast<FARPROC>(MyRemoveDirectoryTransactedA),
  },
  {
    "RemoveDirectoryTransactedW",
    reinterpret_cast<FARPROC>(MyRemoveDirectoryTransactedW),
  },
  {
    "RemoveDirectoryW",
    reinterpret_cast<FARPROC>(MyRemoveDirectoryW),
  },
  {
    "RemoveDllDirectory",
    reinterpret_cast<FARPROC>(MyRemoveDllDirectory),
  },
  {
    "RemoveSecureMemoryCacheCallback",
    reinterpret_cast<FARPROC>(MyRemoveSecureMemoryCacheCallback),
  },
  {
    "RemoveVectoredContinueHandler",
    reinterpret_cast<FARPROC>(MyRemoveVectoredContinueHandler),
  },
  {
    "RemoveVectoredExceptionHandler",
    reinterpret_cast<FARPROC>(MyRemoveVectoredExceptionHandler),
  },
  {
    "ReplaceFileA",
    reinterpret_cast<FARPROC>(MyReplaceFileA),
  },
  {
    "ReplaceFileW",
    reinterpret_cast<FARPROC>(MyReplaceFileW),
  },
  {
    "RequestWakeupLatency",
    reinterpret_cast<FARPROC>(MyRequestWakeupLatency),
  },
  {
    "ResetEvent",
    reinterpret_cast<FARPROC>(MyResetEvent),
  },
  {
    "ResetWriteWatch",
    reinterpret_cast<FARPROC>(MyResetWriteWatch),
  },
  {
    "ResizePseudoConsole",
    reinterpret_cast<FARPROC>(MyResizePseudoConsole),
  },
  {
    "ResolveDelayLoadedAPI",
    reinterpret_cast<FARPROC>(MyResolveDelayLoadedAPI),
  },
  {
    "ResolveDelayLoadsFromDll",
    reinterpret_cast<FARPROC>(MyResolveDelayLoadsFromDll),
  },
  {
    "ResolveLocaleName",
    reinterpret_cast<FARPROC>(MyResolveLocaleName),
  },
  {
    "ResumeThread",
    reinterpret_cast<FARPROC>(MyResumeThread),
  },
  {
    "RtlAddFunctionTable",
    reinterpret_cast<FARPROC>(MyRtlAddFunctionTable),
  },
  {
    "RtlCaptureContext",
    reinterpret_cast<FARPROC>(MyRtlCaptureContext),
  },
  {
    "RtlCaptureStackBackTrace",
    reinterpret_cast<FARPROC>(MyRtlCaptureStackBackTrace),
  },
  {
    "RtlCompareMemory",
    reinterpret_cast<FARPROC>(MyRtlCompareMemory),
  },
  {
    "RtlCopyMemory",
    reinterpret_cast<FARPROC>(MyRtlCopyMemory),
  },
  {
    "RtlDeleteFunctionTable",
    reinterpret_cast<FARPROC>(MyRtlDeleteFunctionTable),
  },
  {
    "RtlFillMemory",
    reinterpret_cast<FARPROC>(MyRtlFillMemory),
  },
  {
    "RtlInstallFunctionTableCallback",
    reinterpret_cast<FARPROC>(MyRtlInstallFunctionTableCallback),
  },
  {
    "RtlLookupFunctionEntry",
    reinterpret_cast<FARPROC>(MyRtlLookupFunctionEntry),
  },
  {
    "RtlMoveMemory",
    reinterpret_cast<FARPROC>(MyRtlMoveMemory),
  },
  {
    "RtlPcToFileHeader",
    reinterpret_cast<FARPROC>(MyRtlPcToFileHeader),
  },
  {
    "RtlRaiseException",
    reinterpret_cast<FARPROC>(MyRtlRaiseException),
  },
  {
    "RtlRestoreContext",
    reinterpret_cast<FARPROC>(MyRtlRestoreContext),
  },
  {
    "RtlUnwind",
    reinterpret_cast<FARPROC>(MyRtlUnwind),
  },
  {
    "RtlUnwindEx",
    reinterpret_cast<FARPROC>(MyRtlUnwindEx),
  },
  {
    "RtlVirtualUnwind",
    reinterpret_cast<FARPROC>(MyRtlVirtualUnwind),
  },
  {
    "RtlZeroMemory",
    reinterpret_cast<FARPROC>(MyRtlZeroMemory),
  },
  {
    "ScrollConsoleScreenBufferA",
    reinterpret_cast<FARPROC>(MyScrollConsoleScreenBufferA),
  },
  {
    "ScrollConsoleScreenBufferW",
    reinterpret_cast<FARPROC>(MyScrollConsoleScreenBufferW),
  },
  {
    "SearchPathA",
    reinterpret_cast<FARPROC>(MySearchPathA),
  },
  {
    "SearchPathW",
    reinterpret_cast<FARPROC>(MySearchPathW),
  },
  {
    "SetCachedSigningLevel",
    reinterpret_cast<FARPROC>(MySetCachedSigningLevel),
  },
  {
    "SetCalendarInfoA",
    reinterpret_cast<FARPROC>(MySetCalendarInfoA),
  },
  {
    "SetCalendarInfoW",
    reinterpret_cast<FARPROC>(MySetCalendarInfoW),
  },
  {
    "SetComPlusPackageInstallStatus",
    reinterpret_cast<FARPROC>(MySetComPlusPackageInstallStatus),
  },
  {
    "SetCommBreak",
    reinterpret_cast<FARPROC>(MySetCommBreak),
  },
  {
    "SetCommConfig",
    reinterpret_cast<FARPROC>(MySetCommConfig),
  },
  {
    "SetCommMask",
    reinterpret_cast<FARPROC>(MySetCommMask),
  },
  {
    "SetCommState",
    reinterpret_cast<FARPROC>(MySetCommState),
  },
  {
    "SetCommTimeouts",
    reinterpret_cast<FARPROC>(MySetCommTimeouts),
  },
  {
    "SetComputerNameA",
    reinterpret_cast<FARPROC>(MySetComputerNameA),
  },
  {
    "SetComputerNameEx2W",
    reinterpret_cast<FARPROC>(MySetComputerNameEx2W),
  },
  {
    "SetComputerNameExA",
    reinterpret_cast<FARPROC>(MySetComputerNameExA),
  },
  {
    "SetComputerNameExW",
    reinterpret_cast<FARPROC>(MySetComputerNameExW),
  },
  {
    "SetComputerNameW",
    reinterpret_cast<FARPROC>(MySetComputerNameW),
  },
  {
    "SetConsoleActiveScreenBuffer",
    reinterpret_cast<FARPROC>(MySetConsoleActiveScreenBuffer),
  },
  {
    "SetConsoleCP",
    reinterpret_cast<FARPROC>(MySetConsoleCP),
  },
  {
    "SetConsoleCtrlHandler",
    reinterpret_cast<FARPROC>(MySetConsoleCtrlHandler),
  },
  {
    "SetConsoleCursor",
    reinterpret_cast<FARPROC>(MySetConsoleCursor),
  },
  {
    "SetConsoleCursorInfo",
    reinterpret_cast<FARPROC>(MySetConsoleCursorInfo),
  },
  {
    "SetConsoleCursorMode",
    reinterpret_cast<FARPROC>(MySetConsoleCursorMode),
  },
  {
    "SetConsoleDisplayMode",
    reinterpret_cast<FARPROC>(MySetConsoleDisplayMode),
  },
  {
    "SetConsoleHistoryInfo",
    reinterpret_cast<FARPROC>(MySetConsoleHistoryInfo),
  },
  {
    "SetConsoleMaximumWindowSize",
    reinterpret_cast<FARPROC>(MySetConsoleMaximumWindowSize),
  },
  {
    "SetConsoleMenuClose",
    reinterpret_cast<FARPROC>(MySetConsoleMenuClose),
  },
  {
    "SetConsoleMode",
    reinterpret_cast<FARPROC>(MySetConsoleMode),
  },
  {
    "SetConsoleNlsMode",
    reinterpret_cast<FARPROC>(MySetConsoleNlsMode),
  },
  {
    "SetConsoleOutputCP",
    reinterpret_cast<FARPROC>(MySetConsoleOutputCP),
  },
  {
    "SetConsoleScreenBufferInfoEx",
    reinterpret_cast<FARPROC>(MySetConsoleScreenBufferInfoEx),
  },
  {
    "SetConsoleScreenBufferSize",
    reinterpret_cast<FARPROC>(MySetConsoleScreenBufferSize),
  },
  {
    "SetConsoleTextAttribute",
    reinterpret_cast<FARPROC>(MySetConsoleTextAttribute),
  },
  {
    "SetConsoleTitleA",
    reinterpret_cast<FARPROC>(MySetConsoleTitleA),
  },
  {
    "SetConsoleTitleW",
    reinterpret_cast<FARPROC>(MySetConsoleTitleW),
  },
  {
    "SetConsoleWindowInfo",
    reinterpret_cast<FARPROC>(MySetConsoleWindowInfo),
  },
  {
    "SetCriticalSectionSpinCount",
    reinterpret_cast<FARPROC>(MySetCriticalSectionSpinCount),
  },
  {
    "SetCurrentConsoleFontEx",
    reinterpret_cast<FARPROC>(MySetCurrentConsoleFontEx),
  },
  {
    "SetCurrentDirectoryA",
    reinterpret_cast<FARPROC>(MySetCurrentDirectoryA),
  },
  {
    "SetCurrentDirectoryW",
    reinterpret_cast<FARPROC>(MySetCurrentDirectoryW),
  },
  {
    "SetDefaultCommConfigA",
    reinterpret_cast<FARPROC>(MySetDefaultCommConfigA),
  },
  {
    "SetDefaultCommConfigW",
    reinterpret_cast<FARPROC>(MySetDefaultCommConfigW),
  },
  {
    "SetDefaultDllDirectories",
    reinterpret_cast<FARPROC>(MySetDefaultDllDirectories),
  },
  {
    "SetDllDirectoryA",
    reinterpret_cast<FARPROC>(MySetDllDirectoryA),
  },
  {
    "SetDllDirectoryW",
    reinterpret_cast<FARPROC>(MySetDllDirectoryW),
  },
  {
    "SetDynamicTimeZoneInformation",
    reinterpret_cast<FARPROC>(MySetDynamicTimeZoneInformation),
  },
  {
    "SetEndOfFile",
    reinterpret_cast<FARPROC>(MySetEndOfFile),
  },
  {
    "SetEnvironmentStringsW",
    reinterpret_cast<FARPROC>(MySetEnvironmentStringsW),
  },
  {
    "SetEnvironmentVariableA",
    reinterpret_cast<FARPROC>(MySetEnvironmentVariableA),
  },
  {
    "SetEnvironmentVariableW",
    reinterpret_cast<FARPROC>(MySetEnvironmentVariableW),
  },
  {
    "SetErrorMode",
    reinterpret_cast<FARPROC>(MySetErrorMode),
  },
  {
    "SetEvent",
    reinterpret_cast<FARPROC>(MySetEvent),
  },
  {
    "SetEventWhenCallbackReturns",
    reinterpret_cast<FARPROC>(MySetEventWhenCallbackReturns),
  },
  {
    "SetFileApisToANSI",
    reinterpret_cast<FARPROC>(MySetFileApisToANSI),
  },
  {
    "SetFileApisToOEM",
    reinterpret_cast<FARPROC>(MySetFileApisToOEM),
  },
  {
    "SetFileAttributesA",
    reinterpret_cast<FARPROC>(MySetFileAttributesA),
  },
  {
    "SetFileAttributesTransactedA",
    reinterpret_cast<FARPROC>(MySetFileAttributesTransactedA),
  },
  {
    "SetFileAttributesTransactedW",
    reinterpret_cast<FARPROC>(MySetFileAttributesTransactedW),
  },
  {
    "SetFileAttributesW",
    reinterpret_cast<FARPROC>(MySetFileAttributesW),
  },
  {
    "SetFileBandwidthReservation",
    reinterpret_cast<FARPROC>(MySetFileBandwidthReservation),
  },
  {
    "SetFileCompletionNotificationModes",
    reinterpret_cast<FARPROC>(MySetFileCompletionNotificationModes),
  },
  {
    "SetFileInformationByHandle",
    reinterpret_cast<FARPROC>(MySetFileInformationByHandle),
  },
  {
    "SetFileIoOverlappedRange",
    reinterpret_cast<FARPROC>(MySetFileIoOverlappedRange),
  },
  {
    "SetFilePointer",
    reinterpret_cast<FARPROC>(MySetFilePointer),
  },
  {
    "SetFilePointerEx",
    reinterpret_cast<FARPROC>(MySetFilePointerEx),
  },
  {
    "SetFileShortNameA",
    reinterpret_cast<FARPROC>(MySetFileShortNameA),
  },
  {
    "SetFileShortNameW",
    reinterpret_cast<FARPROC>(MySetFileShortNameW),
  },
  {
    "SetFileTime",
    reinterpret_cast<FARPROC>(MySetFileTime),
  },
  {
    "SetFileValidData",
    reinterpret_cast<FARPROC>(MySetFileValidData),
  },
  {
    "SetFirmwareEnvironmentVariableA",
    reinterpret_cast<FARPROC>(MySetFirmwareEnvironmentVariableA),
  },
  {
    "SetFirmwareEnvironmentVariableExA",
    reinterpret_cast<FARPROC>(MySetFirmwareEnvironmentVariableExA),
  },
  {
    "SetFirmwareEnvironmentVariableExW",
    reinterpret_cast<FARPROC>(MySetFirmwareEnvironmentVariableExW),
  },
  {
    "SetFirmwareEnvironmentVariableW",
    reinterpret_cast<FARPROC>(MySetFirmwareEnvironmentVariableW),
  },
  {
    "SetHandleCount",
    reinterpret_cast<FARPROC>(MySetHandleCount),
  },
  {
    "SetHandleInformation",
    reinterpret_cast<FARPROC>(MySetHandleInformation),
  },
  {
    "SetInformationJobObject",
    reinterpret_cast<FARPROC>(MySetInformationJobObject),
  },
  {
    "SetIoRateControlInformationJobObject",
    reinterpret_cast<FARPROC>(MySetIoRateControlInformationJobObject),
  },
  {
    "SetLastError",
    reinterpret_cast<FARPROC>(MySetLastError),
  },
  {
    "SetLocalTime",
    reinterpret_cast<FARPROC>(MySetLocalTime),
  },
  {
    "SetLocaleInfoA",
    reinterpret_cast<FARPROC>(MySetLocaleInfoA),
  },
  {
    "SetLocaleInfoW",
    reinterpret_cast<FARPROC>(MySetLocaleInfoW),
  },
  {
    "SetMailslotInfo",
    reinterpret_cast<FARPROC>(MySetMailslotInfo),
  },
  {
    "SetNamedPipeHandleState",
    reinterpret_cast<FARPROC>(MySetNamedPipeHandleState),
  },
  {
    "SetPriorityClass",
    reinterpret_cast<FARPROC>(MySetPriorityClass),
  },
  {
    "SetProcessAffinityMask",
    reinterpret_cast<FARPROC>(MySetProcessAffinityMask),
  },
  {
    "SetProcessAffinityUpdateMode",
    reinterpret_cast<FARPROC>(MySetProcessAffinityUpdateMode),
  },
  {
    "SetProcessDEPPolicy",
    reinterpret_cast<FARPROC>(MySetProcessDEPPolicy),
  },
  {
    "SetProcessDefaultCpuSets",
    reinterpret_cast<FARPROC>(MySetProcessDefaultCpuSets),
  },
  {
    "SetProcessDynamicEHContinuationTargets",
    reinterpret_cast<FARPROC>(MySetProcessDynamicEHContinuationTargets),
  },
  {
    "SetProcessDynamicEnforcedCetCompatibleRanges",
    reinterpret_cast<FARPROC>(MySetProcessDynamicEnforcedCetCompatibleRanges),
  },
  {
    "SetProcessInformation",
    reinterpret_cast<FARPROC>(MySetProcessInformation),
  },
  {
    "SetProcessMitigationPolicy",
    reinterpret_cast<FARPROC>(MySetProcessMitigationPolicy),
  },
  {
    "SetProcessPreferredUILanguages",
    reinterpret_cast<FARPROC>(MySetProcessPreferredUILanguages),
  },
  {
    "SetProcessPriorityBoost",
    reinterpret_cast<FARPROC>(MySetProcessPriorityBoost),
  },
  {
    "SetProcessShutdownParameters",
    reinterpret_cast<FARPROC>(MySetProcessShutdownParameters),
  },
  {
    "SetProcessWorkingSetSize",
    reinterpret_cast<FARPROC>(MySetProcessWorkingSetSize),
  },
  {
    "SetProcessWorkingSetSizeEx",
    reinterpret_cast<FARPROC>(MySetProcessWorkingSetSizeEx),
  },
  {
    "SetProtectedPolicy",
    reinterpret_cast<FARPROC>(MySetProtectedPolicy),
  },
  {
    "SetSearchPathMode",
    reinterpret_cast<FARPROC>(MySetSearchPathMode),
  },
  {
    "SetStdHandle",
    reinterpret_cast<FARPROC>(MySetStdHandle),
  },
  {
    "SetStdHandleEx",
    reinterpret_cast<FARPROC>(MySetStdHandleEx),
  },
  {
    "SetSystemFileCacheSize",
    reinterpret_cast<FARPROC>(MySetSystemFileCacheSize),
  },
  {
    "SetSystemPowerState",
    reinterpret_cast<FARPROC>(MySetSystemPowerState),
  },
  {
    "SetSystemTime",
    reinterpret_cast<FARPROC>(MySetSystemTime),
  },
  {
    "SetSystemTimeAdjustment",
    reinterpret_cast<FARPROC>(MySetSystemTimeAdjustment),
  },
  {
    "SetTapeParameters",
    reinterpret_cast<FARPROC>(MySetTapeParameters),
  },
  {
    "SetTapePosition",
    reinterpret_cast<FARPROC>(MySetTapePosition),
  },
  {
    "SetTermsrvAppInstallMode",
    reinterpret_cast<FARPROC>(MySetTermsrvAppInstallMode),
  },
  {
    "SetThreadAffinityMask",
    reinterpret_cast<FARPROC>(MySetThreadAffinityMask),
  },
  {
    "SetThreadDescription",
    reinterpret_cast<FARPROC>(MySetThreadDescription),
  },
  {
    "SetThreadErrorMode",
    reinterpret_cast<FARPROC>(MySetThreadErrorMode),
  },
  {
    "SetThreadExecutionState",
    reinterpret_cast<FARPROC>(MySetThreadExecutionState),
  },
  {
    "SetThreadGroupAffinity",
    reinterpret_cast<FARPROC>(MySetThreadGroupAffinity),
  },
  {
    "SetThreadIdealProcessor",
    reinterpret_cast<FARPROC>(MySetThreadIdealProcessor),
  },
  {
    "SetThreadIdealProcessorEx",
    reinterpret_cast<FARPROC>(MySetThreadIdealProcessorEx),
  },
  {
    "SetThreadInformation",
    reinterpret_cast<FARPROC>(MySetThreadInformation),
  },
  {
    "SetThreadLocale",
    reinterpret_cast<FARPROC>(MySetThreadLocale),
  },
  {
    "SetThreadPreferredUILanguages",
    reinterpret_cast<FARPROC>(MySetThreadPreferredUILanguages),
  },
  {
    "SetThreadPriority",
    reinterpret_cast<FARPROC>(MySetThreadPriority),
  },
  {
    "SetThreadPriorityBoost",
    reinterpret_cast<FARPROC>(MySetThreadPriorityBoost),
  },
  {
    "SetThreadSelectedCpuSets",
    reinterpret_cast<FARPROC>(MySetThreadSelectedCpuSets),
  },
  {
    "SetThreadStackGuarantee",
    reinterpret_cast<FARPROC>(MySetThreadStackGuarantee),
  },
  {
    "SetThreadToken",
    reinterpret_cast<FARPROC>(MySetThreadToken),
  },
  {
    "SetThreadUILanguage",
    reinterpret_cast<FARPROC>(MySetThreadUILanguage),
  },
  {
    "SetThreadpoolStackInformation",
    reinterpret_cast<FARPROC>(MySetThreadpoolStackInformation),
  },
  {
    "SetThreadpoolThreadMaximum",
    reinterpret_cast<FARPROC>(MySetThreadpoolThreadMaximum),
  },
  {
    "SetThreadpoolThreadMinimum",
    reinterpret_cast<FARPROC>(MySetThreadpoolThreadMinimum),
  },
  {
    "SetThreadpoolTimer",
    reinterpret_cast<FARPROC>(MySetThreadpoolTimer),
  },
  {
    "SetThreadpoolTimerEx",
    reinterpret_cast<FARPROC>(MySetThreadpoolTimerEx),
  },
  {
    "SetThreadpoolWait",
    reinterpret_cast<FARPROC>(MySetThreadpoolWait),
  },
  {
    "SetThreadpoolWaitEx",
    reinterpret_cast<FARPROC>(MySetThreadpoolWaitEx),
  },
  {
    "SetTimeZoneInformation",
    reinterpret_cast<FARPROC>(MySetTimeZoneInformation),
  },
  {
    "SetTimerQueueTimer",
    reinterpret_cast<FARPROC>(MySetTimerQueueTimer),
  },
  {
    "SetUmsThreadInformation",
    reinterpret_cast<FARPROC>(MySetUmsThreadInformation),
  },
  {
    "SetUnhandledExceptionFilter",
    reinterpret_cast<FARPROC>(MySetUnhandledExceptionFilter),
  },
  {
    "SetUserGeoID",
    reinterpret_cast<FARPROC>(MySetUserGeoID),
  },
  {
    "SetUserGeoName",
    reinterpret_cast<FARPROC>(MySetUserGeoName),
  },
  {
    "SetVolumeLabelA",
    reinterpret_cast<FARPROC>(MySetVolumeLabelA),
  },
  {
    "SetVolumeLabelW",
    reinterpret_cast<FARPROC>(MySetVolumeLabelW),
  },
  {
    "SetVolumeMountPointA",
    reinterpret_cast<FARPROC>(MySetVolumeMountPointA),
  },
  {
    "SetVolumeMountPointW",
    reinterpret_cast<FARPROC>(MySetVolumeMountPointW),
  },
  {
    "SetWaitableTimer",
    reinterpret_cast<FARPROC>(MySetWaitableTimer),
  },
  {
    "SetWaitableTimerEx",
    reinterpret_cast<FARPROC>(MySetWaitableTimerEx),
  },
  {
    "SetXStateFeaturesMask",
    reinterpret_cast<FARPROC>(MySetXStateFeaturesMask),
  },
  {
    "SetupComm",
    reinterpret_cast<FARPROC>(MySetupComm),
  },
  {
    "SignalObjectAndWait",
    reinterpret_cast<FARPROC>(MySignalObjectAndWait),
  },
  {
    "SizeofResource",
    reinterpret_cast<FARPROC>(MySizeofResource),
  },
  {
    "Sleep",
    reinterpret_cast<FARPROC>(MySleep),
  },
  {
    "SleepConditionVariableCS",
    reinterpret_cast<FARPROC>(MySleepConditionVariableCS),
  },
  {
    "SleepConditionVariableSRW",
    reinterpret_cast<FARPROC>(MySleepConditionVariableSRW),
  },
  {
    "SleepEx",
    reinterpret_cast<FARPROC>(MySleepEx),
  },
  {
    "StartThreadpoolIo",
    reinterpret_cast<FARPROC>(MyStartThreadpoolIo),
  },
  {
    "SubmitThreadpoolWork",
    reinterpret_cast<FARPROC>(MySubmitThreadpoolWork),
  },
  {
    "SuspendThread",
    reinterpret_cast<FARPROC>(MySuspendThread),
  },
  {
    "SwitchToFiber",
    reinterpret_cast<FARPROC>(MySwitchToFiber),
  },
  {
    "SwitchToThread",
    reinterpret_cast<FARPROC>(MySwitchToThread),
  },
  {
    "SystemTimeToFileTime",
    reinterpret_cast<FARPROC>(MySystemTimeToFileTime),
  },
  {
    "SystemTimeToTzSpecificLocalTime",
    reinterpret_cast<FARPROC>(MySystemTimeToTzSpecificLocalTime),
  },
  {
    "SystemTimeToTzSpecificLocalTimeEx",
    reinterpret_cast<FARPROC>(MySystemTimeToTzSpecificLocalTimeEx),
  },
  {
    "TerminateJobObject",
    reinterpret_cast<FARPROC>(MyTerminateJobObject),
  },
  {
    "TerminateProcess",
    reinterpret_cast<FARPROC>(MyTerminateProcess),
  },
  {
    "TerminateThread",
    reinterpret_cast<FARPROC>(MyTerminateThread),
  },
  {
    "Thread32First",
    reinterpret_cast<FARPROC>(MyThread32First),
  },
  {
    "Thread32Next",
    reinterpret_cast<FARPROC>(MyThread32Next),
  },
  {
    "TlsAlloc",
    reinterpret_cast<FARPROC>(MyTlsAlloc),
  },
  {
    "TlsFree",
    reinterpret_cast<FARPROC>(MyTlsFree),
  },
  {
    "TlsGetValue",
    reinterpret_cast<FARPROC>(MyTlsGetValue),
  },
  {
    "TlsSetValue",
    reinterpret_cast<FARPROC>(MyTlsSetValue),
  },
  {
    "Toolhelp32ReadProcessMemory",
    reinterpret_cast<FARPROC>(MyToolhelp32ReadProcessMemory),
  },
  {
    "TransactNamedPipe",
    reinterpret_cast<FARPROC>(MyTransactNamedPipe),
  },
  {
    "TransmitCommChar",
    reinterpret_cast<FARPROC>(MyTransmitCommChar),
  },
  {
    "TryAcquireSRWLockExclusive",
    reinterpret_cast<FARPROC>(MyTryAcquireSRWLockExclusive),
  },
  {
    "TryAcquireSRWLockShared",
    reinterpret_cast<FARPROC>(MyTryAcquireSRWLockShared),
  },
  {
    "TryEnterCriticalSection",
    reinterpret_cast<FARPROC>(MyTryEnterCriticalSection),
  },
  {
    "TrySubmitThreadpoolCallback",
    reinterpret_cast<FARPROC>(MyTrySubmitThreadpoolCallback),
  },
  {
    "TzSpecificLocalTimeToSystemTime",
    reinterpret_cast<FARPROC>(MyTzSpecificLocalTimeToSystemTime),
  },
  {
    "TzSpecificLocalTimeToSystemTimeEx",
    reinterpret_cast<FARPROC>(MyTzSpecificLocalTimeToSystemTimeEx),
  },
  {
    "UmsThreadYield",
    reinterpret_cast<FARPROC>(MyUmsThreadYield),
  },
  {
    "UnhandledExceptionFilter",
    reinterpret_cast<FARPROC>(MyUnhandledExceptionFilter),
  },
  {
    "UnlockFile",
    reinterpret_cast<FARPROC>(MyUnlockFile),
  },
  {
    "UnlockFileEx",
    reinterpret_cast<FARPROC>(MyUnlockFileEx),
  },
  {
    "UnmapViewOfFile",
    reinterpret_cast<FARPROC>(MyUnmapViewOfFile),
  },
  {
    "UnmapViewOfFileEx",
    reinterpret_cast<FARPROC>(MyUnmapViewOfFileEx),
  },
  {
    "UnregisterApplicationRecoveryCallback",
    reinterpret_cast<FARPROC>(MyUnregisterApplicationRecoveryCallback),
  },
  {
    "UnregisterApplicationRestart",
    reinterpret_cast<FARPROC>(MyUnregisterApplicationRestart),
  },
  {
    "UnregisterBadMemoryNotification",
    reinterpret_cast<FARPROC>(MyUnregisterBadMemoryNotification),
  },
  {
    "UnregisterWait",
    reinterpret_cast<FARPROC>(MyUnregisterWait),
  },
  {
    "UnregisterWaitEx",
    reinterpret_cast<FARPROC>(MyUnregisterWaitEx),
  },
  {
    "UnregisterWaitUntilOOBECompleted",
    reinterpret_cast<FARPROC>(MyUnregisterWaitUntilOOBECompleted),
  },
  {
    "UpdateCalendarDayOfWeek",
    reinterpret_cast<FARPROC>(MyUpdateCalendarDayOfWeek),
  },
  {
    "UpdateProcThreadAttribute",
    reinterpret_cast<FARPROC>(MyUpdateProcThreadAttribute),
  },
  {
    "UpdateResourceA",
    reinterpret_cast<FARPROC>(MyUpdateResourceA),
  },
  {
    "UpdateResourceW",
    reinterpret_cast<FARPROC>(MyUpdateResourceW),
  },
  {
    "VerLanguageNameA",
    reinterpret_cast<FARPROC>(MyVerLanguageNameA),
  },
  {
    "VerLanguageNameW",
    reinterpret_cast<FARPROC>(MyVerLanguageNameW),
  },
  {
    "VerSetConditionMask",
    reinterpret_cast<FARPROC>(MyVerSetConditionMask),
  },
  {
    "VerifyConsoleIoHandle",
    reinterpret_cast<FARPROC>(MyVerifyConsoleIoHandle),
  },
  {
    "VerifyVersionInfoA",
    reinterpret_cast<FARPROC>(MyVerifyVersionInfoA),
  },
  {
    "VerifyVersionInfoW",
    reinterpret_cast<FARPROC>(MyVerifyVersionInfoW),
  },
  {
    "VirtualAlloc",
    reinterpret_cast<FARPROC>(MyVirtualAlloc),
  },
  {
    "VirtualAllocEx",
    reinterpret_cast<FARPROC>(MyVirtualAllocEx),
  },
  {
    "VirtualAllocExNuma",
    reinterpret_cast<FARPROC>(MyVirtualAllocExNuma),
  },
  {
    "VirtualFree",
    reinterpret_cast<FARPROC>(MyVirtualFree),
  },
  {
    "VirtualFreeEx",
    reinterpret_cast<FARPROC>(MyVirtualFreeEx),
  },
  {
    "VirtualLock",
    reinterpret_cast<FARPROC>(MyVirtualLock),
  },
  {
    "VirtualProtect",
    reinterpret_cast<FARPROC>(MyVirtualProtect),
  },
  {
    "VirtualProtectEx",
    reinterpret_cast<FARPROC>(MyVirtualProtectEx),
  },
  {
    "VirtualQuery",
    reinterpret_cast<FARPROC>(MyVirtualQuery),
  },
  {
    "VirtualQueryEx",
    reinterpret_cast<FARPROC>(MyVirtualQueryEx),
  },
  {
    "VirtualUnlock",
    reinterpret_cast<FARPROC>(MyVirtualUnlock),
  },
  {
    "WTSGetActiveConsoleSessionId",
    reinterpret_cast<FARPROC>(MyWTSGetActiveConsoleSessionId),
  },
  {
    "WaitCommEvent",
    reinterpret_cast<FARPROC>(MyWaitCommEvent),
  },
  {
    "WaitForDebugEvent",
    reinterpret_cast<FARPROC>(MyWaitForDebugEvent),
  },
  {
    "WaitForDebugEventEx",
    reinterpret_cast<FARPROC>(MyWaitForDebugEventEx),
  },
  {
    "WaitForMultipleObjects",
    reinterpret_cast<FARPROC>(MyWaitForMultipleObjects),
  },
  {
    "WaitForMultipleObjectsEx",
    reinterpret_cast<FARPROC>(MyWaitForMultipleObjectsEx),
  },
  {
    "WaitForSingleObject",
    reinterpret_cast<FARPROC>(MyWaitForSingleObject),
  },
  {
    "WaitForSingleObjectEx",
    reinterpret_cast<FARPROC>(MyWaitForSingleObjectEx),
  },
  {
    "WaitForThreadpoolIoCallbacks",
    reinterpret_cast<FARPROC>(MyWaitForThreadpoolIoCallbacks),
  },
  {
    "WaitForThreadpoolTimerCallbacks",
    reinterpret_cast<FARPROC>(MyWaitForThreadpoolTimerCallbacks),
  },
  {
    "WaitForThreadpoolWaitCallbacks",
    reinterpret_cast<FARPROC>(MyWaitForThreadpoolWaitCallbacks),
  },
  {
    "WaitForThreadpoolWorkCallbacks",
    reinterpret_cast<FARPROC>(MyWaitForThreadpoolWorkCallbacks),
  },
  {
    "WaitNamedPipeA",
    reinterpret_cast<FARPROC>(MyWaitNamedPipeA),
  },
  {
    "WaitNamedPipeW",
    reinterpret_cast<FARPROC>(MyWaitNamedPipeW),
  },
  {
    "WakeAllConditionVariable",
    reinterpret_cast<FARPROC>(MyWakeAllConditionVariable),
  },
  {
    "WakeConditionVariable",
    reinterpret_cast<FARPROC>(MyWakeConditionVariable),
  },
  {
    "WerGetFlags",
    reinterpret_cast<FARPROC>(MyWerGetFlags),
  },
  {
    "WerRegisterAdditionalProcess",
    reinterpret_cast<FARPROC>(MyWerRegisterAdditionalProcess),
  },
  {
    "WerRegisterAppLocalDump",
    reinterpret_cast<FARPROC>(MyWerRegisterAppLocalDump),
  },
  {
    "WerRegisterCustomMetadata",
    reinterpret_cast<FARPROC>(MyWerRegisterCustomMetadata),
  },
  {
    "WerRegisterExcludedMemoryBlock",
    reinterpret_cast<FARPROC>(MyWerRegisterExcludedMemoryBlock),
  },
  {
    "WerRegisterFile",
    reinterpret_cast<FARPROC>(MyWerRegisterFile),
  },
  {
    "WerRegisterMemoryBlock",
    reinterpret_cast<FARPROC>(MyWerRegisterMemoryBlock),
  },
  {
    "WerRegisterRuntimeExceptionModule",
    reinterpret_cast<FARPROC>(MyWerRegisterRuntimeExceptionModule),
  },
  {
    "WerSetFlags",
    reinterpret_cast<FARPROC>(MyWerSetFlags),
  },
  {
    "WerUnregisterAdditionalProcess",
    reinterpret_cast<FARPROC>(MyWerUnregisterAdditionalProcess),
  },
  {
    "WerUnregisterAppLocalDump",
    reinterpret_cast<FARPROC>(MyWerUnregisterAppLocalDump),
  },
  {
    "WerUnregisterCustomMetadata",
    reinterpret_cast<FARPROC>(MyWerUnregisterCustomMetadata),
  },
  {
    "WerUnregisterExcludedMemoryBlock",
    reinterpret_cast<FARPROC>(MyWerUnregisterExcludedMemoryBlock),
  },
  {
    "WerUnregisterFile",
    reinterpret_cast<FARPROC>(MyWerUnregisterFile),
  },
  {
    "WerUnregisterMemoryBlock",
    reinterpret_cast<FARPROC>(MyWerUnregisterMemoryBlock),
  },
  {
    "WerUnregisterRuntimeExceptionModule",
    reinterpret_cast<FARPROC>(MyWerUnregisterRuntimeExceptionModule),
  },
  {
    "WideCharToMultiByte",
    reinterpret_cast<FARPROC>(MyWideCharToMultiByte),
  },
  {
    "WinExec",
    reinterpret_cast<FARPROC>(MyWinExec),
  },
  {
    "Wow64DisableWow64FsRedirection",
    reinterpret_cast<FARPROC>(MyWow64DisableWow64FsRedirection),
  },
  {
    "Wow64EnableWow64FsRedirection",
    reinterpret_cast<FARPROC>(MyWow64EnableWow64FsRedirection),
  },
  {
    "Wow64GetThreadContext",
    reinterpret_cast<FARPROC>(MyWow64GetThreadContext),
  },
  {
    "Wow64GetThreadSelectorEntry",
    reinterpret_cast<FARPROC>(MyWow64GetThreadSelectorEntry),
  },
  {
    "Wow64RevertWow64FsRedirection",
    reinterpret_cast<FARPROC>(MyWow64RevertWow64FsRedirection),
  },
  {
    "Wow64SetThreadContext",
    reinterpret_cast<FARPROC>(MyWow64SetThreadContext),
  },
  {
    "Wow64SuspendThread",
    reinterpret_cast<FARPROC>(MyWow64SuspendThread),
  },
  {
    "WriteConsoleA",
    reinterpret_cast<FARPROC>(MyWriteConsoleA),
  },
  {
    "WriteConsoleInputA",
    reinterpret_cast<FARPROC>(MyWriteConsoleInputA),
  },
  {
    "WriteConsoleInputW",
    reinterpret_cast<FARPROC>(MyWriteConsoleInputW),
  },
  {
    "WriteConsoleOutputA",
    reinterpret_cast<FARPROC>(MyWriteConsoleOutputA),
  },
  {
    "WriteConsoleOutputAttribute",
    reinterpret_cast<FARPROC>(MyWriteConsoleOutputAttribute),
  },
  {
    "WriteConsoleOutputCharacterA",
    reinterpret_cast<FARPROC>(MyWriteConsoleOutputCharacterA),
  },
  {
    "WriteConsoleOutputCharacterW",
    reinterpret_cast<FARPROC>(MyWriteConsoleOutputCharacterW),
  },
  {
    "WriteConsoleOutputW",
    reinterpret_cast<FARPROC>(MyWriteConsoleOutputW),
  },
  {
    "WriteConsoleW",
    reinterpret_cast<FARPROC>(MyWriteConsoleW),
  },
  {
    "WriteFile",
    reinterpret_cast<FARPROC>(MyWriteFile),
  },
  {
    "WriteFileEx",
    reinterpret_cast<FARPROC>(MyWriteFileEx),
  },
  {
    "WriteFileGather",
    reinterpret_cast<FARPROC>(MyWriteFileGather),
  },
  {
    "WritePrivateProfileSectionA",
    reinterpret_cast<FARPROC>(MyWritePrivateProfileSectionA),
  },
  {
    "WritePrivateProfileSectionW",
    reinterpret_cast<FARPROC>(MyWritePrivateProfileSectionW),
  },
  {
    "WritePrivateProfileStringA",
    reinterpret_cast<FARPROC>(MyWritePrivateProfileStringA),
  },
  {
    "WritePrivateProfileStringW",
    reinterpret_cast<FARPROC>(MyWritePrivateProfileStringW),
  },
  {
    "WritePrivateProfileStructA",
    reinterpret_cast<FARPROC>(MyWritePrivateProfileStructA),
  },
  {
    "WritePrivateProfileStructW",
    reinterpret_cast<FARPROC>(MyWritePrivateProfileStructW),
  },
  {
    "WriteProcessMemory",
    reinterpret_cast<FARPROC>(MyWriteProcessMemory),
  },
  {
    "WriteProfileSectionA",
    reinterpret_cast<FARPROC>(MyWriteProfileSectionA),
  },
  {
    "WriteProfileSectionW",
    reinterpret_cast<FARPROC>(MyWriteProfileSectionW),
  },
  {
    "WriteProfileStringA",
    reinterpret_cast<FARPROC>(MyWriteProfileStringA),
  },
  {
    "WriteProfileStringW",
    reinterpret_cast<FARPROC>(MyWriteProfileStringW),
  },
  {
    "WriteTapemark",
    reinterpret_cast<FARPROC>(MyWriteTapemark),
  },
  {
    "ZombifyActCtx",
    reinterpret_cast<FARPROC>(MyZombifyActCtx),
  },
  {
    "lstrcatA",
    reinterpret_cast<FARPROC>(MylstrcatA),
  },
  {
    "lstrcatW",
    reinterpret_cast<FARPROC>(MylstrcatW),
  },
  {
    "lstrcmpA",
    reinterpret_cast<FARPROC>(MylstrcmpA),
  },
  {
    "lstrcmpW",
    reinterpret_cast<FARPROC>(MylstrcmpW),
  },
  {
    "lstrcmpiA",
    reinterpret_cast<FARPROC>(MylstrcmpiA),
  },
  {
    "lstrcmpiW",
    reinterpret_cast<FARPROC>(MylstrcmpiW),
  },
  {
    "lstrcpyA",
    reinterpret_cast<FARPROC>(MylstrcpyA),
  },
  {
    "lstrcpyW",
    reinterpret_cast<FARPROC>(MylstrcpyW),
  },
  {
    "lstrcpynA",
    reinterpret_cast<FARPROC>(MylstrcpynA),
  },
  {
    "lstrcpynW",
    reinterpret_cast<FARPROC>(MylstrcpynW),
  },
  {
    "lstrlenA",
    reinterpret_cast<FARPROC>(MylstrlenA),
  },
  {
    "lstrlenW",
    reinterpret_cast<FARPROC>(MylstrlenW),
  },
  {
    "timeBeginPeriod",
    reinterpret_cast<FARPROC>(MytimeBeginPeriod),
  },
  {
    "timeEndPeriod",
    reinterpret_cast<FARPROC>(MytimeEndPeriod),
  },
  {
    "timeGetDevCaps",
    reinterpret_cast<FARPROC>(MytimeGetDevCaps),
  },
  {
    "timeGetSystemTime",
    reinterpret_cast<FARPROC>(MytimeGetSystemTime),
  },
  {
    "timeGetTime",
    reinterpret_cast<FARPROC>(MytimeGetTime),
  }
};

std::unordered_map<std::string, FARPROC> _funcMap;

BOOL _Init() {
  _pipeInst._pipe = INVALID_HANDLE_VALUE;
  _pipeInst._pid = GetCurrentProcessId();
  _hKernel = GetModuleHandleA("kernel32");
  if (_hKernel != NULL) {
    for (const auto& funcName : _funcNames) {
      FARPROC baseFuncAddr = GetProcAddress(_hKernel, funcName.data());
      _funcMap[funcName.data()] = baseFuncAddr;
    }
  }
  return (_hKernel == NULL) ? FALSE : TRUE;
}

VOID _Deinit() {
  _DisconnectPipe();
  LhUninstallAllHooks();
  LhWaitForPendingRemovals();
}

BOOL _Run() {
  if (!_ConnectPipe()) { return FALSE; }
  if (!_RecvInit()) { return FALSE; }
  if (!_ParseInit()) { return FALSE; }

  return TRUE;
}

BOOL _ConnectPipe() {
  BOOL success = FALSE;
  DWORD mode = 0;

  std::string pipeName(PIPE_NAME);
  pipeName += std::to_string(_pipeInst._pid);

  while (true) {
    _pipeInst._pipe = CreateFileA(
      pipeName.data(),
      GENERIC_READ | GENERIC_WRITE,
      0,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );

    if (_pipeInst._pipe != INVALID_HANDLE_VALUE) { break; }

    if (GetLastError() != ERROR_PIPE_BUSY) { return FALSE; }
    if (!WaitNamedPipeA(pipeName.data(), 20000)) { return FALSE; }
  }

  mode = PIPE_READMODE_MESSAGE;
  success = SetNamedPipeHandleState(_pipeInst._pipe, &mode, NULL, NULL);

  return success;
}

BOOL _RecvInit() {

  BOOL success = FALSE;
  DWORD size = 0;

  success = ReadFile(
    _pipeInst._pipe,
    &size,
    sizeof(DWORD),
    &_pipeInst._cbRead,
    NULL
  );

  if (!success) { return FALSE; }

  for (DWORD idx = 0; idx < size; ++idx) {
    ZeroMemory(_pipeInst._reqBuff, PIPE_BUFFER_SIZE * sizeof(TCHAR));
    DWORD strLen = 0;
    BOOL verbose = FALSE;

    success = ReadFile(
      _pipeInst._pipe,
      &strLen,
      sizeof(DWORD),
      &_pipeInst._cbRead,
      NULL
    );

    if (!success || strLen == 0) { return FALSE; }

    success = ReadFile(
      _pipeInst._pipe,
      _pipeInst._reqBuff,
      strLen,
      &_pipeInst._cbRead,
      NULL
    );

    if (!success) { return FALSE; }

    success = ReadFile(
      _pipeInst._pipe,
      &verbose,
      sizeof(BOOL),
      &_pipeInst._cbRead,
      NULL
    );

    if (!success) { return FALSE; }

    _track._funcNames.emplace(
      std::string(_pipeInst._reqBuff, strLen),
      verbose
    );
  }

  // Hide filenames
  success = ReadFile(
    _pipeInst._pipe,
    &size,
    sizeof(DWORD),
    &_pipeInst._cbRead,
    NULL
  );

  if (!success) { return FALSE; }

  for (DWORD idx = 0; idx < size; ++idx) {
    ZeroMemory(_pipeInst._reqBuff, PIPE_BUFFER_SIZE);
    DWORD strLen = 0;
    success = ReadFile(
      _pipeInst._pipe,
      &strLen,
      sizeof(DWORD),
      &_pipeInst._cbRead,
      NULL
    );

    if (!success || strLen == 0) { return FALSE; }

    success = ReadFile(
      _pipeInst._pipe,
      _pipeInst._reqBuff,
      strLen,
      &_pipeInst._cbRead,
      NULL
    );

    if (!success) { return FALSE; }
    _track._hideFilenamesA.emplace_back(_pipeInst._reqBuff, strLen);
  }

  success = ReadFile(
    _pipeInst._pipe,
    &size,
    sizeof(DWORD),
    &_pipeInst._cbRead,
    NULL
  );

  if (!success) { return FALSE; }

  for (DWORD idx = 0; idx < size; ++idx) {
    ZeroMemory(_pipeInst._reqBuff, PIPE_BUFFER_SIZE);
    DWORD strLen = 0;
    success = ReadFile(
      _pipeInst._pipe,
      &strLen,
      sizeof(DWORD),
      &_pipeInst._cbRead,
      NULL
    );

    if (!success || strLen == 0) { return FALSE; }

    success = ReadFile(
      _pipeInst._pipe,
      _pipeInst._reqBuff,
      strLen * sizeof(WCHAR),
      &_pipeInst._cbRead,
      NULL
    );

    if (!success) { return FALSE; }
    _track._hideFilenamesW.emplace_back(
      reinterpret_cast<WCHAR*>(_pipeInst._reqBuff), strLen
    );
  }

  return TRUE;
}

VOID _DisconnectPipe() {
  if (_pipeInst._pipe != INVALID_HANDLE_VALUE) { CloseHandle(_pipeInst._pipe); }
}

BOOL _ParseInit() { 
  BOOL res = TRUE;
  for (const auto& el : _track._funcNames) {
    res &= _AddHook(el.first);
  }
  return res;
}

BOOL _AddHook(const std::string& funcName) {

  HOOK_TRACE_INFO _hHook = { NULL };
  FARPROC baseFunc = _funcMap[funcName];
  FARPROC hookFunc = _funcHooksMap[funcName];
  NTSTATUS res = 0;

  res = LhInstallHook(
    baseFunc,
    hookFunc,
    NULL,
    &_hHook
  );

  if (FAILED(res)) { return FALSE; }

  ULONG aclEntries[1] = { 0 };

  if (FAILED(LhSetExclusiveACL(aclEntries, 1, &_hHook))) { return FALSE; }

  return TRUE;
}

VOID _SendInfo(std::string funcName) {
  DWORD cbWritten = 0;
  BOOL success = FALSE;
  SYSTEMTIME time;

  GetLocalTime(&time);
  StringCchPrintfA(_pipeInst._replyBuff, PIPE_BUFFER_SIZE,
    "PID: %d %02d/%02d/%02d %02d:%02d:%02d call %s",
    _pipeInst._pid, time.wDay, time.wMonth, time.wYear % 100,
    time.wHour, time.wMinute, time.wSecond, funcName.data());

  _pipeInst._cbToWrite = DWORD(strlen(_pipeInst._replyBuff)) + 1;

  success = WriteFile(
    _pipeInst._pipe,
    _pipeInst._replyBuff,
    _pipeInst._cbToWrite,
    &cbWritten,
    NULL
  );

  success = WriteFile(
    _pipeInst._pipe,
    _pipeInst._replyBuff,
    _pipeInst._cbToWrite,
    &cbWritten,
    NULL
  );
}

VOID WINAPI MyAcquireSRWLockExclusive(PSRWLOCK SRWLock) {
  using func_type = decltype(&AcquireSRWLockExclusive);
  using real_type = decltype(&MyAcquireSRWLockExclusive);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName("AcquireSRWLockExclusive");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];

  if (baseFuncAddr == NULL) { return; }

  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);

  return baseFunc(SRWLock);
}

VOID WINAPI MyAcquireSRWLockShared(PSRWLOCK SRWLock) {
  using func_type = decltype(&AcquireSRWLockShared);
  using real_type = decltype(&MyAcquireSRWLockShared);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName("AcquireSRWLockShared");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];

  if (baseFuncAddr == NULL) { return; }

  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);

  return baseFunc(SRWLock);
}

BOOL WINAPI MyActivateActCtx(HANDLE hActCtx, ULONG_PTR* lpCookie) {
  using func_type = decltype(&ActivateActCtx);
  using real_type = decltype(&MyActivateActCtx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName("ActivateActCtx");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];

  if (baseFuncAddr == NULL) { return FALSE; }

  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);

  return baseFunc(hActCtx, lpCookie);
}

ATOM MyAddAtomA(LPCSTR lpString) {
  using func_type = decltype(&AddAtomA);
  using real_type = decltype(&MyAddAtomA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName("AddAtomA");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];

  if (baseFuncAddr == NULL) { return 0; }

  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);

  return baseFunc(lpString);
}

ATOM WINAPI MyAddAtomW(LPCWSTR lpString) {
  using func_type = decltype(&AddAtomW);
  using real_type = decltype(&MyAddAtomW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName("AddAtomW");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];

  if (baseFuncAddr == NULL) { return 0; }

  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);

  return baseFunc(lpString);
}

BOOL WINAPI MyAddConsoleAliasA(LPSTR Source, LPSTR Target, LPSTR ExeName) {
  using func_type = decltype(&AddConsoleAliasA);
  using real_type = decltype(&MyAddConsoleAliasA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName("AddConsoleAliasA");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];

  if (baseFuncAddr == NULL) { return FALSE; }

  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);

  return baseFunc(Source, Target, ExeName);
}

BOOL WINAPI MyAddConsoleAliasW(LPWSTR Source, LPWSTR Target, LPWSTR ExeName) {
  using func_type = decltype(&AddConsoleAliasW);
  using real_type = decltype(&MyAddConsoleAliasW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName("AddConsoleAliasW");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];

  if (baseFuncAddr == NULL) { return FALSE; }

  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);

  return baseFunc(Source, Target, ExeName);
}

DLL_DIRECTORY_COOKIE MyAddDllDirectory(PCWSTR NewDirectory) {
  using func_type = decltype(&AddDllDirectory);
  using real_type = decltype(&MyAddDllDirectory);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName("AddDllDirectory");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return 0; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(NewDirectory);
}

BOOL MyAddIntegrityLabelToBoundaryDescriptor(
  HANDLE* BoundaryDescriptor, PSID IntegrityLabel
) {
  using func_type = decltype(&AddIntegrityLabelToBoundaryDescriptor);
  static const std::string funcName("AddIntegrityLabelToBoundaryDescriptor");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return 0; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(BoundaryDescriptor, IntegrityLabel);
}

DWORD MyAddLocalAlternateComputerNameA(LPCSTR lpDnsFQHostName, ULONG ulFlag) {
  using func_type = DWORD(*)(LPCSTR, ULONG);
  static const std::string funcName("AddLocalAlternateComputerNameA");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(lpDnsFQHostName, ulFlag);
}

DWORD MyAddLocalAlternateComputerNameW(LPCWSTR lpDnsFQHostName, ULONG ulFlag) {
  using func_type = DWORD(*)(LPCWSTR, ULONG);
  static const std::string funcName("AddLocalAlternateComputerNameW");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(lpDnsFQHostName, ulFlag);
}

VOID MyAddRefActCtx(HANDLE hActCtx) {
  using func_type = decltype(&AddRefActCtx);
  static const std::string funcName("AddRefActCtx");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(hActCtx);
}

BOOL MyAddResourceAttributeAce(
  PACL pAcl,
  DWORD dwAceRevision,
  DWORD AceFlags,
  DWORD AccessMask,
  PSID pSid,
  PCLAIM_SECURITY_ATTRIBUTES_INFORMATION pAttributeInfo,
  PDWORD pReturnLength
) {
  using func_type = decltype(&AddResourceAttributeAce);
  static const std::string funcName("AddResourceAttributeAce");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(
    pAcl ,dwAceRevision, AceFlags, AccessMask, pSid, pAttributeInfo,
    pReturnLength
  );
}

BOOL MyAddSecureMemoryCacheCallback(PSECURE_MEMORY_CACHE_CALLBACK pfnCallBack) {
  using func_type = decltype(&AddSecureMemoryCacheCallback);
  static const std::string funcName("AddSecureMemoryCacheCallback");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(pfnCallBack);
}

BOOL MyAddSIDToBoundaryDescriptor(HANDLE* BoundaryDescriptor, PSID RequireSid) {
  using func_type = decltype(&AddSIDToBoundaryDescriptor);
  static const std::string funcName("AddSIDToBoundaryDescriptor");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(BoundaryDescriptor, RequireSid);
}

PVOID MyAddVectoredContinueHandler(
  ULONG First, PVECTORED_EXCEPTION_HANDLER Handler
) {
  using func_type = decltype(&AddVectoredContinueHandler);
  static const std::string funcName("AddVectoredContinueHandler");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return NULL; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(First, Handler);
}

PVOID MyAddVectoredExceptionHandler(
  ULONG First, PVECTORED_EXCEPTION_HANDLER Handler
) {
  using func_type = decltype(&AddVectoredExceptionHandler);
  static const std::string funcName("AddVectoredExceptionHandler");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return NULL; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(First, Handler);
}

BOOL MyAllocateUserPhysicalPages(
  HANDLE hProcess, PULONG_PTR NumberOfPages, PULONG_PTR PageArray
) {
  using func_type = decltype(&AllocateUserPhysicalPages);
  static const std::string funcName("AllocateUserPhysicalPages");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return NULL; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(hProcess, NumberOfPages, PageArray);
}

BOOL MyAllocateUserPhysicalPagesNuma(
  HANDLE hProcess,
  PULONG_PTR NumberOfPages,
  PULONG_PTR PageArray,
  DWORD nndPreferred
) {
  using func_type = decltype(&AllocateUserPhysicalPagesNuma);
  static const std::string funcName("AllocateUserPhysicalPagesNuma");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return NULL; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(hProcess, NumberOfPages, PageArray, nndPreferred);
}

BOOL WINAPI MyAllocConsole() {
  using func_type = decltype(&AllocConsole);
  static const std::string funcName("AllocConsole");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return NULL; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc();
}

VOID MyApplicationRecoveryFinished(BOOL bSuccess) {
  using func_type = decltype(&ApplicationRecoveryFinished);
  static const std::string funcName("ApplicationRecoveryFinished");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(bSuccess);
}

HRESULT MyApplicationRecoveryInProgress(PBOOL pbCancelled) {
  using func_type = decltype(&ApplicationRecoveryInProgress);
  static const std::string funcName("ApplicationRecoveryInProgress");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return E_FAIL; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(pbCancelled);
}

LONG MyAppPolicyGetClrCompat(HANDLE processToken, AppPolicyClrCompat* policy) {
  using func_type = decltype(&AppPolicyGetClrCompat);
  static const std::string funcName("AppPolicyGetClrCompat");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(processToken, policy);
}

LONG MyAppPolicyGetMediaFoundationCodecLoading(
  HANDLE processToken, AppPolicyMediaFoundationCodecLoading* policy
) {
  using func_type = decltype(&AppPolicyGetMediaFoundationCodecLoading);
  static const std::string funcName("AppPolicyGetMediaFoundationCodecLoading");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(processToken, policy);
}

LONG MyAppPolicyGetProcessTerminationMethod(
  HANDLE processToken, AppPolicyProcessTerminationMethod* policy
) {
  using func_type = decltype(&AppPolicyGetProcessTerminationMethod);
  static const std::string funcName("AppPolicyGetProcessTerminationMethod");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(processToken, policy);
}

LONG MyAppPolicyGetThreadInitializationType(
  HANDLE processToken, AppPolicyThreadInitializationType* policy
) {
  using func_type = decltype(&AppPolicyGetThreadInitializationType);
  static const std::string funcName("AppPolicyGetThreadInitializationType");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(processToken, policy);
}

LONG MyAppPolicyGetWindowingModel(
  HANDLE processToken, AppPolicyWindowingModel* policy
) {
  using func_type = decltype(&AppPolicyGetWindowingModel);
  static const std::string funcName("AppPolicyGetWindowingModel");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(processToken, policy);
}

BOOL MyAreFileApisANSI() {
  using func_type = decltype(&AreFileApisANSI);
  static const std::string funcName("AreFileApisANSI");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc();
}

BOOL MyAssignProcessToJobObject(HANDLE hJob, HANDLE hProcess) {
  using func_type = decltype(&AssignProcessToJobObject);
  static const std::string funcName("AssignProcessToJobObject");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(hJob, hProcess);
}

BOOL WINAPI MyAttachConsole(DWORD dwProcessId) {
  using func_type = decltype(&AttachConsole);
  static const std::string funcName("AttachConsole");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(dwProcessId);
}

BOOL MyBackupRead(
  HANDLE hFile,
  LPBYTE lpBuffer,
  DWORD nNumberOfBytesToRead,
  LPDWORD lpNumberOfBytesRead,
  BOOL bAbort,
  BOOL bProcessSecurity,
  LPVOID* lpContext
) {
  using func_type = decltype(&BackupRead);
  static const std::string funcName("BackupRead");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(
    hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, bAbort,
    bProcessSecurity, lpContext
  );
}

BOOL MyBackupSeek(
  HANDLE hFile,
  DWORD dwLowBytesToSeek,
  DWORD dwHighBytesToSeek,
  LPDWORD lpdwLowByteSeeked,
  LPDWORD lpdwHighByteSeeked,
  LPVOID* lpContext
) {
  using func_type = decltype(&BackupSeek);
  static const std::string funcName("BackupSeek");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(
    hFile, dwLowBytesToSeek, dwHighBytesToSeek, lpdwLowByteSeeked,
    lpdwHighByteSeeked, lpContext
  );
}

BOOL MyBackupWrite(
  HANDLE hFile,
  LPBYTE lpBuffer,
  DWORD nNumberOfBytesToWrite,
  LPDWORD lpNumberOfBytesWritten,
  BOOL bAbort,
  BOOL bProcessSecurity,
  LPVOID* lpContext
) {
  using func_type = decltype(&BackupWrite);
  static const std::string funcName("BackupWrite");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(
    hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, bAbort,
    bProcessSecurity, lpContext
  );
}

BOOL WINAPI MyBaseFlushAppcompatCache() {
  using func_type = BOOL(WINAPI*)();
  static const std::string funcName("BaseFlushAppcompatCache");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc();
}

HANDLE MyBeginUpdateResourceA(LPCSTR pFileName, BOOL bDeleteExistingResources) {
  using func_type = decltype(&BeginUpdateResourceA);
  static const std::string funcName("BeginUpdateResourceA");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return NULL; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(pFileName, bDeleteExistingResources);
}

HANDLE MyBeginUpdateResourceW(
  LPCWSTR pFileName, BOOL bDeleteExistingResources
) {
  using func_type = decltype(&BeginUpdateResourceW);
  static const std::string funcName("BeginUpdateResourceW");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return NULL; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(pFileName, bDeleteExistingResources);
}

BOOL MyBindIoCompletionCallback(
  HANDLE FilehHandle,
  LPOVERLAPPED_COMPLETION_ROUTINE Function,
  ULONG Flags
) {
  using func_type = decltype(&BindIoCompletionCallback);
  static const std::string funcName("BindIoCompletionCallback");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(FilehHandle, Function, Flags);
}

BOOL MyBuildCommDCBA(LPCSTR lpDef, LPDCB lpDCB) {
  using func_type = decltype(&BuildCommDCBA);
  static const std::string funcName("BuildCommDCBA");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(lpDef, lpDCB);
}

BOOL MyBuildCommDCBAndTimeoutsA(
  LPCSTR lpDef, LPDCB lpDCB, LPCOMMTIMEOUTS lpCommTimeouts
) {
  using func_type = decltype(&BuildCommDCBAndTimeoutsA);
  static const std::string funcName("BuildCommDCBAndTimeoutsA");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(lpDef, lpDCB, lpCommTimeouts);
}

BOOL MyBuildCommDCBAndTimeoutsW(
  LPCWSTR lpDef, LPDCB lpDCB, LPCOMMTIMEOUTS lpCommTimeouts
) {
  using func_type = decltype(&BuildCommDCBAndTimeoutsW);
  static const std::string funcName("BuildCommDCBAndTimeoutsW");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(lpDef, lpDCB, lpCommTimeouts);
}

BOOL MyBuildCommDCBW(LPCWSTR lpDef, LPDCB lpDCB) {
  using func_type = decltype(&BuildCommDCBW);
  static const std::string funcName("BuildCommDCBW");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(lpDef, lpDCB);
}

BOOL MyCallbackMayRunLong(PTP_CALLBACK_INSTANCE pci) {
  using func_type = decltype(&CallbackMayRunLong);
  static const std::string funcName("CallbackMayRunLong");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(pci);
}

BOOL MyCallNamedPipeA(
  LPCSTR  lpNamedPipeName,
  LPVOID  lpInBuffer,
  DWORD   nInBufferSize,
  LPVOID  lpOutBuffer,
  DWORD   nOutBufferSize,
  LPDWORD lpBytesRead,
  DWORD   nTimeOut
) {
  using func_type = decltype(&CallNamedPipeA);
  static const std::string funcName("CallNamedPipeA");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(
    lpNamedPipeName, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize,
    lpBytesRead, nTimeOut
  );
}

BOOL MyCallNamedPipeW(
  LPCWSTR  lpNamedPipeName,
  LPVOID  lpInBuffer,
  DWORD   nInBufferSize,
  LPVOID  lpOutBuffer,
  DWORD   nOutBufferSize,
  LPDWORD lpBytesRead,
  DWORD   nTimeOut
) {
  using func_type = decltype(&CallNamedPipeW);
  static const std::string funcName("CallNamedPipeW");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];

  if (baseFuncAddr == NULL) { return FALSE; }

  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);

  return baseFunc(
    lpNamedPipeName, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize,
    lpBytesRead, nTimeOut
  );
}

BOOL WINAPI MyCancelIo(HANDLE hFile) {

  using func_type = decltype(&CancelIo);

  static const std::string funcName("CancelIo");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];

  if (baseFuncAddr == NULL) { return FALSE; }

  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);

  return baseFunc(hFile);
}

BOOL WINAPI MyCancelIoEx(HANDLE hFile, LPOVERLAPPED lpOverlapped) {

  using func_type = decltype(&CancelIoEx);
  static_assert(std::is_same_v<decltype(&MyCancelIoEx),func_type>);

  static const std::string funcName("CancelIoEx");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(hFile, lpOverlapped);
}

/// Here

HANDLE MyFindFirstFileA(LPCSTR lpFileName,
  LPWIN32_FIND_DATAA lpFindFileData) {
  using func_first_type = HANDLE(*)(LPCSTR, LPWIN32_FIND_DATAA);
  using func_next_type = BOOL(*)(HANDLE, LPWIN32_FIND_DATAA);
  using func_close_type = BOOL(*)(HANDLE);

  std::string funcFirstName("FindFirstFileA");
  std::string funcNextName("FindNextFileA");
  std::string funcCloseName("FindClose");

  HANDLE hFile = INVALID_HANDLE_VALUE;

  auto baseFirstFuncAddr = _funcMap[funcFirstName];
  if (baseFirstFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  func_first_type baseFirstFunc =
    reinterpret_cast<func_first_type>(baseFirstFuncAddr);

  auto baseNextFuncAddr = _funcMap[funcNextName];
  if (baseNextFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  func_next_type baseNextFunc =
    reinterpret_cast<func_next_type>(baseNextFuncAddr);
  
  auto baseCloseFuncAddr = _funcMap[funcCloseName];
  if (baseCloseFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  func_close_type baseCloseFunc =
    reinterpret_cast<func_close_type>(baseCloseFuncAddr);

  if (_track._funcNames.count(funcFirstName)
    && _track._funcNames[funcFirstName]) {
    _SendInfo(funcFirstName);
  }

  hFile = baseFirstFunc(lpFileName, lpFindFileData);
  if (hFile == INVALID_HANDLE_VALUE) { return hFile; }

  BOOL bFound = _CheckA(lpFindFileData->cFileName);

  // If this filename should not be hidden
  if (!bFound) { return hFile; }

  // This file filename should be hidden so iterate over found files
  
  BOOL bRes = TRUE;

  while (baseNextFunc(hFile, lpFindFileData)) {
    // If this filename shouldn't be hidden return
    if (!_CheckA(lpFindFileData->cFileName)) { return hFile; }
  }

  // All files are hidden
  baseCloseFunc(hFile);
  std::memset(lpFindFileData, 0x00, sizeof(*lpFindFileData));
  SetLastError(ERROR_FILE_NOT_FOUND);
  return INVALID_HANDLE_VALUE;
}

HANDLE MyFindFirstFileW(LPCWSTR lpFileName,
  LPWIN32_FIND_DATAW lpFindFileData) {
  using func_first_type = HANDLE(*)(LPCWSTR, LPWIN32_FIND_DATAW);
  using func_next_type = BOOL(*)(HANDLE, LPWIN32_FIND_DATAW);
  using func_close_type = BOOL(*)(HANDLE);

  std::string funcFirstName("FindFirstFileW");
  std::string funcNextName("FindNextFileW");
  std::string funcCloseName("FindClose");

  HANDLE hFile = INVALID_HANDLE_VALUE;

  auto baseFirstFuncAddr = _funcMap[funcFirstName];
  if (baseFirstFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  func_first_type baseFirstFunc =
    reinterpret_cast<func_first_type>(baseFirstFuncAddr);

  auto baseNextFuncAddr = _funcMap[funcNextName];
  if (baseNextFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  func_next_type baseNextFunc =
    reinterpret_cast<func_next_type>(baseNextFuncAddr);
  
  auto baseCloseFuncAddr = _funcMap[funcCloseName];
  if (baseCloseFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  func_close_type baseCloseFunc =
    reinterpret_cast<func_close_type>(baseCloseFuncAddr);

  if (_track._funcNames.count(funcFirstName)
    && _track._funcNames[funcFirstName]) {
    _SendInfo(funcFirstName);
  }

  hFile = baseFirstFunc(lpFileName, lpFindFileData);
  if (hFile == INVALID_HANDLE_VALUE) { return hFile; }

  BOOL bFound = _CheckW(lpFindFileData->cFileName);

  // If this filename should not be hidden
  if (!bFound) { return hFile; }

  // This file filename should be hidden so iterate over found files
  
  BOOL bRes = TRUE;

  while (baseNextFunc(hFile, lpFindFileData)) {
    // If this filename shouldn't be hidden return
    if (!_CheckW(lpFindFileData->cFileName)) { return hFile; }
  }

  // All files are hidden
  baseCloseFunc(hFile);
  std::memset(lpFindFileData, 0x00, sizeof(*lpFindFileData));
  SetLastError(ERROR_FILE_NOT_FOUND);
  return INVALID_HANDLE_VALUE;
}

BOOL MyFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
  using func_type = BOOL(*)(HANDLE, LPWIN32_FIND_DATAA);
  static const std::string funcName("FindNextFileA");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  
  BOOL bRes = TRUE;
  while (baseFunc(hFindFile, lpFindFileData)) {
    if (!_CheckA(lpFindFileData->cFileName)) { return TRUE; }
  }

  return FALSE;
}
BOOL MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
  using func_type = BOOL(*)(HANDLE, LPWIN32_FIND_DATAW);
  static const std::string funcName("FindNextFileW");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  
  BOOL bRes = TRUE;
  while (baseFunc(hFindFile, lpFindFileData)) {
    if (!_CheckW(lpFindFileData->cFileName)) { return TRUE; }
  }

  return FALSE;
}

HANDLE MyCreateFileA(
  LPCSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile) {
  using func_type = HANDLE(*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
    DWORD, DWORD, HANDLE);
  static const std::string funcName("CreateFileA");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  if (_CheckA(lpFileName)) { return INVALID_HANDLE_VALUE; }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  
  return baseFunc(lpFileName, dwDesiredAccess, dwSharedMode,
    lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
    hTemplateFile);
}

HANDLE MyCreateFileW(
  LPCWSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile) {
  using func_type = HANDLE(*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
    DWORD, DWORD, HANDLE);
  static const std::string funcName("CreateFileW");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  if (_CheckW(lpFileName)) { return INVALID_HANDLE_VALUE; }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);

  return baseFunc(lpFileName, dwDesiredAccess, dwSharedMode,
    lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
    hTemplateFile);
}

BOOL MyBeep(DWORD dwFreq, DWORD dwDuration) {
  using func_type = BOOL(WINAPI*)(DWORD, DWORD);
  static const std::string funcName("Beep");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(dwFreq, dwDuration);
}

BOOL MyCloseHandle(HANDLE hObject) {
  using func_type = BOOL(*)(HANDLE);
  static const std::string funcName("CloseHandle");

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  static auto baseFuncAddr = _funcMap[funcName];
  if (baseFuncAddr == NULL) { return FALSE; }
  static func_type baseFunc = reinterpret_cast<func_type>(baseFuncAddr);
  return baseFunc(hObject);
}

BOOL _CheckA(LPCSTR lpFileName) {
  BOOL bFound = FALSE;
  for (const auto& el : _track._hideFilenamesA) {
    if (!el.compare(lpFileName))  {
      bFound = TRUE;
      break;
    }
  }
  return bFound;
}

BOOL _CheckW(LPCWSTR lpFileName) {
  BOOL bFound = FALSE;
  for (const auto& el : _track._hideFilenamesW) {
    if (!el.compare(lpFileName))  {
      bFound = TRUE;
      break;
    }
  }
  return bFound;
}
