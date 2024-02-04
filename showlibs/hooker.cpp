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
  "AddSecureMemoryCacheCallback",
  "AddSIDToBoundaryDescriptor",
  "AddVectoredContinueHandler",
  "AddVectoredExceptionHandler",
  "AllocateUserPhysicalPages",
  "AllocateUserPhysicalPagesNuma",
  "AllocConsole",
  "ApplicationRecoveryFinished",
  "ApplicationRecoveryInProgress",
  "AppPolicyGetClrCompat",
  "AppPolicyGetMediaFoundationCodecLoading",
  "AppPolicyGetProcessTerminationMethod",
  "AppPolicyGetThreadInitializationType",
  "AppPolicyGetWindowingModel",
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
  "CallbackMayRunLong",
  "CallNamedPipeA",
  "CallNamedPipeW",
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
  "FindNextChangeNotification",
  "FindNextFileA",
  "FindNextFileNameW",
  "FindNextFileW",
  "FindNextStreamW",
  "FindNextVolumeA",
  "FindNextVolumeMountPointA",
  "FindNextVolumeMountPointW",
  "FindNextVolumeW",
  "FindNLSString",
  "FindNLSStringEx",
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
  "GetCachedSigningLevel",
  "GetCalendarDateFormatEx",
  "GetCalendarInfoA",
  "GetCalendarInfoEx",
  "GetCalendarInfoW",
  "GetCalendarSupportedDateRange",
  "GetCommandLineA",
  "GetCommandLineW",
  "GetCommConfig",
  "GetCommMask",
  "GetCommModemStatus",
  "GetCommProperties",
  "GetCommState",
  "GetCommTimeouts",
  "GetComPlusPackageInstallStatus",
  "GetCompressedFileSizeA",
  "GetCompressedFileSizeTransactedA",
  "GetCompressedFileSizeTransactedW",
  "GetCompressedFileSizeW",
  "GetComputerNameA",
  "GetComputerNameExA",
  "GetComputerNameExW",
  "GetComputerNameW",
  "GetConsoleAliasA",
  "GetConsoleAliasesA",
  "GetConsoleAliasesLengthA",
  "GetConsoleAliasesLengthW",
  "GetConsoleAliasesW",
  "GetConsoleAliasExesA",
  "GetConsoleAliasExesLengthA",
  "GetConsoleAliasExesLengthW",
  "GetConsoleAliasExesW",
  "GetConsoleAliasW",
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
  "GetCPInfo",
  "GetCPInfoExA",
  "GetCPInfoExW",
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
  "GetLocaleInfoA",
  "GetLocaleInfoEx",
  "GetLocaleInfoW",
  "GetLocalTime",
  "GetLogicalDrives",
  "GetLogicalDriveStringsA",
  "GetLogicalDriveStringsW",
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
  "GetNLSVersion",
  "GetNLSVersionEx",
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
  "GetProcessDefaultCpuSets",
  "GetProcessDEPPolicy",
  "GetProcessGroupAffinity",
  "GetProcessHandleCount",
  "GetProcessHeap",
  "GetProcessHeaps",
  "GetProcessId",
  "GetProcessIdOfThread",
  "GetProcessInformation",
  "GetProcessIoCounters",
  "GetProcessMitigationPolicy",
  "GetProcessorSystemCycleTime",
  "GetProcessPreferredUILanguages",
  "GetProcessPriorityBoost",
  "GetProcessShutdownParameters",
  "GetProcessTimes",
  "GetProcessVersion",
  "GetProcessWorkingSetSize",
  "GetProcessWorkingSetSizeEx",
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
  "GetSystemDefaultLangID",
  "GetSystemDefaultLCID",
  "GetSystemDefaultLocaleName",
  "GetSystemDefaultUILanguage",
  "GetSystemDEPPolicy",
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
  "GetThreadId",
  "GetThreadIdealProcessorEx",
  "GetThreadInformation",
  "GetThreadIOPendingFlag",
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
  "GetUserDefaultLangID",
  "GetUserDefaultLCID",
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
  "GetVolumePathNamesForVolumeNameA",
  "GetVolumePathNamesForVolumeNameW",
  "GetVolumePathNameW",
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
  "InitOnceBeginInitialize",
  "InitOnceComplete",
  "InitOnceExecuteOnce",
  "InitOnceInitialize",
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
  "IsNativeVhdBoot",
  "IsNLSDefinedString",
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
  "K32EnumProcesses",
  "K32EnumProcessModules",
  "K32EnumProcessModulesEx",
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
  "LocaleNameToLCID",
  "LocalFileTimeToFileTime",
  "LocalFlags",
  "LocalFree",
  "LocalHandle",
  "LocalLock",
  "LocalReAlloc",
  "LocalSize",
  "LocalUnlock",
  "LocateXStateFeature",
  "LockFile",
  "LockFileEx",
  "LockResource",
  "lstrcatA",
  "lstrcatW",
  "lstrcmpA",
  "lstrcmpiA",
  "lstrcmpiW",
  "lstrcmpW",
  "lstrcpyA",
  "lstrcpynA",
  "lstrcpynW",
  "lstrcpyW",
  "lstrlenA",
  "lstrlenW",
  "LZClose",
  "LZCopy",
  "LZInit",
  "LZOpenFileA",
  "LZOpenFileW",
  "LZRead",
  "LZSeek",
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
  "OfferVirtualMemory",
  "OOBEComplete",
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
  "QueryThreadpoolStackInformation",
  "QueryThreadProfiling",
  "QueryUmsThreadInformation",
  "QueryUnbiasedInterruptTime",
  "QueueUserAPC",
  "QueueUserWorkItem",
  "RaiseException",
  "RaiseFailFastException",
  "RaiseInvalid16BitExeError",
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
  "RegisterApplicationRecoveryCallback",
  "RegisterApplicationRestart",
  "RegisterBadMemoryNotification",
  "RegisterWaitForInputIdle",
  "RegisterWaitForSingleObject",
  "RegisterWaitForSingleObjectEx",
  "RegisterWaitUntilOOBECompleted",
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
  "ReleaseActCtx",
  "ReleaseMutex",
  "ReleaseMutexWhenCallbackReturns",
  "ReleaseSemaphore",
  "ReleaseSemaphoreWhenCallbackReturns",
  "ReleaseSRWLockExclusive",
  "ReleaseSRWLockShared",
  "RemoveDirectoryA",
  "RemoveDirectoryTransactedA",
  "RemoveDirectoryTransactedW",
  "RemoveDirectoryW",
  "RemoveDllDirectory",
  "RemoveSecureMemoryCacheCallback",
  "RemoveVectoredContinueHandler",
  "RemoveVectoredExceptionHandler",
  "ReOpenFile",
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
  "SetCommBreak",
  "SetCommConfig",
  "SetCommMask",
  "SetCommState",
  "SetCommTimeouts",
  "SetComPlusPackageInstallStatus",
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
  "SetLocaleInfoA",
  "SetLocaleInfoW",
  "SetLocalTime",
  "SetMailslotInfo",
  "SetNamedPipeHandleState",
  "SetPriorityClass",
  "SetProcessAffinityMask",
  "SetProcessAffinityUpdateMode",
  "SetProcessDefaultCpuSets",
  "SetProcessDEPPolicy",
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
  "SetThreadpoolStackInformation",
  "SetThreadpoolThreadMaximum",
  "SetThreadpoolThreadMinimum",
  "SetThreadpoolTimer",
  "SetThreadpoolTimerEx",
  "SetThreadpoolWait",
  "SetThreadpoolWaitEx",
  "SetThreadPreferredUILanguages",
  "SetThreadPriority",
  "SetThreadPriorityBoost",
  "SetThreadSelectedCpuSets",
  "SetThreadStackGuarantee",
  "SetThreadToken",
  "SetThreadUILanguage",
  "SetTimerQueueTimer",
  "SetTimeZoneInformation",
  "SetUmsThreadInformation",
  "SetUnhandledExceptionFilter",
  "SetupComm",
  "SetUserGeoID",
  "SetUserGeoName",
  "SetVolumeLabelA",
  "SetVolumeLabelW",
  "SetVolumeMountPointA",
  "SetVolumeMountPointW",
  "SetWaitableTimer",
  "SetWaitableTimerEx",
  "SetXStateFeaturesMask",
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
  "timeBeginPeriod",
  "timeEndPeriod",
  "timeGetDevCaps",
  "timeGetSystemTime",
  "timeGetTime",
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
  "VerifyConsoleIoHandle",
  "VerifyVersionInfoA",
  "VerifyVersionInfoW",
  "VerLanguageNameA",
  "VerLanguageNameW",
  "VerSetConditionMask",
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
  "WTSGetActiveConsoleSessionId",
  "ZombifyActCtx",
};

std::unordered_map<std::string, FARPROC> _funcHooksMap = {
  {
    "AcquireSRWLockExclusive",
    reinterpret_cast<FARPROC>(MyAcquireSRWLockExclusive)
  },
  {
    "AcquireSRWLockShared",
    reinterpret_cast<FARPROC>(MyAcquireSRWLockShared)
  },
  {
    "ActivateActCtx",
    reinterpret_cast<FARPROC>(MyActivateActCtx)
  },
  {
    "AddAtomA",
    reinterpret_cast<FARPROC>(MyAddAtomA)
  },
  {
    "AddAtomW",
    reinterpret_cast<FARPROC>(MyAddAtomW)
  },
  {
    "AddConsoleAliasA",
    reinterpret_cast<FARPROC>(MyAddConsoleAliasA)
  },
  {
    "AddConsoleAliasW",
    reinterpret_cast<FARPROC>(MyAddConsoleAliasW)
  },
  {
    "AddDllDirectory",
    reinterpret_cast<FARPROC>(MyAddDllDirectory)
  },
  {
    "AddIntegrityLabelToBoundaryDescriptor",
    reinterpret_cast<FARPROC>(MyAddIntegrityLabelToBoundaryDescriptor)
  },
  {
    "AddLocalAlternateComputerNameA",
    reinterpret_cast<FARPROC>(MyAddLocalAlternateComputerNameA)
  },
  {
    "AddLocalAlternateComputerNameW",
    reinterpret_cast<FARPROC>(MyAddLocalAlternateComputerNameW)
  },
  {
    "AddRefActCtx",
    reinterpret_cast<FARPROC>(MyAddRefActCtx)
  },
  {
    "AddResourceAttributeAce",
    reinterpret_cast<FARPROC>(MyAddResourceAttributeAce)
  },
  {
    "AddSecureMemoryCacheCallback",
    reinterpret_cast<FARPROC>(MyAddSecureMemoryCacheCallback)
  },
  {
    "AddSIDToBoundaryDescriptor",
    reinterpret_cast<FARPROC>(MyAddSIDToBoundaryDescriptor)
  },
  {
    "AddVectoredContinueHandler",
    reinterpret_cast<FARPROC>(MyAddVectoredContinueHandler)
  },
  {
    "AddVectoredExceptionHandler",
    reinterpret_cast<FARPROC>(MyAddVectoredExceptionHandler)
  },
  {
    "AllocateUserPhysicalPages",
    reinterpret_cast<FARPROC>(MyAllocateUserPhysicalPages)
  },
  {
    "AllocateUserPhysicalPagesNuma",
    reinterpret_cast<FARPROC>(MyAllocateUserPhysicalPagesNuma)
  },
  {
    "AllocConsole",
    reinterpret_cast<FARPROC>(MyAllocConsole)
  },
  {
    "ApplicationRecoveryFinished",
    reinterpret_cast<FARPROC>(MyApplicationRecoveryFinished)
  },
  {
    "ApplicationRecoveryInProgress",
    reinterpret_cast<FARPROC>(MyApplicationRecoveryInProgress)
  },
  {
    "AppPolicyGetClrCompat",
    reinterpret_cast<FARPROC>(MyAppPolicyGetClrCompat)
  },
  {
    "AppPolicyGetMediaFoundationCodecLoading",
    reinterpret_cast<FARPROC>(MyAppPolicyGetMediaFoundationCodecLoading)
  },
  {
    "AppPolicyGetProcessTerminationMethod",
    reinterpret_cast<FARPROC>(MyAppPolicyGetProcessTerminationMethod)
  },
  {
    "AppPolicyGetThreadInitializationType",
    reinterpret_cast<FARPROC>(MyAppPolicyGetThreadInitializationType)
  },
  {
    "AppPolicyGetWindowingModel",
    reinterpret_cast<FARPROC>(MyAppPolicyGetWindowingModel)
  },
  {
    "AreFileApisANSI",
    reinterpret_cast<FARPROC>(MyAreFileApisANSI)
  },
  {
    "AssignProcessToJobObject",
    reinterpret_cast<FARPROC>(MyAssignProcessToJobObject)
  },
  {
    "AttachConsole",
    reinterpret_cast<FARPROC>(MyAttachConsole)
  },
  {
    "BackupRead",
    reinterpret_cast<FARPROC>(MyBackupRead)
  },
  {
    "BackupSeek",
    reinterpret_cast<FARPROC>(MyBackupSeek)
  },
  {
    "BackupWrite",
    reinterpret_cast<FARPROC>(MyBackupWrite)
  },
  {
    "BaseFlushAppcompatCache",
    reinterpret_cast<FARPROC>(MyBaseFlushAppcompatCache)
  },
  {
    "Beep",
    reinterpret_cast<FARPROC>(MyBeep)
  },
  {
    "BeginUpdateResourceA",
    reinterpret_cast<FARPROC>(MyBeginUpdateResourceA)
  },
  {
    "BeginUpdateResourceW",
    reinterpret_cast<FARPROC>(MyBeginUpdateResourceW)
  },
  {
    "BindIoCompletionCallback",
    reinterpret_cast<FARPROC>(MyBindIoCompletionCallback)
  },
  {
    "BuildCommDCBA",
    reinterpret_cast<FARPROC>(MyBuildCommDCBA)
  },
  {
    "BuildCommDCBAndTimeoutsA",
    reinterpret_cast<FARPROC>(MyBuildCommDCBAndTimeoutsA)
  },
  {
    "BuildCommDCBAndTimeoutsW",
    reinterpret_cast<FARPROC>(MyBuildCommDCBAndTimeoutsW)
  },
  {
    "BuildCommDCBW",
    reinterpret_cast<FARPROC>(MyBuildCommDCBW)
  },
  {
    "CallbackMayRunLong",
    reinterpret_cast<FARPROC>(MyCallbackMayRunLong)
  },
  {
    "CallNamedPipeA",
    reinterpret_cast<FARPROC>(MyCallNamedPipeA)
  },
  {
    "CallNamedPipeW",
    reinterpret_cast<FARPROC>(MyCallNamedPipeW)
  },
  {
    "CancelIo",
    reinterpret_cast<FARPROC>(MyCancelIo)
  },
  {
    "CancelIoEx",
    reinterpret_cast<FARPROC>(CancelIoEx)
  },
  /* 
  "CancelIoEx",
  "CancelSynchronousIo",
  "CancelThreadpoolIo",
  "CancelTimerQueueTimer",
  "CancelWaitableTimer",
  "CeipIsOptedIn",
  "ChangeTimerQueueTimer",
  "CheckAllowDecryptedRemoteDestinationPolicy",
  "CheckElevation",
  "CheckElevationEnabled",
  "CheckForReadOnlyResource",
  "CheckForReadOnlyResourceFilter",
  "CheckIsMSIXPackage",
  "CheckNameLegalDOS8Dot3A",
  "CheckNameLegalDOS8Dot3W",
  "CheckRemoteDebuggerPresent",
  "CheckTokenCapability",
  "CheckTokenMembershipEx",
  "ClearCommBreak",
  "ClearCommError",
  "CloseConsoleHandle", */
  {
    "CloseHandle",
    reinterpret_cast<FARPROC>(MyCloseHandle)
  },
  /*"ClosePackageInfo",
  "ClosePrivateNamespace",
  "CloseProfileUserMapping",
  "ClosePseudoConsole",
  "CloseState",
  "CloseThreadpool",
  "CloseThreadpoolCleanupGroup",
  "CloseThreadpoolCleanupGroupMembers",
  "CloseThreadpoolIo",
  "CloseThreadpoolTimer",
  "CloseThreadpoolWait",
  "CloseThreadpoolWork",
  "CmdBatNotification",
  "CommConfigDialogA",
  "CommConfigDialogW",
  "CompareCalendarDates",
  "CompareFileTime",
  "CompareStringA",
  "CompareStringEx",
  "CompareStringOrdinal",
  "CompareStringW",
  "ConnectNamedPipe",
  "ConsoleMenuControl",
  "ContinueDebugEvent",
  "ConvertCalDateTimeToSystemTime",
  "ConvertDefaultLocale",
  "ConvertFiberToThread",
  "ConvertNLSDayOfWeekToWin32DayOfWeek",
  "ConvertSystemTimeToCalDateTime",
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
  "CopyLZFile",
  "CreateActCtxA",
  "CreateActCtxW",
  "CreateActCtxWWorker",
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
  "CreateFile2",*/
  {
    "CreateFileA",
    reinterpret_cast<FARPROC>(MyCreateFileA)
  },
  /*"CreateFileMappingA",
  "CreateFileMappingFromApp",
  "CreateFileMappingNumaA",
  "CreateFileMappingNumaW",
  "CreateFileMappingW",
  "CreateFileTransactedA",
  "CreateFileTransactedW", */
  {
    "CreateFileW",
    reinterpret_cast<FARPROC>(MyCreateFileW)
  },
  /*"CreateHardLinkA",
  "CreateHardLinkTransactedA",
  "CreateHardLinkTransactedW",
  "CreateHardLinkW",
  "CreateIoCompletionPort",
  "CreateJobObjectA",
  "CreateJobObjectW",
  "CreateJobSet",
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
  "CreateProcessInternalA",
  "CreateProcessInternalW",
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
  "CtrlRoutine",
  "DeactivateActCtx",
  "DeactivateActCtxWorker",
  "DeactivateActCtxWorker",
  "DeactivateActCtxWorker",
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
  "DnsHostnameToComputerNameExW",
  "DnsHostnameToComputerNameW",
  "DosDateTimeToFileTime",
  "DosPathToSessionPathA",
  "DosPathToSessionPathW",
  "DuplicateConsoleHandle",
  "DuplicateEncryptionInfoFileExt",
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
  "EnumerateLocalComputerNamesA",
  "EnumerateLocalComputerNamesW",
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
  "ExitVDM",
  "ExpandEnvironmentStringsA",
  "ExpandEnvironmentStringsW",
  "ExpungeConsoleCommandHistoryA",
  "ExpungeConsoleCommandHistoryW",
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
  "FindActCtxSectionGuidWorker",
  "FindActCtxSectionStringA",
  "FindActCtxSectionStringW",
  "FindActCtxSectionStringWWorker",
  "FindAtomA",
  "FindAtomW",
  "FindClose",
  "FindCloseChangeNotification",
  "FindFirstChangeNotificationA",
  "FindFirstChangeNotificationW",*/
  {
    "FindFirstFileA",
    reinterpret_cast<FARPROC>(MyFindFirstFileA)
  },
  /*"FindFirstFileExA",
  "FindFirstFileExW",
  "FindFirstFileNameTransactedW",
  "FindFirstFileNameW",
  "FindFirstFileTransactedA",
  "FindFirstFileTransactedW", */
  {
    "FindFirstFileW",
    reinterpret_cast<FARPROC>(MyFindFirstFileW)
  },
  /*"FindFirstStreamTransactedW",
  "FindFirstStreamW",
  "FindFirstVolumeA",
  "FindFirstVolumeMountPointA",
  "FindFirstVolumeMountPointW",
  "FindFirstVolumeW",
  "FindNextChangeNotification",*/
  {
    "FindNextFileA",
    reinterpret_cast<FARPROC>(MyFindNextFileA)
  },
  //"FindNextFileNameW",
  {
    "FindNextFileW",
    reinterpret_cast<FARPROC>(MyFindNextFileW)
  },
  /*"FindNextStreamW",
  "FindNextVolumeA",
  "FindNextVolumeMountPointA",
  "FindNextVolumeMountPointW",
  "FindNextVolumeW",
  "FindNLSString",
  "FindNLSStringEx",
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
  "GetApplicationRecoveryCallbackWorker",
  "GetApplicationRestartSettings",
  "GetApplicationRestartSettingsWorker",
  "GetApplicationUserModelId",
  "GetAtomNameA",
  "GetAtomNameW",
  "GetBinaryType",
  "GetBinaryTypeA",
  "GetBinaryTypeW",
  "GetCachedSigningLevel",
  "GetCalendarDateFormat",
  "GetCalendarDateFormatEx",
  "GetCalendarDaysInMonth",
  "GetCalendarDifferenceInDays",
  "GetCalendarInfoA",
  "GetCalendarInfoEx",
  "GetCalendarInfoW",
  "GetCalendarMonthsInYear",
  "GetCalendarSupportedDateRange",
  "GetCalendarWeekNumber",
  "GetCommandLineA",
  "GetCommandLineW",
  "GetCommConfig",
  "GetCommMask",
  "GetCommModemStatus",
  "GetCommProperties",
  "GetCommState",
  "GetCommTimeouts",
  "GetComPlusPackageInstallStatus",
  "GetCompressedFileSizeA",
  "GetCompressedFileSizeTransactedA",
  "GetCompressedFileSizeTransactedW",
  "GetCompressedFileSizeW",
  "GetComputerNameA",
  "GetComputerNameExA",
  "GetComputerNameExW",
  "GetComputerNameW",
  "GetConsoleAliasA",
  "GetConsoleAliasesA",
  "GetConsoleAliasesLengthA",
  "GetConsoleAliasesLengthW",
  "GetConsoleAliasesW",
  "GetConsoleAliasExesA",
  "GetConsoleAliasExesLengthA",
  "GetConsoleAliasExesLengthW",
  "GetConsoleAliasExesW",
  "GetConsoleAliasW",
  "GetConsoleCharType",
  "GetConsoleCommandHistoryA",
  "GetConsoleCommandHistoryLengthA",
  "GetConsoleCommandHistoryLengthW",
  "GetConsoleCommandHistoryW",
  "GetConsoleCP",
  "GetConsoleCursorInfo",
  "GetConsoleCursorMode",
  "GetConsoleDisplayMode",
  "GetConsoleFontInfo",
  "GetConsoleFontSize",
  "GetConsoleHardwareState",
  "GetConsoleHistoryInfo",
  "GetConsoleInputExeNameA",
  "GetConsoleInputExeNameW",
  "GetConsoleInputWaitHandle",
  "GetConsoleKeyboardLayoutNameA",
  "GetConsoleKeyboardLayoutNameW",
  "GetConsoleMode",
  "GetConsoleNlsMode",
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
  "GetCPInfo",
  "GetCPInfoExA",
  "GetCPInfoExW",
  "GetCurrencyFormatA",
  "GetCurrencyFormatEx",
  "GetCurrencyFormatW",
  "GetCurrentActCtx",
  "GetCurrentActCtxWorker",
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
  "GetDateFormatAWorker",
  "GetDateFormatEx",
  "GetDateFormatW",
  "GetDateFormatWWorker",
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
  "GetEncryptedFileVersionExt",
  "GetEnvironmentStrings",
  "GetEnvironmentStringsA",
  "GetEnvironmentStringsW",
  "GetEnvironmentVariableA",
  "GetEnvironmentVariableW",
  "GetEraNameCountedString",
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
  "GetLocaleInfoA",
  "GetLocaleInfoEx",
  "GetLocaleInfoW",
  "GetLocalTime",
  "GetLogicalDrives",
  "GetLogicalDriveStringsA",
  "GetLogicalDriveStringsW",
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
  "GetNamedPipeAttribute",
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
  "GetNextVDMCommand",
  "GetNLSVersion",
  "GetNLSVersionEx",
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
  "GetPackageInfo",
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
  "GetProcessDefaultCpuSets",
  "GetProcessDEPPolicy",
  "GetProcessGroupAffinity",
  "GetProcessHandleCount",
  "GetProcessHeap",
  "GetProcessHeaps",
  "GetProcessId",
  "GetProcessIdOfThread",
  "GetProcessInformation",
  "GetProcessIoCounters",
  "GetProcessMitigationPolicy",
  "GetProcessorSystemCycleTime",
  "GetProcessPreferredUILanguages",
  "GetProcessPriorityBoost",
  "GetProcessShutdownParameters",
  "GetProcessTimes",
  "GetProcessVersion",
  "GetProcessWorkingSetSize",
  "GetProcessWorkingSetSizeEx",
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
  "GetStateFolder",
  "GetStdHandle",
  "GetStringScripts",
  "GetStringTypeA",
  "GetStringTypeExA",
  "GetStringTypeExW",
  "GetStringTypeW",
  "GetSystemAppDataKey",
  "GetSystemCpuSetInformation",
  "GetSystemDefaultLangID",
  "GetSystemDefaultLCID",
  "GetSystemDefaultLocaleName",
  "GetSystemDefaultUILanguage",
  "GetSystemDEPPolicy",
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
  "GetThreadId",
  "GetThreadIdealProcessorEx",
  "GetThreadInformation",
  "GetThreadIOPendingFlag",
  "GetThreadLocale",
  "GetThreadPreferredUILanguages",
  "GetThreadPriority",
  "GetThreadPriorityBoost",
  "GetThreadPriorityBoost",
  "GetThreadSelectorEntry",
  "GetThreadTimes",
  "GetThreadUILanguage",
  "GetTickCount",
  "GetTickCount64",
  "GetTimeFormatA",
  "GetTimeFormatAWorker",
  "GetTimeFormatEx",
  "GetTimeFormatW",
  "GetTimeFormatWWorker",
  "GetTimeZoneInformation",
  "GetTimeZoneInformationForYear",
  "GetUILanguageInfo",
  "GetUmsCompletionListEvent",
  "GetUmsSystemThreadInformation",
  "GetUserDefaultGeoName",
  "GetUserDefaultLangID",
  "GetUserDefaultLCID",
  "GetUserDefaultLocaleName",
  "GetUserDefaultUILanguage",
  "GetUserGeoID",
  "GetUserPreferredUILanguages",
  "GetVDMCurrentDirectories",
  "GetVersion",
  "GetVersionExA",
  "GetVersionExW",
  "GetVolumeInformationA",
  "GetVolumeInformationByHandleW",
  "GetVolumeInformationW",
  "GetVolumeNameForVolumeMountPointA",
  "GetVolumeNameForVolumeMountPointW",
  "GetVolumePathNameA",
  "GetVolumePathNamesForVolumeNameA",
  "GetVolumePathNamesForVolumeNameW",
  "GetVolumePathNameW",
  "GetWindowsDirectoryA",
  "GetWindowsDirectoryW",
  "GetWriteWatch",
  "GetXStateFeaturesMask",
  "GlobalAddAtomA",
  "GlobalAddAtomExA",
  "GlobalAddAtomExW",
  "GlobalAddAtomW",
  "GlobalAlloc",
  "GlobalCompact",
  "GlobalDeleteAtom",
  "GlobalFindAtomA",
  "GlobalFindAtomW",
  "GlobalFix",
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
  "GlobalUnfix",
  "GlobalUnlock",
  "GlobalUnWire",
  "GlobalWire",
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
  "InitOnceBeginInitialize",
  "InitOnceComplete",
  "InitOnceExecuteOnce",
  "InitOnceInitialize",
  "InstallELAMCertificateInfo",
  "InterlockedFlushSList",
  "InterlockedPopEntrySList",
  "InterlockedPushEntrySList",
  "InterlockedPushListSList",
  "InterlockedPushListSListEx",
  "InvalidateConsoleDIBits",
  "IsBadCodePtr",
  "IsBadHugeReadPtr",
  "IsBadHugeWritePtr",
  "IsBadReadPtr",
  "IsBadStringPtrA",
  "IsBadStringPtrW",
  "IsBadWritePtr",
  "IsCalendarLeapDay",
  "IsCalendarLeapMonth",
  "IsCalendarLeapYear",
  "IsDBCSLeadByte",
  "IsDBCSLeadByteEx",
  "IsDebuggerPresent",
  "IsEnclaveTypeSupported",
  "IsNativeVhdBoot",
  "IsNLSDefinedString",
  "IsNormalizedString",
  "IsProcessCritical",
  "IsProcessInJob",
  "IsProcessorFeaturePresent",
  "IsSystemResumeAutomatic",
  "IsThreadAFiber",
  "IsThreadpoolTimerSet",
  "IsUserCetAvailableInEnvironment",
  "IsValidCalDateTime",
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
  "K32EnumProcesses",
  "K32EnumProcessModules",
  "K32EnumProcessModulesEx",
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
  "LeaveCriticalSection",
  "LeaveCriticalSectionWhenCallbackReturns",
  "LoadAppInitDlls",
  "LoadEnclaveData",
  "LoadLibraryA",
  "LoadLibraryExA",
  "LoadLibraryExW",
  "LoadLibraryW",
  "LoadModule",
  "LoadPackagedLibrary",
  "LoadResource",
  "LoadStringBaseExW",
  "LoadStringBaseW",
  "LocalAlloc",
  "LocalCompact",
  "LocaleNameToLCID",
  "LocalFileTimeToFileTime",
  "LocalFileTimeToLocalSystemTime",
  "LocalFlags",
  "LocalFree",
  "LocalHandle",
  "LocalLock",
  "LocalReAlloc",
  "LocalShrink",
  "LocalSize",
  "LocalSystemTimeToLocalFileTime",
  "LocalUnlock",
  "LocateXStateFeature",
  "LockFile",
  "LockFileEx",
  "LockResource",
  "lstrcatA",
  "lstrcatW",
  "lstrcmpA",
  "lstrcmpiA",
  "lstrcmpiW",
  "lstrcmpW",
  "lstrcpyA",
  "lstrcpynA",
  "lstrcpynW",
  "lstrcpyW",
  "lstrlenA",
  "lstrlenW",
  "LZClose",
  "LZCloseFile",
  "LZCopy",
  "LZCreateFileW",
  "LZDone",
  "LZInit",
  "LZOpenFileA",
  "LZOpenFileW",
  "LZRead",
  "LZSeek",
  "LZStart",
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
  "NlsCheckPolicy",
  "NlsGetCacheUpdateCount",
  "NlsUpdateLocale",
  "NlsUpdateSystemLocale",
  "NormalizeString",
  "NotifyMountMgr",
  "NotifyUILanguageChange",
  "NtVdm64CreateProcessInternalW",
  "OfferVirtualMemory",
  "OOBEComplete",
  "OpenConsoleW",
  "OpenConsoleWStub",
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
  "OpenProfileUserMapping",
  "OpenSemaphoreA",
  "OpenSemaphoreW",
  "OpenState",
  "OpenStateExplicit",
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
  "PrivCopyFileExW",
  "PrivMoveFileIdentityW",
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
  "PssWalkMarkerRewind",
  "PssWalkMarkerSeek",
  "PssWalkMarkerSeekToBeginning",
  "PssWalkMarkerSetPosition",
  "PssWalkMarkerTell",
  "PssWalkSnapshot",
  "PulseEvent",
  "PurgeComm",
  "QueryActCtxSettingsW",
  "QueryActCtxSettingsWWorker",
  "QueryActCtxW",
  "QueryActCtxWWorker",
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
  "QueryThreadpoolStackInformation",
  "QueryThreadProfiling",
  "QueryUmsThreadInformation",
  "QueryUnbiasedInterruptTime",
  "QueueUserAPC",
  "QueueUserWorkItem",
  "QuirkGetData2Worker",
  "QuirkGetDataWorker",
  "QuirkIsEnabled2Worker",
  "QuirkIsEnabled3Worker",
  "QuirkIsEnabledForPackage2Worker",
  "QuirkIsEnabledForPackage3Worker",
  "QuirkIsEnabledForPackage4Worker",
  "QuirkIsEnabledForPackageWorker",
  "QuirkIsEnabledWorker",
  "RaiseException",
  "RaiseFailFastException",
  "RaiseInvalid16BitExeError",
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
  "RegisterApplicationRecoveryCallback",
  "RegisterApplicationRestart",
  "RegisterBadMemoryNotification",
  "RegisterConsoleIME",
  "RegisterConsoleOS2",
  "RegisterConsoleVDM",
  "RegisterWaitForInputIdle",
  "RegisterWaitForSingleObject",
  "RegisterWaitForSingleObjectEx",
  "RegisterWaitUntilOOBECompleted",
  "RegisterWowBaseHandlers",
  "RegisterWowExec",
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
  "ReleaseActCtx",
  "ReleaseActCtxWorker",
  "ReleaseMutex",
  "ReleaseMutexWhenCallbackReturns",
  "ReleaseSemaphore",
  "ReleaseSemaphoreWhenCallbackReturns",
  "ReleaseSRWLockExclusive",
  "ReleaseSRWLockShared",
  "RemoveDirectoryA",
  "RemoveDirectoryTransactedA",
  "RemoveDirectoryTransactedW",
  "RemoveDirectoryW",
  "RemoveDllDirectory",
  "RemoveLocalAlternateComputerNameA",
  "RemoveLocalAlternateComputerNameW",
  "RemoveSecureMemoryCacheCallback",
  "RemoveVectoredContinueHandler",
  "RemoveVectoredExceptionHandler",
  "ReOpenFile",
  "ReplaceFileA",
  "ReplaceFileW",
  "ReplacePartitionUnit",
  "RequestDeviceWakeup",
  "RequestWakeupLatency",
  "ResetEvent",
  "ResetWriteWatch",
  "ResizePseudoConsole",
  "ResolveDelayLoadedAPI",
  "ResolveDelayLoadsFromDll",
  "ResolveLocaleName",
  "RestoreLastError",
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
  "SetCommBreak",
  "SetCommConfig",
  "SetCommMask",
  "SetCommState",
  "SetCommTimeouts",
  "SetComPlusPackageInstallStatus",
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
  "SetConsoleFont",
  "SetConsoleHardwareState",
  "SetConsoleHistoryInfo",
  "SetConsoleIcon",
  "SetConsoleInputExeNameA",
  "SetConsoleInputExeNameW",
  "SetConsoleKeyShortcuts",
  "SetConsoleLocalEUDC",
  "SetConsoleMaximumWindowSize",
  "SetConsoleMenuClose",
  "SetConsoleMode",
  "SetConsoleNlsMode",
  "SetConsoleNumberOfCommandsA",
  "SetConsoleNumberOfCommandsW",
  "SetConsoleOS2OemFormat",
  "SetConsoleOutputCP",
  "SetConsolePalette",
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
  "SetEnvironmentStringsA",
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
  "SetLastConsoleEventActive",
  "SetLastError",
  "SetLocaleInfoA",
  "SetLocaleInfoW",
  "SetLocalPrimaryComputerNameA",
  "SetLocalPrimaryComputerNameW",
  "SetLocalTime",
  "SetMailslotInfo",
  "SetMessageWaitingIndicator",
  "SetNamedPipeAttribute",
  "SetNamedPipeHandleState",
  "SetPriorityClass",
  "SetProcessAffinityMask",
  "SetProcessAffinityUpdateMode",
  "SetProcessDefaultCpuSets",
  "SetProcessDEPPolicy",
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
  "SetThreadAffinityMask",
  "SetThreadDescription",
  "SetThreadErrorMode",
  "SetThreadExecutionState",
  "SetThreadGroupAffinity",
  "SetThreadIdealProcessor",
  "SetThreadIdealProcessorEx",
  "SetThreadInformation",
  "SetThreadLocale",
  "SetThreadpoolStackInformation",
  "SetThreadpoolThreadMaximum",
  "SetThreadpoolThreadMinimum",
  "SetThreadpoolTimer",
  "SetThreadpoolTimerEx",
  "SetThreadpoolWait",
  "SetThreadpoolWaitEx",
  "SetThreadPreferredUILanguages",
  "SetThreadPriority",
  "SetThreadPriorityBoost",
  "SetThreadSelectedCpuSets",
  "SetThreadStackGuarantee",
  "SetThreadToken",
  "SetThreadUILanguage",
  "SetTimerQueueTimer",
  "SetTimeZoneInformation",
  "SetUmsThreadInformation",
  "SetUnhandledExceptionFilter",
  "SetupComm",
  "SetUserGeoID",
  "SetUserGeoName",
  "SetVDMCurrentDirectories",
  "SetVolumeLabelA",
  "SetVolumeLabelW",
  "SetVolumeMountPointA",
  "SetVolumeMountPointW",
  "SetVolumeMountPointWStub",
  "SetWaitableTimer",
  "SetWaitableTimerEx",
  "SetXStateFeaturesMask",
  "ShowConsoleCursor",
  "SignalObjectAndWait",
  "SizeofResource",
  "Sleep",
  "SleepConditionVariableCS",
  "SleepConditionVariableSRW",
  "SleepEx",
  "SortCloseHandle",
  "SortGetHandle",
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
  "TermsrvAppInstallMode",
  "TermsrvConvertSysRootToUserDir",
  "TermsrvCreateRegEntry",
  "TermsrvDeleteKey",
  "TermsrvDeleteValue",
  "TermsrvGetPreSetValue",
  "TermsrvGetWindowsDirectoryA",
  "TermsrvGetWindowsDirectoryW",
  "TermsrvOpenRegEntry",
  "TermsrvOpenUserClasses",
  "TermsrvRestoreKey",
  "TermsrvSetKeySecurity",
  "TermsrvSetValueKey",
  "TermsrvSyncUserIniFileExt",
  "Thread32First",
  "Thread32Next",
  "timeBeginPeriod",
  "timeEndPeriod",
  "timeGetDevCaps",
  "timeGetSystemTime",
  "timeGetTime",
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
  "uaw_lstrcmpiW",
  "uaw_lstrcmpW",
  "uaw_lstrlenW",
  "uaw_wcschr",
  "uaw_wcscpy",
  "uaw_wcsicmp",
  "uaw_wcslen",
  "uaw_wcsrchr",
  "UmsThreadYield",
  "UnhandledExceptionFilter",
  "UnlockFile",
  "UnlockFileEx",
  "UnmapViewOfFile",
  "UnmapViewOfFileEx",
  "UnregisterApplicationRecoveryCallback",
  "UnregisterApplicationRestart",
  "UnregisterBadMemoryNotification",
  "UnregisterConsoleIME",
  "UnregisterWait",
  "UnregisterWaitEx",
  "UnregisterWaitUntilOOBECompleted",
  "UpdateCalendarDayOfWeek",
  "UpdateProcThreadAttribute",
  "UpdateResourceA",
  "UpdateResourceW",
  "UTRegister",
  "UTUnRegister",
  "VDMConsoleOperation",
  "VDMOperationStarted",
  "VerifyConsoleIoHandle",
  "VerifyScripts",
  "VerifyVersionInfoA",
  "VerifyVersionInfoW",
  "VerLanguageNameA",
  "VerLanguageNameW",
  "VerSetConditionMask",
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
  "WerGetFlagsWorker",
  "WerpGetDebugger",
  "WerpInitiateRemoteRecovery",
  "WerpLaunchAeDebug",
  "WerpNotifyLoadStringResourceWorker",
  "WerpNotifyUseStringResourceWorker",
  "WerRegisterAdditionalProcess",
  "WerRegisterAppLocalDump",
  "WerRegisterCustomMetadata",
  "WerRegisterExcludedMemoryBlock",
  "WerRegisterFile",
  "WerRegisterFileWorker",
  "WerRegisterMemoryBlock",
  "WerRegisterMemoryBlockWorker",
  "WerRegisterRuntimeExceptionModule",
  "WerRegisterRuntimeExceptionModuleWorker",
  "WerSetFlags",
  "WerSetFlagsWorker",
  "WerUnregisterAdditionalProcess",
  "WerUnregisterAppLocalDump",
  "WerUnregisterCustomMetadata",
  "WerUnregisterExcludedMemoryBlock",
  "WerUnregisterFile",
  "WerUnregisterFileWorker",
  "WerUnregisterMemoryBlock",
  "WerUnregisterMemoryBlockWorker",
  "WerUnregisterRuntimeExceptionModule",
  "WerUnregisterRuntimeExceptionModuleWorker",
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
  "WriteConsoleInputVDMA",
  "WriteConsoleInputVDMW",
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
  "WTSGetActiveConsoleSessionId",
  "ZombifyActCtx",
  "ZombifyActCtxWorker"*/
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
