#include "framework.h"
#include "hooker.h"

#include <unordered_map>
#include <string>
#include <initializer_list>

PIPEINST _pipeInst;
Tracking _track;
HMODULE _hKernel = NULL;

std::initializer_list<std::string> _funcNames = {
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
  "AdjustCalendarDate",
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
  "BaseCheckAppcompatCache",
  "BaseCheckAppcompatCacheEx",
  "BaseCheckAppcompatCacheExWorker",
  "BaseCheckAppcompatCacheWorker",
  "BaseCheckElevation",
  "BaseCleanupAppcompatCacheSupport",
  "BaseCleanupAppcompatCacheSupportWorker",
  "BaseDestroyVDMEnvironment",
  "BaseDllReadWriteIniFile",
  "BaseDumpAppcompatCache",
  "BaseDumpAppcompatCacheWorker",
  "BaseElevationPostProcessing",
  "BaseFlushAppcompatCache",
  "BaseFlushAppcompatCacheWorker",
  "BaseFormatObjectAttributes",
  "BaseFormatTimeOut",
  "BaseFreeAppCompatDataForProcessWorker",
  "BaseGenerateAppCompatData",
  "BaseGetNamedObjectDirectory",
  "BaseInitAppcompatCacheSupport",
  "BaseInitAppcompatCacheSupportWorker",
  "BaseIsAppcompatInfrastructureDisabled",
  "BaseIsAppcompatInfrastructureDisabledWorker",
  "BaseIsDosApplication",
  "Basep8BitStringToDynamicUnicodeString",
  "BasepAllocateActivationContextActivationBlock",
  "BasepAnsiStringToDynamicUnicodeString",
  "BasepAppContainerEnvironmentExtension",
  "BasepAppXExtension",
  "BasepCheckAppCompat",
  "BasepCheckWebBladeHashes",
  "BasepCheckWinSaferRestrictions",
  "BasepConstructSxsCreateProcessMessage",
  "BasepCopyEncryption",
  "BasepFinishPackageActivationForSxS",
  "BasepFreeActivationContextActivationBlock",
  "BasepFreeAppCompatData",
  "BasepGetAppCompatData",
  "BasepGetComputerNameFromNtPath",
  "BasepGetExeArchType",
  "BasepGetPackageActivationTokenForSxS",
  "BasepInitAppCompatData",
  "BasepIsProcessAllowed",
  "BasepMapModuleHandle",
  "BasepNotifyLoadStringResource",
  "BasepPostSuccessAppXExtension",
  "BasepProcessInvalidImage",
  "BasepQueryAppCompat",
  "BasepQueryModuleChpeSettings",
  "BasepReleaseAppXContext",
  "BasepReleaseSxsCreateProcessUtilityStruct",
  "BasepReportFault",
  "BasepSetFileEncryptionCompression",
  "BaseQueryModuleData",
  "BaseReadAppCompatDataForProcessWorker",
  "BaseSetLastNTError",
  "BaseThreadInitThunk",
  "BaseUpdateAppcompatCache",
  "BaseUpdateAppcompatCacheWorker",
  "BaseUpdateVDMEntry",
  "BaseVerifyUnicodeString",
  "BaseWriteErrorElevationRequiredEvent",
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
  "CancelDeviceWakeupRequest",
  "CancelIo",
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
  "CloseConsoleHandle",
  "CloseHandle",
  "ClosePackageInfo",
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
  "ZombifyActCtxWorker"
};

std::unordered_map<std::string, FARPROC> _funcHooksMap = {
  { "AcquireSRWLockExclusive", (FARPROC)_MyAcquireSRWLockExclusive },
  { "AcquireSRWLockShared", (FARPROC)_MyAcquireSRWLockShared },
  { "ActivateActCtx", (FARPROC)_MyActivateActCtx },
  { "AddAtomA", (FARPROC)_MyAddAtomA },
  { "AddAtomW", (FARPROC)_MyAddAtomW },
  { "AddConsoleAliasA", (FARPROC)_MyAddConsoleAliasA },
  { "AddConsoleAliasW", (FARPROC)_MyAddConsoleAliasW },
  { "AddDllDirectory", (FARPROC)_MyAddDllDirectory },
  { "AddIntegrityLabelToBoundaryDescriptor", (FARPROC)_MyAddIntegrityLabelToBoundaryDescriptor },
  { "AddLocalAlternateComputerNameA", (FARPROC)_MyAddLocalAlternateComputerNameA },
  { "AddLocalAlternateComputerNameW", (FARPROC)_MyAddLocalAlternateComputerNameW },
  { "AddRefActCtx", (FARPROC)_MyAddRefActCtx },
  { "AddResourceAttributeAce", (FARPROC)_MyAddResourceAttributeAce },
  { "AddSecureMemoryCacheCallback", (FARPROC)_MyAddSecureMemoryCacheCallback },
  { "AddSIDToBoundaryDescriptor", (FARPROC)_MyAddSIDToBoundaryDescriptor },
  { "AddVectoredContinueHandler", (FARPROC)_MyAddVectoredContinueHandler },
  { "AddVectoredExceptionHandler", (FARPROC)_MyAddVectoredExceptionHandler },
  { "AllocateUserPhysicalPages", (FARPROC)_MyAllocateUserPhysicalPages },
  { "AllocateUserPhysicalPagesNuma", (FARPROC)_MyAllocateUserPhysicalPagesNuma },
  { "AllocConsole", (FARPROC)_MyAllocConsole },
  { "ApplicationRecoveryFinished", (FARPROC)_MyApplicationRecoveryFinished },
  { "ApplicationRecoveryInProgress", (FARPROC)_MyApplicationRecoveryInProgress },
  { "AppPolicyGetClrCompat", (FARPROC)_MyAppPolicyGetClrCompat },
  { "AppPolicyGetMediaFoundationCodecLoading", (FARPROC)_MyAppPolicyGetMediaFoundationCodecLoading },
  { "AppPolicyGetProcessTerminationMethod", (FARPROC)_MyAppPolicyGetProcessTerminationMethod },
  { "AppPolicyGetThreadInitializationType", (FARPROC)_MyAppPolicyGetThreadInitializationType },
  { "AppPolicyGetWindowingModel", (FARPROC)_MyAppPolicyGetWindowingModel },
  { "AreFileApisANSI", (FARPROC)_MyAreFileApisANSI },
  { "AssignProcessToJobObject", (FARPROC)_MyAssignProcessToJobObject },
  /*"AttachConsole",
  "BackupRead",
  "BackupSeek",
  "BackupWrite",
  "BaseCheckAppcompatCache",
  "BaseCheckAppcompatCacheEx",
  "BaseCheckAppcompatCacheExWorker",
  "BaseCheckAppcompatCacheWorker",
  "BaseCheckElevation",
  "BaseCleanupAppcompatCacheSupport",
  "BaseCleanupAppcompatCacheSupportWorker",
  "BaseDestroyVDMEnvironment",
  "BaseDllReadWriteIniFile",
  "BaseDumpAppcompatCache",
  "BaseDumpAppcompatCacheWorker",
  "BaseElevationPostProcessing",
  "BaseFlushAppcompatCache",
  "BaseFlushAppcompatCacheWorker",
  "BaseFormatObjectAttributes",
  "BaseFormatTimeOut",
  "BaseFreeAppCompatDataForProcessWorker",
  "BaseGenerateAppCompatData",
  "BaseGetNamedObjectDirectory",
  "BaseInitAppcompatCacheSupport",
  "BaseInitAppcompatCacheSupportWorker",
  "BaseIsAppcompatInfrastructureDisabled",
  "BaseIsAppcompatInfrastructureDisabledWorker",
  "BaseIsDosApplication",
  "Basep8BitStringToDynamicUnicodeString",
  "BasepAllocateActivationContextActivationBlock",
  "BasepAnsiStringToDynamicUnicodeString",
  "BasepAppContainerEnvironmentExtension",
  "BasepAppXExtension",
  "BasepCheckAppCompat",
  "BasepCheckWebBladeHashes",
  "BasepCheckWinSaferRestrictions",
  "BasepConstructSxsCreateProcessMessage",
  "BasepCopyEncryption",
  "BasepFinishPackageActivationForSxS",
  "BasepFreeActivationContextActivationBlock",
  "BasepFreeAppCompatData",
  "BasepGetAppCompatData",
  "BasepGetComputerNameFromNtPath",
  "BasepGetExeArchType",
  "BasepGetPackageActivationTokenForSxS",
  "BasepInitAppCompatData",
  "BasepIsProcessAllowed",
  "BasepMapModuleHandle",
  "BasepNotifyLoadStringResource",
  "BasepPostSuccessAppXExtension",
  "BasepProcessInvalidImage",
  "BasepQueryAppCompat",
  "BasepQueryModuleChpeSettings",
  "BasepReleaseAppXContext",
  "BasepReleaseSxsCreateProcessUtilityStruct",
  "BasepReportFault",
  "BasepSetFileEncryptionCompression",
  "BaseQueryModuleData",
  "BaseReadAppCompatDataForProcessWorker",
  "BaseSetLastNTError",
  "BaseThreadInitThunk",
  "BaseUpdateAppcompatCache",
  "BaseUpdateAppcompatCacheWorker",
  "BaseUpdateVDMEntry",
  "BaseVerifyUnicodeString",
  "BaseWriteErrorElevationRequiredEvent", */
  { "Beep", (FARPROC)_MyBeep },
/*  "BeginUpdateResourceA",
  "BeginUpdateResourceW",
  "BindIoCompletionCallback",
  "BuildCommDCBA",
  "BuildCommDCBAndTimeoutsA",
  "BuildCommDCBAndTimeoutsW",
  "BuildCommDCBW",
  "CallbackMayRunLong",
  "CallNamedPipeA",
  "CallNamedPipeW",
  "CancelDeviceWakeupRequest",
  "CancelIo",
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
  { "CloseHandle", (FARPROC)_MyCloseHandle },
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
  { "CreateFileA", (FARPROC)_MyCreateFileA },
  /*"CreateFileMappingA",
  "CreateFileMappingFromApp",
  "CreateFileMappingNumaA",
  "CreateFileMappingNumaW",
  "CreateFileMappingW",
  "CreateFileTransactedA",
  "CreateFileTransactedW", */
  { "CreateFileW", (FARPROC)_MyCreateFileW },
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
  { "FindFirstFileA", (FARPROC)_MyFindFirstFileA },
  /*"FindFirstFileExA",
  "FindFirstFileExW",
  "FindFirstFileNameTransactedW",
  "FindFirstFileNameW",
  "FindFirstFileTransactedA",
  "FindFirstFileTransactedW", */
  { "FindFirstFileW", (FARPROC)_MyFindFirstFileW },
  /*"FindFirstStreamTransactedW",
  "FindFirstStreamW",
  "FindFirstVolumeA",
  "FindFirstVolumeMountPointA",
  "FindFirstVolumeMountPointW",
  "FindFirstVolumeW",
  "FindNextChangeNotification",*/
  { "FindNextFileA", (FARPROC)_MyFindNextFileA },
  //"FindNextFileNameW",
  { "FindNextFileW", (FARPROC)_MyFindNextFileW },
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
    for (const auto& __funcName : _funcNames) {
      FARPROC __baseFuncAddr = GetProcAddress(_hKernel, __funcName.data());
      _funcMap[__funcName.data()] = __baseFuncAddr;
    }
  }
  return (_hKernel == NULL) ? FALSE : TRUE;
}

void _Deinit() {
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
  BOOL __success = FALSE;
  DWORD __mode = 0;

  std::string __pipeName(PIPE_NAME);
  __pipeName += std::to_string(_pipeInst._pid);

  while (true) {
    _pipeInst._pipe = CreateFileA(
      __pipeName.data(),
      GENERIC_READ | GENERIC_WRITE,
      0,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );

    if (_pipeInst._pipe != INVALID_HANDLE_VALUE) { break; }

    if (GetLastError() != ERROR_PIPE_BUSY) { return FALSE; }
    if (!WaitNamedPipeA(__pipeName.data(), 20000)) { return FALSE; }
  }

  __mode = PIPE_READMODE_MESSAGE;
  __success = SetNamedPipeHandleState(_pipeInst._pipe, &__mode, NULL, NULL);

  return __success;
}

BOOL _RecvInit() {

  BOOL __success = FALSE;
  DWORD __size = 0;

  __success = ReadFile(
    _pipeInst._pipe,
    &__size,
    sizeof(DWORD),
    &_pipeInst._cbRead,
    NULL
  );

  if (!__success) { return FALSE; }

  for (DWORD __idx = 0; __idx < __size; ++__idx) {
    ZeroMemory(_pipeInst._reqBuff, PIPE_BUFFER_SIZE * sizeof(TCHAR));
    DWORD __strLen = 0;
    BOOL __verbose = FALSE;

    __success = ReadFile(
      _pipeInst._pipe,
      &__strLen,
      sizeof(DWORD),
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success || __strLen == 0) { return FALSE; }

    __success = ReadFile(
      _pipeInst._pipe,
      _pipeInst._reqBuff,
      __strLen,
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success) { return FALSE; }

    __success = ReadFile(
      _pipeInst._pipe,
      &__verbose,
      sizeof(BOOL),
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success) { return FALSE; }

    _track._funcNames.emplace(
      std::string(_pipeInst._reqBuff, __strLen),
      __verbose
    );
  }

  // Hide filenames
  __success = ReadFile(
    _pipeInst._pipe,
    &__size,
    sizeof(DWORD),
    &_pipeInst._cbRead,
    NULL
  );

  if (!__success) { return FALSE; }

  for (DWORD __idx = 0; __idx < __size; ++__idx) {
    ZeroMemory(_pipeInst._reqBuff, PIPE_BUFFER_SIZE);
    DWORD __strLen = 0;
    __success = ReadFile(
      _pipeInst._pipe,
      &__strLen,
      sizeof(DWORD),
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success || __strLen == 0) { return FALSE; }

    __success = ReadFile(
      _pipeInst._pipe,
      _pipeInst._reqBuff,
      __strLen,
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success) { return FALSE; }
    _track._hideFilenamesA.emplace_back(_pipeInst._reqBuff, __strLen);
  }

  __success = ReadFile(
    _pipeInst._pipe,
    &__size,
    sizeof(DWORD),
    &_pipeInst._cbRead,
    NULL
  );

  if (!__success) { return FALSE; }

  for (DWORD __idx = 0; __idx < __size; ++__idx) {
    ZeroMemory(_pipeInst._reqBuff, PIPE_BUFFER_SIZE);
    DWORD __strLen = 0;
    __success = ReadFile(
      _pipeInst._pipe,
      &__strLen,
      sizeof(DWORD),
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success || __strLen == 0) { return FALSE; }

    __success = ReadFile(
      _pipeInst._pipe,
      _pipeInst._reqBuff,
      __strLen * sizeof(WCHAR),
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success) { return FALSE; }
    _track._hideFilenamesW.emplace_back(
      reinterpret_cast<WCHAR*>(_pipeInst._reqBuff), __strLen
    );
  }

  return TRUE;
}

void _DisconnectPipe() {
  if (_pipeInst._pipe != INVALID_HANDLE_VALUE) { CloseHandle(_pipeInst._pipe); }
}

BOOL _ParseInit() { 
  BOOL __res = TRUE;
  for (const auto& __el : _track._funcNames) {
    __res &= _AddHook(__el.first);
  }
  return __res;
}

BOOL _AddHook(const std::string& __funcName) {

  HOOK_TRACE_INFO _hHook = { NULL };
  FARPROC __baseFunc = _funcMap[__funcName];
  FARPROC __hookFunc = _funcHooksMap[__funcName];
  NTSTATUS __res = 0;
  __res = LhInstallHook(
    __baseFunc,
    __hookFunc,
    NULL,
    &_hHook
  );
  if (FAILED(__res)) { return FALSE; }
  ULONG __aclEntries[1] = { 0 };
  if (FAILED(LhSetExclusiveACL(__aclEntries, 1, &_hHook))) { return FALSE; }

  return TRUE;
}

void _SendInfo(std::string __funcName) {
  DWORD __cbWritten = 0;
  BOOL __success = FALSE;
  SYSTEMTIME __time;
  GetLocalTime(&__time);
  StringCchPrintfA(_pipeInst._replyBuff, PIPE_BUFFER_SIZE,
    "PID: %d %02d/%02d/%02d %02d:%02d:%02d call %s",
    _pipeInst._pid, __time.wDay, __time.wMonth, __time.wYear % 100,
    __time.wHour, __time.wMinute, __time.wSecond, __funcName.data());

  _pipeInst._cbToWrite = DWORD(strlen(_pipeInst._replyBuff)) + 1;
  __success = WriteFile(
    _pipeInst._pipe,
    _pipeInst._replyBuff,
    _pipeInst._cbToWrite,
    &__cbWritten,
    NULL
  );
  __success = WriteFile(
    _pipeInst._pipe,
    _pipeInst._replyBuff,
    _pipeInst._cbToWrite,
    &__cbWritten,
    NULL
  );
}

void _MyAcquireSRWLockExclusive(PSRWLOCK __SRWLock) {
  using func_type = void(*)(PSRWLOCK);
  std::string __funcName("AcquireSRWLockExclusive");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__SRWLock);
}

void _MyAcquireSRWLockShared(PSRWLOCK __SRWLock) {
  using func_type = void(*)(PSRWLOCK);
  std::string __funcName("AcquireSRWLockShared");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__SRWLock);
}

BOOL _MyActivateActCtx(HANDLE __hActCtx, ULONG_PTR* __lpCookie) {
  using func_type = BOOL(*)(HANDLE, ULONG_PTR*);
  std::string __funcName("ActivateActCtx");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__hActCtx, __lpCookie);
}

ATOM _MyAddAtomA(LPCSTR __lpString) {
  using func_type = ATOM(*)(LPCSTR);
  std::string __funcName("AddAtomA");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return 0; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__lpString);
}

ATOM _MyAddAtomW(LPCWSTR __lpString) {
  using func_type = ATOM(*)(LPCWSTR);
  std::string __funcName("AddAtomW");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return 0; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__lpString);
}

BOOL WINAPI _MyAddConsoleAliasA(LPCSTR __Source, LPCSTR __Target, LPCSTR __ExeName) {
  using func_type = BOOL(WINAPI*)(LPCSTR, LPCSTR, LPCSTR);
  std::string __funcName("AddConsoleAliasA");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__Source, __Target, __ExeName);
}

BOOL WINAPI _MyAddConsoleAliasW(LPCWSTR __Source, LPCWSTR __Target,
  LPCWSTR __ExeName) {
  using func_type = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPCWSTR);
  std::string __funcName("AddConsoleAliasW");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__Source, __Target, __ExeName);
}

DLL_DIRECTORY_COOKIE _MyAddDllDirectory(PCWSTR __NewDirectory) {
  using func_type = DLL_DIRECTORY_COOKIE(*)(PCWSTR);
  std::string __funcName("AddDllDirectory");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return 0; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__NewDirectory);
}

BOOL _MyAddIntegrityLabelToBoundaryDescriptor(HANDLE* __BoundaryDescriptor ,
  PSID __IntegrityLabel) {
  using func_type = BOOL(*)(HANDLE*, PSID);
  std::string __funcName("AddIntegrityLabelToBoundaryDescriptor");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return 0; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__BoundaryDescriptor, __IntegrityLabel);
}

DWORD _MyAddLocalAlternateComputerNameA(LPCSTR __lpDnsFQHostName,
  ULONG __ulFlag) {
  using func_type = DWORD(*)(LPCSTR, ULONG);
  std::string __funcName("AddLocalAlternateComputerNameA");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__lpDnsFQHostName, __ulFlag);
}

DWORD _MyAddLocalAlternateComputerNameW(LPCWSTR __lpDnsFQHostName,
  ULONG __ulFlag) {
  using func_type = DWORD(*)(LPCWSTR, ULONG);
  std::string __funcName("AddLocalAlternateComputerNameW");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__lpDnsFQHostName, __ulFlag);
}

void _MyAddRefActCtx(HANDLE __hActCtx) {
  using func_type = void(*)(HANDLE);
  std::string __funcName("AddRefActCtx");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__hActCtx);
}

BOOL _MyAddResourceAttributeAce(
  PACL __pAcl,
  DWORD __dwAceRevision,
  DWORD __AceFlags,
  DWORD __AccessMask,
  PSID __pSid,
  PCLAIM_SECURITY_ATTRIBUTES_INFORMATION __pAttributeInfo,
  PDWORD __pReturnLength) {
  using func_type = BOOL(*)(PACL, DWORD, DWORD, DWORD, PSID,
    PCLAIM_SECURITY_ATTRIBUTES_INFORMATION, PDWORD);
  std::string __funcName("AddResourceAttributeAce");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__pAcl ,__dwAceRevision, __AceFlags, __AccessMask, __pSid,
    __pAttributeInfo, __pReturnLength);
}

BOOL _MyAddSecureMemoryCacheCallback(PSECURE_MEMORY_CACHE_CALLBACK __pfnCallBack) {
  using func_type = BOOL(*)(PSECURE_MEMORY_CACHE_CALLBACK);
  std::string __funcName("AddSecureMemoryCacheCallback");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__pfnCallBack);
}

BOOL _MyAddSIDToBoundaryDescriptor(HANDLE* __BoundaryDescriptor,
  PSID __RequireSid) {
  using func_type = BOOL(*)(HANDLE*, PSID);
  std::string __funcName("AddSIDToBoundaryDescriptor");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__BoundaryDescriptor, __RequireSid);
}

PVOID _MyAddVectoredContinueHandler(ULONG __First,
  PVECTORED_EXCEPTION_HANDLER __Handler) {
  using func_type = PVOID(*)(ULONG, PVECTORED_EXCEPTION_HANDLER);
  std::string __funcName("AddVectoredContinueHandler");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return NULL; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__First, __Handler);
}

PVOID _MyAddVectoredExceptionHandler(ULONG __First,
  PVECTORED_EXCEPTION_HANDLER __Handler) {
  using func_type = PVOID(*)(ULONG, PVECTORED_EXCEPTION_HANDLER);
  std::string __funcName("AddVectoredExceptionHandler");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return NULL; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__First, __Handler);
}

BOOL _MyAllocateUserPhysicalPages(HANDLE __hProcess,
  PULONG_PTR __NumberOfPages, PULONG_PTR __PageArray) {
  using func_type = BOOL(*)(HANDLE, PULONG_PTR, PULONG_PTR);
  std::string __funcName("AllocateUserPhysicalPages");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return NULL; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__hProcess, __NumberOfPages, __PageArray);
}

BOOL _MyAllocateUserPhysicalPagesNuma(HANDLE __hProcess,
  PULONG_PTR __NumberOfPages, PULONG_PTR __PageArray, DWORD __nndPreferred) {
  using func_type = BOOL(*)(HANDLE, PULONG_PTR, PULONG_PTR, DWORD);
  std::string __funcName("AllocateUserPhysicalPagesNuma");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return NULL; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__hProcess, __NumberOfPages, __PageArray, __nndPreferred);
}

BOOL WINAPI _MyAllocConsole() {
  using func_type = BOOL(WINAPI*)();
  std::string __funcName("AllocConsole");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return NULL; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc();
}

void _MyApplicationRecoveryFinished(BOOL __bSuccess) {
  using func_type = void(*)(BOOL);
  std::string __funcName("ApplicationRecoveryFinished");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__bSuccess);
}

HRESULT _MyApplicationRecoveryInProgress(PBOOL __pbCancelled) {
  using func_type = HRESULT(*)(PBOOL);
  std::string __funcName("ApplicationRecoveryInProgress");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return E_FAIL; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__pbCancelled);
}

LONG _MyAppPolicyGetClrCompat(HANDLE __processToken,
  AppPolicyClrCompat* __policy) {
  using func_type = LONG(*)(HANDLE, AppPolicyClrCompat*);
  std::string __funcName("AppPolicyGetClrCompat");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__processToken, __policy);
}

LONG _MyAppPolicyGetMediaFoundationCodecLoading(HANDLE __processToken,
  AppPolicyMediaFoundationCodecLoading* __policy) {
  using func_type = LONG(*)(HANDLE, AppPolicyMediaFoundationCodecLoading*);
  std::string __funcName("AppPolicyGetMediaFoundationCodecLoading");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__processToken, __policy);
}

LONG _MyAppPolicyGetProcessTerminationMethod(HANDLE __processToken,
  AppPolicyProcessTerminationMethod* __policy) {
  using func_type = LONG(*)(HANDLE, AppPolicyProcessTerminationMethod*);
  std::string __funcName("AppPolicyGetProcessTerminationMethod");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__processToken, __policy);
}

LONG _MyAppPolicyGetThreadInitializationType(HANDLE __processToken,
  AppPolicyThreadInitializationType* __policy) {
  using func_type = LONG(*)(HANDLE, AppPolicyThreadInitializationType*);
  std::string __funcName("AppPolicyGetThreadInitializationType");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__processToken, __policy);
}

LONG _MyAppPolicyGetWindowingModel(HANDLE __processToken,
  AppPolicyWindowingModel* __policy) {
  using func_type = LONG(*)(HANDLE, AppPolicyWindowingModel*);
  std::string __funcName("AppPolicyGetWindowingModel");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return ERROR_INVALID_PARAMETER; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__processToken, __policy);
}

BOOL _MyAreFileApisANSI() {
  using func_type = BOOL(*)();
  std::string __funcName("AreFileApisANSI");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc();
}

BOOL _MyAssignProcessToJobObject(HANDLE __hJob, HANDLE __hProcess) {
  using func_type = BOOL(*)(HANDLE, HANDLE);
  std::string __funcName("AssignProcessToJobObject");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__hJob, __hProcess);
}

BOOL WINAPI _MyAttachConsole(DWORD __dwProcessId) {
  using func_type = BOOL(WINAPI*)(DWORD);
  std::string __funcName("AttachConsole");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__dwProcessId);
}

BOOL _MyBackupRead(
  HANDLE __hFile,
  LPBYTE __lpBuffer,
  DWORD __nNumberOfBytesToRead,
  LPDWORD __lpNumberOfBytesRead,
  BOOL __bAbort,
  BOOL __bProcessSecurity,
  LPVOID* __lpContext) {
  using func_type = BOOL(*)(HANDLE, LPBYTE, DWORD, LPDWORD, BOOL, BOOL,
    LPVOID*);
  std::string __funcName("BackupRead");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__hFile, __lpBuffer, __nNumberOfBytesToRead,
    __lpNumberOfBytesRead, __bAbort, __bProcessSecurity, __lpContext);
}

BOOL _MyBackupSeek(
  HANDLE __hFile,
  DWORD __dwLowBytesToSeek,
  DWORD __dwHighBytesToSeek,
  LPDWORD __lpdwLowByteSeeked,
  LPDWORD __lpdwHighByteSeeked,
  LPVOID* __lpContext) {
  using func_type = BOOL(*)(HANDLE, DWORD, DWORD, LPDWORD, LPDWORD, LPVOID*);
  std::string __funcName("BackupSeek");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__hFile, __dwLowBytesToSeek, __dwHighBytesToSeek,
    __lpdwLowByteSeeked, __lpdwHighByteSeeked, __lpContext);
}

BOOL _MyBackupWrite(
  HANDLE __hFile,
  LPBYTE __lpBuffer,
  DWORD __nNumberOfBytesToWrite,
  LPDWORD __lpNumberOfBytesWritten,
  BOOL __bAbort,
  BOOL __bProcessSecurity,
  LPVOID* __lpContext) {
  using func_type = BOOL(*)(HANDLE, LPBYTE, DWORD, LPDWORD, BOOL, BOOL, LPVOID*);
  std::string __funcName("BackupWrite");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__hFile, __lpBuffer, __nNumberOfBytesToWrite,
    __lpNumberOfBytesWritten, __bAbort, __bProcessSecurity, __lpContext);
}

HANDLE _MyFindFirstFileA(LPCSTR __lpFileName,
  LPWIN32_FIND_DATAA __lpFindFileData) {
  using func_type = HANDLE(*)(LPCSTR, LPWIN32_FIND_DATAA);
  std::string __funcName("FindFirstFileA");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);

  HANDLE __res = __baseFunc(__lpFileName, __lpFindFileData);
  if (__res == INVALID_HANDLE_VALUE) { return __res; }

  BOOL __bFound = _CheckA(__lpFileName);
  return __bFound ? INVALID_HANDLE_VALUE : __res;
}
HANDLE _MyFindFirstFileW(LPCWSTR __lpFileName,
  LPWIN32_FIND_DATAW __lpFindFileData) {
  using func_type = HANDLE(*)(LPCWSTR, LPWIN32_FIND_DATAW);
  std::string __funcName("FindFirstFileA");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);

  HANDLE __res = __baseFunc(__lpFileName, __lpFindFileData);
  if (__res == INVALID_HANDLE_VALUE) { return __res; }

  BOOL __bFound = _CheckW(__lpFileName);
  return __bFound ? INVALID_HANDLE_VALUE : __res;
}

BOOL _MyFindNextFileA(HANDLE __hFindFile, LPWIN32_FIND_DATAA __lpFindFileData) {
  using func_type = BOOL(*)(HANDLE, LPWIN32_FIND_DATAA);
  std::string __funcName("FindNextFileA");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  
  BOOL __bRes = TRUE;
  while (__baseFunc(__hFindFile, __lpFindFileData)) {
    if (!_CheckA(__lpFindFileData->cFileName)) { return TRUE; }
  }

  return FALSE;
}
BOOL _MyFindNextFileW(HANDLE __hFindFile, LPWIN32_FIND_DATAW __lpFindFileData) {
  using func_type = BOOL(*)(HANDLE, LPWIN32_FIND_DATAW);
  std::string __funcName("FindNextFileW");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  
  BOOL __bRes = TRUE;
  WCHAR __tmpFileName[MAX_PATH * 10] = { 0 };
  do {
    if (!_CheckW(__lpFindFileData->cFileName)) { return TRUE; }
  } while (__baseFunc(__hFindFile, __lpFindFileData));

  return FALSE;
}

HANDLE _MyCreateFileA(
  LPCSTR __lpFileName,
  DWORD __dwDesiredAccess,
  DWORD __dwSharedMode,
  LPSECURITY_ATTRIBUTES __lpSecurityAttributes,
  DWORD __dwCreationDisposition,
  DWORD __dwFlagsAndAttributes,
  HANDLE __hTemplateFile) {
  using func_type = HANDLE(*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
    DWORD, DWORD, HANDLE);
  std::string __funcName("CreateFileA");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  if (_CheckA(__lpFileName)) { return INVALID_HANDLE_VALUE; }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  
  return __baseFunc(__lpFileName, __dwDesiredAccess, __dwSharedMode,
    __lpSecurityAttributes, __dwCreationDisposition, __dwFlagsAndAttributes,
    __hTemplateFile);
}

HANDLE _MyCreateFileW(
  LPCWSTR __lpFileName,
  DWORD __dwDesiredAccess,
  DWORD __dwSharedMode,
  LPSECURITY_ATTRIBUTES __lpSecurityAttributes,
  DWORD __dwCreationDisposition,
  DWORD __dwFlagsAndAttributes,
  HANDLE __hTemplateFile) {
  using func_type = HANDLE(*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
    DWORD, DWORD, HANDLE);
  std::string __funcName("CreateFileW");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  if (_CheckW(__lpFileName)) { return INVALID_HANDLE_VALUE; }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);

  return __baseFunc(__lpFileName, __dwDesiredAccess, __dwSharedMode,
    __lpSecurityAttributes, __dwCreationDisposition, __dwFlagsAndAttributes,
    __hTemplateFile);
}

BOOL _MyBeep(DWORD __dwFreq, DWORD __dwDuration) {
  using func_type = BOOL(WINAPI*)(DWORD, DWORD);
  std::string __funcName("Beep");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__dwFreq, __dwDuration);
}

BOOL _MyCloseHandle(HANDLE __hObject) {
  using func_type = BOOL(*)(HANDLE);
  std::string __funcName("CloseHandle");

  if (_track._funcNames.count(__funcName) && _track._funcNames[__funcName]) {
    _SendInfo(__funcName);
  }

  auto __baseFuncAddr = _funcMap[__funcName];
  if (__baseFuncAddr == NULL) { return FALSE; }
  func_type __baseFunc = reinterpret_cast<func_type>(__baseFuncAddr);
  return __baseFunc(__hObject);
}

BOOL _CheckA(LPCSTR __lpFileName) {
  BOOL __bFound = FALSE;
  for (const auto& __el : _track._hideFilenamesA) {
    if (!__el.compare(__lpFileName))  {
      __bFound = TRUE;
      break;
    }
  }
  return __bFound;
}

BOOL _CheckW(LPCWSTR __lpFileName) {
  BOOL __bFound = FALSE;
  for (const auto& __el : _track._hideFilenamesW) {
    if (!__el.compare(__lpFileName))  {
      __bFound = TRUE;
      break;
    }
  }
  return __bFound;
}
