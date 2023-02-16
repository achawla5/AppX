param (
    [Parameter(Mandatory = $true)]
    [UInt32]$ProcessId,
    [Parameter(Mandatory = $true)]
    [string]$DumpPath,
    [string]$DumpType="Full"
    )


<#
.SYNOPSIS
Script to dump PPL processes

.DESCRIPTION
Script to dump PPL processes

.PARAMETER ProcessId
    Pid of the process to dump

.Parameter DumpPath
    Path of the dump file to be generated

.Parameter DumpType
    Type of dump

#>

$WerFileTypeDump = 3

switch($DumpType)
{
    "Micro" { $WerFileTypeDump = 1 }
    "Mini" { $WerFileTypeDump = 2 }
    "Full" { $WerFileTypeDump = 3 }
    "Triage" { $WerFileTypeDump = 6 }
    default  { $WerFileTypeDump = $DumpType }
}

function Check-Permissions {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Prepare-Win32Native {
$CreateProcessCode = @'

public static readonly UInt32 CREATE_PROTECTED_PROCESS = 0x00040000;
public static readonly UInt32 GENERIC_WRITE = 0x40000000;
public static readonly UInt32 CREATE_NEW = 1;

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
  public IntPtr hProcess;
  public IntPtr hThread;
  public UInt32  dwProcessId;
  public UInt32  dwThreadId;
}

[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFO
{
  public UInt32  cb;
  public IntPtr lpReserved;
  public IntPtr lpDesktop;
  public IntPtr lpTitle;
  public UInt32  dwX;
  public UInt32  dwY;
  public UInt32  dwXSize;
  public UInt32  dwYSize;
  public UInt32  dwXCountChars;
  public UInt32  dwYCountChars;
  public UInt32  dwFillAttribute;
  public UInt32  dwFlags;
  public UInt16   wShowWindow;
  public UInt16   cbReserved2;
  public IntPtr lpReserved2;
  public IntPtr hStdInput;
  public IntPtr hStdOutput;
  public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES {
  public UInt32  nLength;
  public IntPtr lpSecurityDescriptor;
  public bool bInheritHandle;
}

[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CreateProcessW(string lpApplicationName,
    string lpCommandLine,
    IntPtr lpProcessAttributes,
    IntPtr lpThreadAttributes,
    bool bInheritHandles,
    UInt32 dwCreationFlags,
    IntPtr lpEnvironment,
    IntPtr lpCurrentDirectory,
    [In] ref STARTUPINFO lpStartupInfo,
    [In] [Out] ref PROCESS_INFORMATION lpProcessInformation);

[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern IntPtr CreateEvent(
  [In] ref SECURITY_ATTRIBUTES lpEventAttributes,
  [In] bool bManualReset,
  [In] bool bInitialState,
  [In] string lpName);

[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern IntPtr CreateFile(
  [In]     string               lpFileName,
  [In]     UInt32                 dwDesiredAccess,
  [In]     UInt32                 dwShareMode,
  [In] ref SECURITY_ATTRIBUTES lpSecurityAttributes,
  [In]     UInt32                 dwCreationDisposition,
  [In]     UInt32                 dwFlagsAndAttributes,
  [In]     IntPtr                hTemplateFile
);

[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
public static extern UInt32 WaitForSingleObject(
  [In] IntPtr hHandle,
  [In] UInt32 dwMilliseconds
);

[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
public static extern bool CloseHandle(
  [In] IntPtr hObject
);

[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
public static extern bool GetExitCodeProcess(
  [In] IntPtr  hProcess,
  [In] [Out] ref UInt32 lpExitCode
);

'@

Add-Type -MemberDefinition $CreateProcessCode -Name "Kernel32" -Namespace "Win32API"
}

function Start-Protected-Process($Application, $CommandLine)
{
    $procInfo = New-Object -TypeName "Win32API.Kernel32+PROCESS_INFORMATION";
    $startupInfo = New-Object -TypeName "Win32API.Kernel32+STARTUPINFO"
    $startupInfo.cb = [Runtime.InteropServices.Marshal]::SizeOf($startupInfo)
    
    $retVal = [Win32API.Kernel32]::CreateProcessW($Application, $commandLine, 0, 0, $true, [Win32API.Kernel32]::CREATE_PROTECTED_PROCESS, 0, 0, [ref] $startupInfo, [ref] $procInfo);
    Log-Verbose CreateProcess returned $retVal
    if (!$retVal)
    {
        throw "Unable to start werfault process. LastError=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    return $procInfo
}

function Create-Inheritable-Security-Attributes
{
    $secAttributes = New-Object -TypeName "Win32API.Kernel32+SECURITY_ATTRIBUTES"
    $secAttributes.nLength = [Runtime.InteropServices.Marshal]::SizeOf($secAttributes)
    $secAttributes.bInheritHandle = $true;

    return $secAttributes
}

function Create-Inheritable-Event
{
    $secAttributes = Create-Inheritable-Security-Attributes
    return [Win32API.Kernel32]::CreateEvent([ref] $secAttributes, $false, $false, $null)
}

function Create-Dump-File($Path)
{
    $secAttributes = Create-Inheritable-Security-Attributes
    $fileHandle = [Win32API.Kernel32]::CreateFile($Path, [Win32API.Kernel32]::GENERIC_WRITE, 0, [ref] $secAttributes, [Win32API.Kernel32]::CREATE_NEW, 0, 0)

    if ($fileHandle -eq -1)
    {
        throw "Cannot create file $dumpPath with write access. LastError=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    return $fileHandle
}

function Wait-For-Process($ProcInfo)
{
    return [Win32API.Kernel32]::WaitForSingleObject($ProcInfo.hProcess, [UInt32]::MaxValue)
}

function Get-ExitCode($ProcInfo)
{
    [UInt32]$exitCode = [UInt32]::MaxValue;
    $retVal = [Win32API.Kernel32]::GetExitCodeProcess($ProcInfo.hProcess, [ref] $exitCode);
    return $exitCode
}

function Close-Handle($Handle)
{
    return [Win32API.Kernel32]::CloseHandle($Handle)
}

function Log-Error($Message)
{
    Write-Host -ForeGroundColor Red $Message
}

function Log-Information($Message)
{
    Write-Host $Message
}

function Log-Verbose($Message)
{
    Write-Verbose $Message
}

function Log-Success($Message)
{
    Write-Host -ForegroundColor Green $Message
}

if (!$(Check-Permissions))
{
    Log-Error "Script is not running with sufficient privileges. Please run as an elevated administrator"
    exit 1
}

$cancelEvent = 0
$fileHandle = -1

try
{
    Prepare-Win32Native

    $cancelEvent = Create-Inheritable-Event
    $fileHandle = Create-Dump-File -Path $DumpPath

    Log-Verbose "Created cancel event: $cancelEvent"
    Log-Verbose "Created file handle: $fileHandle"

    Log-Verbose "Setting dump type to: $WerFileTypeDump"
    $commandLine = "c:\\windows\\system32\\werfaultsecure.exe /h /s /pid $ProcessId /type $WerFileTypeDump /encfile $fileHandle /cancel $cancelEvent"
    Log-Verbose "Running command line: $commandLine"

    Log-Information "Starting dump of process PID $ProcessId"
    $procInfo = Start-Protected-Process -Application "C:\\windows\\system32\\werfaultsecure.exe" -CommandLine $commandLine
    $waitVal = Wait-For-Process $procInfo
    Log-Verbose "Wait for process returned: $waitVal"

    if ($waitVal -ne 0)
    {
        throw "Waiting for process failed. Wait returned: $waitVal"
    }

    $exitCode = Get-ExitCode $procInfo

    Log-Verbose "Werfault returned: $exitCode"
    if ($exitCode -ne 0)
    {
        throw "Werfault returned non-zero value: $exitCode"
    }

    Log-Success "Dump completed successfully"
}
catch
{
    Write-Error $_;
}
finally
{
    if ($cancelEvent -ne 0)
    {
        <# Suppress output #>
        $retval = Close-Handle $cancelEvent
    }

    if ($fileHandle -ne -1)
    {
        <# Suppress output #>
        $retval = Close-Handle $fileHandle
    }

    if ($procInfo -ne $null)
    {
        if ($procInfo.hProcess -ne 0)
        {
            <# Suppress output #>
            $retval = Close-Handle $procInfo.hProcess
        }

        if ($procInfo.hThread -ne 0)
        {
            <# Suppress output #>
            $retval = Close-Handle $procInfo.hThread
        }
    }
}


