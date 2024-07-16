<#

.SYNOPSIS
This is a Powershell script to manage LSA account rights.

.DESCRIPTION
The script contains three functions Get-Rights, Set-Right and Remove-Right to manage LSA rights.

.EXAMPLE
Get-Right -User 'DOMAIN\User'
Get-Right 'User'

.LINK
https://github.com/rzander/LSARights

#>

$class = @"
using System.Text;
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public static class LsaWrapperSetRight
{
    // Import the LSA functions

    [DllImport("advapi32.dll", PreserveSig = true)]
    private static extern UInt32 LsaOpenPolicy(
        ref LSA_UNICODE_STRING SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        Int32 DesiredAccess,
        out IntPtr PolicyHandle
        );

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    private static extern uint LsaAddAccountRights(
        IntPtr PolicyHandle,
        IntPtr AccountSid,
        LSA_UNICODE_STRING[] UserRights,
        uint CountOfRights);

    [DllImport("advapi32.dll", PreserveSig = true)]
    static extern uint LsaRemoveAccountRights(
        IntPtr PolicyHandle,
        IntPtr AccountSid,
        [MarshalAs(UnmanagedType.U1)]
        bool AllRights,
        LSA_UNICODE_STRING[] UserRights,
        uint CountOfRights);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint LsaEnumerateAccountRights(
        IntPtr PolicyHandle,
        IntPtr AccountSid,
        out IntPtr UserRights,
        out uint CountOfRights);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaFreeMemory(System.IntPtr pBuffer);

    [DllImport("advapi32")]
    public static extern void FreeSid(IntPtr pSid);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true, PreserveSig = true)]
    private static extern bool LookupAccountName(
        string lpSystemName, string lpAccountName,
        IntPtr psid,
        ref int cbsid,
        StringBuilder domainName, ref int cbdomainLength, ref int use);

    [DllImport("advapi32.dll")]
    private static extern bool IsValidSid(IntPtr pSid);

    [DllImport("advapi32.dll")]
    private static extern long LsaClose(IntPtr ObjectHandle);

    [DllImport("kernel32.dll")]
    private static extern int GetLastError();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaNtStatusToWinError(uint status);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

    private enum LSA_AccessPolicy : long
    {
        POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
        POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
        POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
        POLICY_TRUST_ADMIN = 0x00000008L,
        POLICY_CREATE_ACCOUNT = 0x00000010L,
        POLICY_CREATE_SECRET = 0x00000020L,
        POLICY_CREATE_PRIVILEGE = 0x00000040L,
        POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
        POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
        POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
        POLICY_SERVER_ADMIN = 0x00000400L,
        POLICY_LOOKUP_NAMES = 0x00000800L,
        POLICY_NOTIFICATION = 0x00001000L
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public readonly LSA_UNICODE_STRING ObjectName;
        public UInt32 Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    /// Name of an account - "domain\account" or only "account"
    /// Name ofthe privilege
    /// The windows error code returned by LsaAddAccountRights
    private static long Init(String accountName, out IntPtr policyHandle, out IntPtr sid)
    {
        long winErrorCode = 0; //contains the last error

        //initialize a pointer for the policy handle
        policyHandle = IntPtr.Zero;
        //pointer an size for the SID
        sid = IntPtr.Zero;
        int sidSize = 0;
        //StringBuilder and size for the domain name
        var domainName = new StringBuilder();
        int nameSize = 0;
        //account-type variable for lookup
        int accountType = 0;

        bool result = true;
        if (accountName.ToLower().StartsWith("s-1-5-"))
        {
            ConvertStringSidToSid(accountName, out sid);
        }
        else
        {
            //get required buffer size
            LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType);

            //allocate buffers
            domainName = new StringBuilder(nameSize);
            sid = Marshal.AllocHGlobal(sidSize);


            //lookup the SID for the account
            result = LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType);
        }

        //say what you're doing
        //Console.WriteLine("LookupAccountName result = " + result);
        //Console.WriteLine("IsValidSid: " + IsValidSid(sid));
        //Console.WriteLine("LookupAccountName domainName: " + domainName);

        if (!result)
        {
            winErrorCode = GetLastError();
            Console.WriteLine("LookupAccountName failed: " + winErrorCode);
            //return winErrorCode;
        }
        else
        {
            //initialize an empty unicode-string
            var systemName = new LSA_UNICODE_STRING();
            //combine all policies
            var access = (int)(
                                    LSA_AccessPolicy.POLICY_AUDIT_LOG_ADMIN |
                                    LSA_AccessPolicy.POLICY_CREATE_ACCOUNT |
                                    LSA_AccessPolicy.POLICY_CREATE_PRIVILEGE |
                                    LSA_AccessPolicy.POLICY_CREATE_SECRET |
                                    LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION |
                                    LSA_AccessPolicy.POLICY_LOOKUP_NAMES |
                                    LSA_AccessPolicy.POLICY_NOTIFICATION |
                                    LSA_AccessPolicy.POLICY_SERVER_ADMIN |
                                    LSA_AccessPolicy.POLICY_SET_AUDIT_REQUIREMENTS |
                                    LSA_AccessPolicy.POLICY_SET_DEFAULT_QUOTA_LIMITS |
                                    LSA_AccessPolicy.POLICY_TRUST_ADMIN |
                                    LSA_AccessPolicy.POLICY_VIEW_AUDIT_INFORMATION |
                                    LSA_AccessPolicy.POLICY_VIEW_LOCAL_INFORMATION
                                );

            //these attributes are not used, but LsaOpenPolicy wants them to exists
            var ObjectAttributes = new LSA_OBJECT_ATTRIBUTES();
            ObjectAttributes.Length = 0;
            ObjectAttributes.RootDirectory = IntPtr.Zero;
            ObjectAttributes.Attributes = 0;
            ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;

            //get a policy handle
            uint resultPolicy = LsaOpenPolicy(ref systemName, ref ObjectAttributes, access, out policyHandle);
            winErrorCode = LsaNtStatusToWinError(resultPolicy);

            if (winErrorCode != 0)
            {
                Console.WriteLine("OpenPolicy failed: " + winErrorCode);
                //return winErrorCode;
            }
        }

        return winErrorCode;
    }

    public static long AddRight(String accountName, String privilegeName)
    {
        IntPtr policyHandle = IntPtr.Zero;
        IntPtr sid = IntPtr.Zero;

        long winErrorCode = 0; //contains the last error

        winErrorCode = Init(accountName, out policyHandle, out sid);
        if (winErrorCode == 0)
        {
            //initialize an unicode-string for the privilege name
            var userRights = new LSA_UNICODE_STRING[1];
            userRights[0] = new LSA_UNICODE_STRING();
            userRights[0].Buffer = Marshal.StringToHGlobalUni(privilegeName);
            userRights[0].Length = (UInt16)(privilegeName.Length * UnicodeEncoding.CharSize);
            userRights[0].MaximumLength = (UInt16)((privilegeName.Length + 1) * UnicodeEncoding.CharSize);

            //add the right to the account
            uint res = LsaAddAccountRights(policyHandle, sid, userRights, 1);
            winErrorCode = LsaNtStatusToWinError(res);
            if (winErrorCode != 0)
            {
                Console.WriteLine("LsaAddAccountRights failed: " + winErrorCode);
            }

            LsaClose(policyHandle);
        }
        FreeSid(sid);
        return winErrorCode;
    }

    public static long RemoveRight(String accountName, String privilegeName)
    {
        IntPtr policyHandle = IntPtr.Zero;
        IntPtr sid = IntPtr.Zero;

        long winErrorCode = 0; //contains the last error

        winErrorCode = Init(accountName, out policyHandle, out sid);
        if (winErrorCode == 0)
        {
            //initialize an unicode-string for the privilege name
            var userRights = new LSA_UNICODE_STRING[1];
            userRights[0] = new LSA_UNICODE_STRING();
            userRights[0].Buffer = Marshal.StringToHGlobalUni(privilegeName);
            userRights[0].Length = (UInt16)(privilegeName.Length * UnicodeEncoding.CharSize);
            userRights[0].MaximumLength = (UInt16)((privilegeName.Length + 1) * UnicodeEncoding.CharSize);

            //add the right to the account
            uint res = LsaRemoveAccountRights(policyHandle, sid, false, userRights, 1);
            winErrorCode = LsaNtStatusToWinError(res);
            if (winErrorCode != 0)
            {
                Console.WriteLine("LsaRemoveAccountRights failed: " + winErrorCode);
            }

            LsaClose(policyHandle);
        }
        FreeSid(sid);
        return winErrorCode;
    }

    public static string[] GetRight(String accountName)
    {
        IntPtr policyHandle = IntPtr.Zero;
        IntPtr sid = IntPtr.Zero;
        List<string> lResult = new List<string>();

        long winErrorCode = 0; //contains the last error

        winErrorCode = Init(accountName, out policyHandle, out sid);
        if (winErrorCode == 0)
        {
            IntPtr rightsPtr = IntPtr.Zero;
            uint countOfRights;

            long res = LsaEnumerateAccountRights(policyHandle, sid, out rightsPtr, out countOfRights);
            try
            {
                IntPtr ptr = rightsPtr;
                for (Int32 i = 0; i < countOfRights; i++)
                {
                    var structure = (LSA_UNICODE_STRING)Marshal.PtrToStructure(ptr, typeof(LSA_UNICODE_STRING));

                    char[] destination = new char[structure.Length / sizeof(char)];
                    Marshal.Copy(structure.Buffer, destination, 0, destination.Length);

                    string userRightStr = new string(destination, 0, destination.Length);

                    lResult.Add(userRightStr);

                    ptr = (IntPtr)(((long)ptr) + Marshal.SizeOf(typeof(LSA_UNICODE_STRING)));
                }
            }
            finally
            {
                LsaFreeMemory(rightsPtr);
            }

            LsaClose(policyHandle);
        }
        FreeSid(sid);
        return lResult.ToArray();
    }
}
"@


Add-Type -TypeDefinition $class

function Get-Rights {
    <#
  .SYNOPSIS
  Get all LSA Rights for a specific user.
  .DESCRIPTION
  LSA Rights:
SeBatchLogonRight = Required for an account to log on using the batch logon type.
SeDenyBatchLogonRight = Explicitly denies an account the right to log on using the batch logon type.
SeDenyInteractiveLogonRight = Explicitly denies an account the right to log on using the interactive logon type.
SeDenyNetworkLogonRight = Explicitly denies an account the right to log on using the network logon type.
SeDenyRemoteInteractiveLogonRight = Explicitly denies an account the right to log on remotely using the interactive logon type.
SeDenyServiceLogonRight = Explicitly denies an account the right to log on using the service logon type.
SeInteractiveLogonRight = Required for an account to log on using the interactive logon type.
SeNetworkLogonRight = Required for an account to log on using the network logon type.
SeRemoteInteractiveLogonRight = Required for an account to log on remotely using the interactive logon type.
SeServiceLogonRight = Required for an account to log on using the service logon type.
  .EXAMPLE
  Get-Rights -Username 'Domain\Username'
  .EXAMPLE
  Get-Rights #will take current user as account.
  .PARAMETER Username
  The name of User in the format DOMAIN\USERNAME
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = 'Username to get LSA rights.')]
        [Alias('user')]
        [ValidateLength(4, 40)]
        [string] $Username = $env:USERDOMAIN + '\' + $env:USERNAME
    )

    begin {
        [LsaWrapperSetRight]::GetRight($Username) 
    }
}

function Set-Right {
    <#
  .SYNOPSIS
  Set LSA Rights for a specific user.
  .DESCRIPTION
  LSA Rights:
SeBatchLogonRight = Required for an account to log on using the batch logon type.
SeDenyBatchLogonRight = Explicitly denies an account the right to log on using the batch logon type.
SeDenyInteractiveLogonRight = Explicitly denies an account the right to log on using the interactive logon type.
SeDenyNetworkLogonRight = Explicitly denies an account the right to log on using the network logon type.
SeDenyRemoteInteractiveLogonRight = Explicitly denies an account the right to log on remotely using the interactive logon type.
SeDenyServiceLogonRight = Explicitly denies an account the right to log on using the service logon type.
SeInteractiveLogonRight = Required for an account to log on using the interactive logon type.
SeNetworkLogonRight = Required for an account to log on using the network logon type.
SeRemoteInteractiveLogonRight = Required for an account to log on remotely using the interactive logon type.
SeServiceLogonRight = Required for an account to log on using the service logon type.
  .EXAMPLE
  Set-Right -Username 'Domain\Username' -Right 'SeServiceLogonRight'
  .EXAMPLE
  Set-Right -Right 'SeServiceLogonRight' #will take current user as account.
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = 'Username to set LSA rights.')]
        [Alias('user')]
        [ValidateLength(4, 40)]
        [string] $Username = $env:USERDOMAIN + '\' + $env:USERNAME,
        [Parameter(Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = 'LSA rights to add')]
        [ValidateSet('SeServiceLogonRight', 'SeRemoteInteractiveLogonRight', 'SeNetworkLogonRight', 
            'SeInteractiveLogonRight', 'SeDenyServiceLogonRight', 'SeDenyRemoteInteractiveLogonRight', 
            'SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyBatchLogonRight', 'SeBatchLogonRight'  )]
        [string] $Right
    )

    begin {
        $res = [LsaWrapperSetRight]::AddRight($Username, $Right) 
        if ($res -ne 0) { Write-Error -Message "Unable to set LSA rights." -ErrorId $res } 
    }
}

function Remove-Right {
    <#
  .SYNOPSIS
  Remove an LSA Right for a specific user.
  .DESCRIPTION
  LSA Rights:
SeBatchLogonRight = Required for an account to log on using the batch logon type.
SeDenyBatchLogonRight = Explicitly denies an account the right to log on using the batch logon type.
SeDenyInteractiveLogonRight = Explicitly denies an account the right to log on using the interactive logon type.
SeDenyNetworkLogonRight = Explicitly denies an account the right to log on using the network logon type.
SeDenyRemoteInteractiveLogonRight = Explicitly denies an account the right to log on remotely using the interactive logon type.
SeDenyServiceLogonRight = Explicitly denies an account the right to log on using the service logon type.
SeInteractiveLogonRight = Required for an account to log on using the interactive logon type.
SeNetworkLogonRight = Required for an account to log on using the network logon type.
SeRemoteInteractiveLogonRight = Required for an account to log on remotely using the interactive logon type.
SeServiceLogonRight = Required for an account to log on using the service logon type.
  .EXAMPLE
  Remove-Right -Username 'Domain\Username' -Right 'SeServiceLogonRight'
  .EXAMPLE
  Remove-Right -Right 'SeServiceLogonRight' #will take current user as account.
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = 'Username to get LSA rights.')]
        [Alias('user')]
        [ValidateLength(4, 40)]
        [string] $Username = $env:USERDOMAIN + '\' + $env:USERNAME,
        [Parameter(Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = 'LSA rights to remove')]
        [ValidateSet('SeServiceLogonRight', 'SeRemoteInteractiveLogonRight', 'SeNetworkLogonRight', 
            'SeInteractiveLogonRight', 'SeDenyServiceLogonRight', 'SeDenyRemoteInteractiveLogonRight', 
            'SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyBatchLogonRight', 'SeBatchLogonRight'  )]
        [string] $Right
    )

    begin {
        $res = [LsaWrapperSetRight]::RemoveRight($Username, $Right)
        if ($res -ne 0) { Write-Error -Message "Unable to remove LSA rights." -ErrorId $res } 
    }
}
