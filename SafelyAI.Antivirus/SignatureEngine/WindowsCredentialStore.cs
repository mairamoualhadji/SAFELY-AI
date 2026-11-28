using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SafelyAI.Antivirus.SignatureEngine;

/// <summary>Stores feed credentials in the current Windows user's Credential Manager.</summary>
public static class WindowsCredentialStore
{
    private const string TargetName = "SAFELY-AI/MalwareBazaar/AuthKey";
    private const uint GenericCredential = 1;
    private const uint PersistLocalMachine = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeCredential
    {
        public uint Flags;
        public uint Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Comment;
        public NativeFileTime LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] public string? TargetAlias;
        [MarshalAs(UnmanagedType.LPWStr)] public string? UserName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime { public uint Low; public uint High; }

    [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWrite(ref NativeCredential credential, uint flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredRead(string target, uint type, uint reserved, out IntPtr credential);

    [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredFree")]
    private static extern void CredFree(IntPtr buffer);

    public static bool HasApiKey()
    {
        if (!OperatingSystem.IsWindows()) return false;
        if (!CredRead(TargetName, GenericCredential, 0, out var pointer))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == 1168) return false;
            throw new Win32Exception(error, "Impossible de lire la clé du Gestionnaire d’identifiants Windows.");
        }
        try
        {
            var credential = Marshal.PtrToStructure<NativeCredential>(pointer);
            return credential.CredentialBlob != IntPtr.Zero && credential.CredentialBlobSize is > 0 and <= 512;
        }
        finally { CredFree(pointer); }
    }

    public static void SaveApiKey(string apiKey)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Le Gestionnaire d’identifiants nécessite Windows.");
        apiKey = apiKey?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(apiKey) || apiKey.Length > 512 || apiKey.Any(character => character is < '!' or > '~'))
            throw new ArgumentException("La clé API est vide ou invalide.", nameof(apiKey));

        var secret = Encoding.UTF8.GetBytes(apiKey.Trim());
        var blob = Marshal.AllocHGlobal(secret.Length);
        try
        {
            Marshal.Copy(secret, 0, blob, secret.Length);
            var credential = new NativeCredential
            {
                Type = GenericCredential,
                TargetName = TargetName,
                CredentialBlob = blob,
                CredentialBlobSize = checked((uint)secret.Length),
                Persist = PersistLocalMachine,
                UserName = Environment.UserName
            };
            if (!CredWrite(ref credential, 0)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Impossible d’enregistrer la clé dans le Gestionnaire d’identifiants Windows.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            for (var index = 0; index < secret.Length; index++) Marshal.WriteByte(blob, index, 0);
            Marshal.FreeHGlobal(blob);
        }
    }

    public static bool TryRead(out string apiKey)
    {
        apiKey = string.Empty;
        if (!OperatingSystem.IsWindows()) return false;
        if (!CredRead(TargetName, GenericCredential, 0, out var pointer))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == 1168) return false; // ERROR_NOT_FOUND
            throw new Win32Exception(error, "Impossible de lire la clé du Gestionnaire d’identifiants Windows.");
        }

        try
        {
            var credential = Marshal.PtrToStructure<NativeCredential>(pointer);
            if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize is 0 or > 512) return false;
            var bytes = new byte[checked((int)credential.CredentialBlobSize)];
            try
            {
                Marshal.Copy(credential.CredentialBlob, bytes, 0, bytes.Length);
                apiKey = Encoding.UTF8.GetString(bytes);
                return !string.IsNullOrWhiteSpace(apiKey);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        finally { CredFree(pointer); }
    }

    public static void DeleteApiKey()
    {
        if (!OperatingSystem.IsWindows()) return;
        if (!CredDelete(TargetName, GenericCredential, 0) && Marshal.GetLastWin32Error() != 1168)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Impossible de supprimer la clé du Gestionnaire d’identifiants Windows.");
    }
}
