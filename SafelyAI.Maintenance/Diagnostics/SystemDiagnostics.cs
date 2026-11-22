
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace SafelyAI.Maintenance.Diagnostics
{
    public class SystemDiagnostics
    {
        public SystemDiagnosticsResult Analyze()
        {
            var result = new SystemDiagnosticsResult();

            try
            {
                result.ComputerName = Environment.MachineName;
                result.UserName = Environment.UserName;
                result.OperatingSystem = RuntimeInformation.OSDescription;
                result.ProcessorCount = Environment.ProcessorCount;
                result.Is64BitOperatingSystem =
                    Environment.Is64BitOperatingSystem;

                // Informations sur le disque système
                string systemDrive = Path.GetPathRoot(
                    Environment.SystemDirectory
                ) ?? "C:\\";

                var drive = DriveInfo.GetDrives()
                    .FirstOrDefault(d =>
                        d.IsReady &&
                        d.Name.Equals(
                            systemDrive,
                            StringComparison.OrdinalIgnoreCase
                        )
                    );

                if (drive != null)
                {
                    result.TotalDiskSpaceGB =
                        Math.Round(drive.TotalSize / 1073741824.0, 2);

                    result.FreeDiskSpaceGB =
                        Math.Round(drive.AvailableFreeSpace / 1073741824.0, 2);
                }

                // Mémoire physique disponible sur Windows
                if (OperatingSystem.IsWindows())
                {
                    var memory = new MEMORYSTATUSEX();

                    if (GlobalMemoryStatusEx(memory))
                    {
                        result.TotalMemoryGB =
                            Math.Round(memory.ullTotalPhys / 1073741824.0, 2);

                        result.AvailableMemoryGB =
                            Math.Round(memory.ullAvailPhys / 1073741824.0, 2);
                    }
                }

                result.Success = true;
                result.Status = "Diagnostic terminé.";
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Status = "Erreur : " + ex.Message;
            }

            return result;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private class MEMORYSTATUSEX
        {
            public uint dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(
            [In, Out] MEMORYSTATUSEX lpBuffer
        );
    }

    public class SystemDiagnosticsResult
    {
        public bool Success { get; set; }
        public string Status { get; set; } = "";
        public string ComputerName { get; set; } = "";
        public string UserName { get; set; } = "";
        public string OperatingSystem { get; set; } = "";
        public int ProcessorCount { get; set; }
        public bool Is64BitOperatingSystem { get; set; }
        public double TotalMemoryGB { get; set; }
        public double AvailableMemoryGB { get; set; }
        public double TotalDiskSpaceGB { get; set; }
        public double FreeDiskSpaceGB { get; set; }
    }
}
