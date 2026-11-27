namespace SafelyAI.Antivirus.FileScanner;

public static class ScanScopes
{
    public static IEnumerable<string> Quick()
    {
        foreach (var name in new[] { "Desktop", "Downloads", "Documents" })
        {
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), name);
            if (Directory.Exists(path)) yield return path;
        }
        var temp = Path.GetTempPath();
        if (Directory.Exists(temp)) yield return temp;
    }
    public static IEnumerable<string> Full() => DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed).Select(d => d.RootDirectory.FullName);
}
