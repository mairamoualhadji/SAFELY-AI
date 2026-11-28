using SafelyAI.Common;
using Timer = System.Threading.Timer;
namespace SafelyAI.SystemMonitor.USBMonitor;

public class UsbMonitor
{
    public event Action<string>? DriveInserted;   // à relier à l'analyse des clés USB de Membre 3
    public event Action<string>? DriveRemoved;

    private HashSet<string> _known = new();
    private Timer? _timer;

    public List<string> GetUsbDevices() =>
        Shell.Lines(Shell.PowerShell("Get-PnpDevice -Class USB -PresentOnly | Where-Object { $_.FriendlyName } | ForEach-Object { $_.FriendlyName }"));

    public void Start()
    {
        _known = CurrentDrives();
        _timer = new Timer(_ => Check(), null, 3000, 3000);
    }

    public void Stop() => _timer?.Dispose();

    public void Dispose()
    {
        Stop();
        _timer = null;
    }

    private static HashSet<string> CurrentDrives() =>
        DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Removable && d.IsReady).Select(d => d.Name).ToHashSet();

    private void Check()
    {
        var now = CurrentDrives();
        foreach (var d in now.Except(_known)) DriveInserted?.Invoke(d);
        foreach (var d in _known.Except(now)) DriveRemoved?.Invoke(d);
        _known = now;
    }
}
