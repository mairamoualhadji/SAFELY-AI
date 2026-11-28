using System.Net.NetworkInformation;
namespace SafelyAI.Network.TrafficMonitoring;

public record NetworkTrafficSnapshot(DateTimeOffset CapturedAt, long SentBytes, long ReceivedBytes);

public class TrafficMonitor
{
    public NetworkTrafficSnapshot CaptureSnapshot()
    {
        var totals = GetTotals();
        return new NetworkTrafficSnapshot(DateTimeOffset.UtcNow, totals.Sent, totals.Received);
    }

    public static (long SentBytes, long ReceivedBytes) CalculateDelta(NetworkTrafficSnapshot before, NetworkTrafficSnapshot after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        return (Math.Max(0, after.SentBytes - before.SentBytes), Math.Max(0, after.ReceivedBytes - before.ReceivedBytes));
    }

    public static (long Sent, long Received) GetTotals()
    {
        long sent = 0, received = 0;
        foreach (var n in NetworkInterface.GetAllNetworkInterfaces()
                     .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
        {
            var s = n.GetIPv4Statistics();
            sent += s.BytesSent; received += s.BytesReceived;
        }
        return (sent, received);
    }

    // Débit en Ko/s sur une courte durée.
    public async Task<(double UpKbps, double DownKbps)> MeasureAsync(int milliseconds = 1000)
    {
        var a = GetTotals();
        await Task.Delay(milliseconds);
        var b = GetTotals();
        var sec = milliseconds / 1000.0;
        return ((b.Sent - a.Sent) / 1024.0 / sec, (b.Received - a.Received) / 1024.0 / sec);
    }
}
