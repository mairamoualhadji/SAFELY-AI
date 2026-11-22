using SafelyAI.Desktop.Helpers;
using SafelyAI.Desktop.Views;
namespace SafelyAI.Desktop.ViewModels;
public class MainViewModel : ObservableObject
{
    private object? _current;
    private readonly DashboardViewModel _dashboard = new();
    private readonly SettingsViewModel _settings = new();
    public object? CurrentView { get => _current; set => Set(ref _current, value); }
    public RelayCommand NavigateCommand { get; }
    public MainViewModel()
    {
        NavigateCommand = new(p => Navigate(p as string ?? "Dashboard"));
        Navigate("Dashboard");
    }
    private void Navigate(string key) => CurrentView = key switch
    {
        "Antivirus" => new AntivirusView(),
        "Quarantine" => new QuarantineView(),
        "Network" => new NetworkView(),
        "System" => new SystemView(),
        "Identity" => new IdentityView(),
        "WebProtection" => new WebProtectionView(),
        "Maintenance" => new MaintenanceView(),
        "Reports" => new ReportsView(),
        "Settings" => new SettingsView { DataContext = _settings },
        _ => new DashboardView { DataContext = _dashboard }
    };
}
