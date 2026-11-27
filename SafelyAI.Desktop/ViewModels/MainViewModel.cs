using System.Collections.ObjectModel;
using SafelyAI.Desktop.Helpers;
using SafelyAI.Desktop.Services;
using SafelyAI.Desktop.Views;

namespace SafelyAI.Desktop.ViewModels;

public sealed class NavigationItem(string key, string title, string glyph) : ObservableObject
{
    private bool _isSelected;
    public string Key { get; } = key;
    public string Title { get; } = title;
    public string Glyph { get; } = glyph;
    public bool IsSelected { get => _isSelected; set => Set(ref _isSelected, value); }
}

public class MainViewModel : ObservableObject
{
    private object? _currentView;
    private string _currentPageTitle = "Vue d’ensemble";
    private string _currentPageDescription = "L’essentiel de votre sécurité, réuni au même endroit.";
    private bool _isDarkMode = true;

    public DesktopSession Session { get; } = new();
    private readonly DashboardView _dashboard;
    private readonly AntivirusView _antivirus;
    private readonly QuarantineView _quarantine;
    private readonly NetworkView _network;
    private readonly SystemView _system;
    private readonly IdentityView _identity;
    private readonly WebProtectionView _web;
    private readonly MaintenanceView _maintenance;
    private readonly ReportsView _reports;
    private readonly SettingsView _settings;

    public ObservableCollection<NavigationItem> NavigationItems { get; } =
    [
        new("Dashboard", "Vue d’ensemble", "◫"), new("Antivirus", "Antivirus", "◈"),
        new("Quarantine", "Quarantaine", "▣"), new("Network", "Réseau", "⌁"),
        new("System", "Système", "▤"), new("Identity", "Comptes", "♙"),
        new("WebProtection", "Protection Web", "◎"), new("Maintenance", "Maintenance", "⌘"),
        new("Reports", "Rapports", "▥"), new("Settings", "Paramètres", "⚙")
    ];

    public object? CurrentView { get => _currentView; private set => Set(ref _currentView, value); }
    public string CurrentPageTitle { get => _currentPageTitle; private set => Set(ref _currentPageTitle, value); }
    public string CurrentPageDescription { get => _currentPageDescription; private set => Set(ref _currentPageDescription, value); }
    public string ThemeGlyph => _isDarkMode ? "☼" : "☾";
    public int NotificationCount => Session.NotificationCount;
    public RelayCommand NavigateCommand { get; }
    public RelayCommand ToggleThemeCommand { get; }
    public RelayCommand ClearNotificationsCommand { get; }

    public MainViewModel()
    {
        _dashboard = new DashboardView { DataContext = new DashboardViewModel(Session) };
        _antivirus = new AntivirusView { DataContext = new AntivirusViewModel(Session) };
        _quarantine = new QuarantineView { DataContext = new QuarantineViewModel(Session) };
        _network = new NetworkView { DataContext = new NetworkViewModel() };
        _system = new SystemView { DataContext = new SystemViewModel() };
        _identity = new IdentityView { DataContext = new IdentityViewModel(Session) };
        _web = new WebProtectionView { DataContext = new WebProtectionViewModel(Session) };
        _maintenance = new MaintenanceView { DataContext = new MaintenanceViewModel(Session) };
        _reports = new ReportsView { DataContext = new ReportsViewModel(Session) };
        var settingsViewModel = new SettingsViewModel(Session);
        _isDarkMode = settingsViewModel.IsDarkMode;
        settingsViewModel.ThemeChanged += dark => { _isDarkMode = dark; OnPropertyChanged(nameof(ThemeGlyph)); };
        _settings = new SettingsView { DataContext = settingsViewModel };
        Session.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(DesktopSession.NotificationCount)) OnPropertyChanged(nameof(NotificationCount));
        };
        NavigateCommand = new(p => Navigate(p as string ?? "Dashboard"));
        ToggleThemeCommand = new(_ => ToggleTheme());
        ClearNotificationsCommand = new(_ => Session.ClearNotifications());
        Navigate("Dashboard");
    }

    private void ToggleTheme()
    {
        _isDarkMode = !_isDarkMode;
        ThemeService.Apply(_isDarkMode);
        OnPropertyChanged(nameof(ThemeGlyph));
        if (_settings.DataContext is SettingsViewModel settings) settings.IsDarkMode = _isDarkMode;
    }

    private void Navigate(string key)
    {
        var item = NavigationItems.FirstOrDefault(x => x.Key == key) ?? NavigationItems[0];
        foreach (var nav in NavigationItems) nav.IsSelected = nav == item;
        switch (item.Key)
        {
            case "Antivirus": SetPage(_antivirus, "Antivirus", "Analysez les fichiers localement et gérez les éléments détectés."); break;
            case "Quarantine": SetPage(_quarantine, "Quarantaine", "Éléments isolés par le moteur local; restauration après confirmation."); break;
            case "Network": SetPage(_network, "Protection réseau", "Connexions TCP et trafic observés sur cet appareil."); break;
            case "System": SetPage(_system, "Surveillance du système", "Ressources et processus Windows en lecture seule."); break;
            case "Identity": SetPage(_identity, "Protection des comptes", "Audit local des comptes et des événements disponibles."); break;
            case "WebProtection": SetPage(_web, "Protection Web", "Analyse heuristique locale des URL et téléchargements."); break;
            case "Maintenance": SetPage(_maintenance, "Maintenance", "Diagnostic et nettoyage temporaire avec validation."); break;
            case "Reports": SetPage(_reports, "Rapports", "Historique des analyses et export de rapport."); break;
            case "Settings": SetPage(_settings, "Paramètres", "Préférences d’affichage et niveau de protection."); break;
            default: SetPage(_dashboard, "Vue d’ensemble", "L’essentiel de votre sécurité, réuni au même endroit."); break;
        }
        if (item.Key == "System" && _system.DataContext is SystemViewModel system) system.RefreshCommand.Execute(null);
        if (item.Key == "Network" && _network.DataContext is NetworkViewModel network) network.RefreshCommand.Execute(null);
        OnPropertyChanged(nameof(CurrentView)); OnPropertyChanged(nameof(CurrentPageTitle)); OnPropertyChanged(nameof(CurrentPageDescription));
    }

    private void SetPage(object view, string title, string description)
    {
        CurrentView = view; CurrentPageTitle = title; CurrentPageDescription = description;
    }
}
