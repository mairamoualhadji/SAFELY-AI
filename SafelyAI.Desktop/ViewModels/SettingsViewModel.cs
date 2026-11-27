using SafelyAI.Desktop.Helpers;
using SafelyAI.Desktop.Services;

namespace SafelyAI.Desktop.ViewModels;

public class SettingsViewModel : ObservableObject
{
    private bool _dark = true;
    private string _mode;
    private readonly DesktopSession _session;
    public event Action<bool>? ThemeChanged;
    public bool IsDarkMode
    {
        get => _dark;
        set { if (Set(ref _dark, value)) { ThemeService.Apply(value); Save(); ThemeChanged?.Invoke(value); } }
    }
    public string Mode
    {
        get => _mode;
        set
        {
            if (Set(ref _mode, value))
            {
                _session.ProtectionMode = value;
                OnPropertyChanged(nameof(ModeDescription));
                Save();
                _session.AddNotification("Mode modifié", $"Le mode {value} est sélectionné pour cette session.", "Information");
            }
        }
    }
    public string ModeDescription => Mode switch
    {
        "Économie de ressources" => "Réduit la fréquence de vérification des téléchargements surveillés à 3 secondes. Les autres scans restent manuels.",
        "Protection maximale" => "Vérifie plus souvent les téléchargements surveillés (toutes les 0,5 seconde). Les autres scans restent manuels.",
        _ => "Vérifie les téléchargements surveillés chaque seconde. Les autres scans restent manuels."
    };
    public string[] Modes { get; } = ["Économie de ressources", "Équilibré", "Protection maximale"];

    public SettingsViewModel(DesktopSession session)
    {
        _session = session;
        var preferences = AppPreferencesStore.Load();
        _dark = preferences.IsDarkMode;
        _mode = Modes.Contains(preferences.ProtectionMode) ? preferences.ProtectionMode : "Équilibré";
        _session.ProtectionMode = _mode;
        ThemeService.Apply(_dark);
    }

    private void Save() => AppPreferencesStore.Save(new AppPreferences(IsDarkMode, Mode));
}
