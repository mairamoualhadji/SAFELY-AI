using SafelyAI.Desktop.Helpers;
using SafelyAI.Desktop.Services;

namespace SafelyAI.Desktop.ViewModels;

public class SettingsViewModel : ObservableObject
{
    private bool _dark = true;
    private string _mode;
    private readonly DesktopSession _session;
    private bool _isBackgroundProtectionEnabled;
    private string _backgroundProtectionStatus = "Surveillance en arrière-plan désactivée.";
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
    public bool IsBackgroundProtectionEnabled
    {
        get => _isBackgroundProtectionEnabled;
        private set { if (Set(ref _isBackgroundProtectionEnabled, value)) OnPropertyChanged(nameof(CanEnableBackgroundProtection)); }
    }
    public bool CanEnableBackgroundProtection => !IsBackgroundProtectionEnabled;
    public string BackgroundProtectionStatus { get => _backgroundProtectionStatus; private set => Set(ref _backgroundProtectionStatus, value); }
    public RelayCommand EnableBackgroundProtectionCommand { get; }
    public RelayCommand DisableBackgroundProtectionCommand { get; }

    public SettingsViewModel(DesktopSession session)
    {
        _session = session;
        var preferences = AppPreferencesStore.Load();
        _dark = preferences.IsDarkMode;
        _mode = Modes.Contains(preferences.ProtectionMode) ? preferences.ProtectionMode : "Équilibré";
        _session.ProtectionMode = _mode;
        ThemeService.Apply(_dark);
        RefreshBackgroundProtectionState();
        EnableBackgroundProtectionCommand = new(_ => EnableBackgroundProtection());
        DisableBackgroundProtectionCommand = new(_ => DisableBackgroundProtection());
    }

    private void RefreshBackgroundProtectionState()
    {
        try
        {
            IsBackgroundProtectionEnabled = UserBackgroundProtectionStartup.IsEnabled();
            BackgroundProtectionStatus = IsBackgroundProtectionEnabled
                ? "Activée au démarrage de votre session Windows. Contrôle jusqu’à 20 000 fichiers déjà présents puis les nouveaux téléchargements; tente un scan Defender sans UAC pour les nouveaux fichiers et continue localement si refusé. Mode utilisateur, sans blocage noyau."
                : "Désactivée. L’agent surveille le dossier Téléchargements quand il est activé, même après fermeture de la fenêtre SAFELY AI.";
        }
        catch (Exception exception)
        {
            IsBackgroundProtectionEnabled = false;
            BackgroundProtectionStatus = $"État du démarrage automatique indisponible : {exception.Message}";
        }
    }

    private void EnableBackgroundProtection()
    {
        try
        {
            UserBackgroundProtectionStartup.EnableAndStart();
            IsBackgroundProtectionEnabled = true;
            BackgroundProtectionStatus = "Activée. L’agent contrôle les fichiers déjà présents dans Téléchargements puis les nouveaux fichiers, tente un scan Defender sans UAC pour les nouveaux, applique le mode enregistré et isole les matches SHA-256 exacts.";
            _session.AddNotification("Protection en arrière-plan activée", "L’agent se lance maintenant et à l’ouverture de votre session Windows. Il fonctionne en mode utilisateur et ne bloque pas avant exécution.", "Information");
        }
        catch (Exception exception)
        {
            IsBackgroundProtectionEnabled = false;
            BackgroundProtectionStatus = $"Activation impossible : {exception.Message}";
            _session.AddNotification("Protection en arrière-plan indisponible", exception.Message, "Avertissement");
        }
    }

    private void DisableBackgroundProtection()
    {
        try
        {
            UserBackgroundProtectionStartup.Disable();
            IsBackgroundProtectionEnabled = false;
            BackgroundProtectionStatus = "Désactivée. L’agent en cours a reçu une demande d’arrêt; son lancement automatique est supprimé.";
            _session.AddNotification("Protection en arrière-plan désactivée", "L’agent utilisateur est arrêté et ne se lancera plus à la prochaine ouverture de session.", "Information");
        }
        catch (Exception exception)
        {
            BackgroundProtectionStatus = $"Désactivation impossible : {exception.Message}";
            _session.AddNotification("Désactivation impossible", exception.Message, "Avertissement");
        }
    }

    private void Save() => AppPreferencesStore.Save(new AppPreferences(IsDarkMode, Mode));
}
