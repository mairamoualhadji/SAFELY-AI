using SafelyAI.Desktop.Helpers;
using SafelyAI.Desktop.Models;
namespace SafelyAI.Desktop.ViewModels;
public class SettingsViewModel : ObservableObject
{
    private bool _dark = true;
    private ProtectionMode _mode = ProtectionMode.Balanced;
    public bool IsDarkMode { get => _dark; set { if (Set(ref _dark, value)) ThemeService.Apply(value); } }
    public ProtectionMode Mode { get => _mode; set => Set(ref _mode, value); }
    public Array Modes { get; } = Enum.GetValues(typeof(ProtectionMode));
}
