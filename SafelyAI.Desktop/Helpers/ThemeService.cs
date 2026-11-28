using System.Windows;
namespace SafelyAI.Desktop.Helpers;
public static class ThemeService
{
    // Remplace le dictionnaire de couleurs (index 0 dans App.xaml) : mode sombre ou clair.
    public static void Apply(bool dark)
    {
        var uri = new Uri($"/SafelyAI.Desktop;component/Themes/{(dark ? "Dark" : "Light")}Theme.xaml", UriKind.Relative);
        Application.Current.Resources.MergedDictionaries[0] = new ResourceDictionary { Source = uri };
    }
}
