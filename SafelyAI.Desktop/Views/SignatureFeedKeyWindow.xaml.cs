using System.Windows;

namespace SafelyAI.Desktop.Views;

public partial class SignatureFeedKeyWindow : Window
{
    public string ApiKey => ApiKeyInput.Password.Trim();

    public SignatureFeedKeyWindow() => InitializeComponent();

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(ApiKey))
        {
            MessageBox.Show(this, "Collez d’abord une clé API.", "Clé manquante", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        DialogResult = true;
    }
}
