using System.Windows;
using SafelyAI.Desktop.ViewModels;
namespace SafelyAI.Desktop.Views;
public partial class MainWindow : Window
{
    public MainWindow() { InitializeComponent(); DataContext = new MainViewModel(); Closed += (_, _) => { if (DataContext is MainViewModel viewModel) { viewModel.Dispose(); viewModel.Session.Dispose(); } }; }

    private void NotificationsButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is not MainViewModel viewModel) return;
        new NotificationsWindow(viewModel) { Owner = this }.ShowDialog();
    }
}
