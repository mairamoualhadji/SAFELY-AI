using System.Windows;
using SafelyAI.Desktop.ViewModels;

namespace SafelyAI.Desktop.Views;

public partial class NotificationsWindow : Window
{
    public NotificationsWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
