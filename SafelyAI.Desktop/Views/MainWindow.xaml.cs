using System.Windows;
using SafelyAI.Desktop.ViewModels;
namespace SafelyAI.Desktop.Views;
public partial class MainWindow : Window
{
    public MainWindow() { InitializeComponent(); DataContext = new MainViewModel(); }
}
