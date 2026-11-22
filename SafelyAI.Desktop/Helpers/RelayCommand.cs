using System.Windows.Input;
namespace SafelyAI.Desktop.Helpers;
public class RelayCommand : ICommand
{
    private readonly Action<object?> _run;
    public RelayCommand(Action<object?> run) => _run = run;
    public event EventHandler? CanExecuteChanged { add { } remove { } }
    public bool CanExecute(object? p) => true;
    public void Execute(object? p) => _run(p);
}
