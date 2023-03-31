using System.Management.Automation;
using Virtu_Toggler;

using var ps = PowerShell.Create();

try
{
    // The script path that checks the registry if the hypervisor is on.
    ps.AddScript("(Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\")");
    var result = ps.Invoke();

    // Runs function that checks if the script gave off errors
    VirtuChanger.PSErrorCheck(ps);

    string decision = "";
    string mode = "";
    // Iterates through results, to find if "Enabled" is 1 or 0.
    foreach (PSObject value in result)
    {
        object enabled = value.Properties["Enabled"].Value;
        if (enabled.ToString() == "1")
        {
            mode = enabled.ToString();
            // If virtualization is enabled.
            Console.WriteLine("Virtualization is turned on, do you wish to turn it off? (y/n)");
            decision = Console.ReadLine();
            while (decision != "n" && decision != "N" && decision != "y" && decision != "Y")
            {
                Console.WriteLine("Wrong input, try again (y means yes, n means no)");
                decision = Console.ReadLine();
            }
            
            // No changes made.
            if(decision == "n" || decision == "N")
            {
                Console.WriteLine("Stopping program...");
                break;
            } 
            // Disable virtualization
            else
            {
                VirtuChanger.Toggler(mode);
            }
        }
        else if (enabled.ToString() == "0")
        {
            mode = enabled.ToString();
            // If virtualization is disabled.
            Console.WriteLine("Virtualization is turned off, do you wish to turn it on? (y/n)");
            decision = Console.ReadLine();
            while (decision != "n" && decision != "N" && decision != "y" && decision != "Y")
            {
                Console.WriteLine("Wrong input, try again (y means yes, n means no)");
                decision = Console.ReadLine();
            }

            // No changes made.
            if (decision == "n" || decision == "N")
            {
                Console.WriteLine("Stopping program...");
                break;
            }
            // Enable virtualization.
            else
            {
                VirtuChanger.Toggler(mode);
            }
        }
    }
}
catch (Exception error)
{
    Console.WriteLine(error.Message);
}
