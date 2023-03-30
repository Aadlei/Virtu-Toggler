using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace Virtu_Toggler
{
    internal class VirtuChanger
    {
        public static void Enabler()
        {
            Console.WriteLine("Running bcdedit...");

            // Creates a new process to set hypervisor to auto.
            Process p = new Process();
            ProcessStartInfo startInfo = new ProcessStartInfo();

            // Parameters for the process
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.Verb = "runas";
            startInfo.FileName = @"CMD.EXE";
            startInfo.Arguments = @"/C bcdedit /set hypervisorlaunchtype auto";

            Console.WriteLine("Setting 'hypervisorlaunchtype' to auto...");
            p.StartInfo = startInfo;
            p.Start();
            string output = p.StandardOutput.ReadToEnd();

            p.Close();

            // Now checks if the settings was correctly changed.
            Console.WriteLine("Checking if the setting has been changed...");
            bool setting = BcdChecker();

            if(setting)
            {
                Console.WriteLine("Successfully changed attribute!");
                var ps = PowerShell.Create();
                ps.AddScript("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\" /v \"Enabled\" /t REG_DWORD /d 1 /f").Invoke();
            } else
            {
                Console.WriteLine("Failed to change attribute, did you run with administrator privileges?");
            }

        }

        // Function that checks if hypervisorlaunchtype is on or off, returns either 0 or 1.
        public static bool BcdChecker()
        {
            // Creates a new process to check if the setting is changed.
            Process c = new Process();
            ProcessStartInfo startInfo = new ProcessStartInfo();
            // Parameters for the process
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.Verb = "runas";
            startInfo.FileName = @"CMD.EXE";
            startInfo.Arguments = @"/C bcdedit";
            c.StartInfo = startInfo;
            c.Start();

            string check = c.StandardOutput.ReadToEnd();

            // Reads the BCDEDIT list of boot settings, to see whether hypervisorlaunchtype is on 'auto'.
            var lines = check.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries).Where(l => l.Length > 24);
            foreach (var line in lines)
            {
                var key = line.Substring(0, 24).Replace(" ", string.Empty);
                var value = line.Substring(24).Replace(" ", string.Empty);
                if (key == "hypervisorlaunchtype")
                {
                    Console.WriteLine("Found key, checking if it is correct...");
                    if (value == "Auto")
                    {
                        c.Close();
                        return true;
                    }
                    else
                    {
                        c.Close();
                        return false;
                    }
                }
            }
            c.Close();
            return false;
        }
    }
}

