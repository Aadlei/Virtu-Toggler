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
        // Main function that toggles virtualization on or off depending on "mode".
        public static void Toggler(string mode)
        {
            Console.WriteLine("Running bcdedit.");

            // Creates a new process to set hypervisor to on/off.
            Process p = new Process();
            ProcessStartInfo startInfo = new ProcessStartInfo();

            // Parameters for the process
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.Verb = "runas";
            startInfo.FileName = @"CMD.EXE";

            // If mode is 1, disable virt. 
            if(mode == "1")
            {
                startInfo.Arguments = @"/C bcdedit /set hypervisorlaunchtype off";
                Console.WriteLine("Setting 'hypervisorlaunchtype' to off..");
            }
            // If mode is 0, enable virt.
            else if (mode == "0")
            {
                startInfo.Arguments = @"/C bcdedit /set hypervisorlaunchtype auto";
                Console.WriteLine("Setting 'hypervisorlaunchtype' to auto..");
            } 
            
            p.StartInfo = startInfo;
            p.Start();
            string output = p.StandardOutput.ReadToEnd();

            p.Close();

            // Now checks if the settings was correctly changed.
            Console.WriteLine("Checking if the setting has been changed...");
            bool setting = BcdChecker();

            // So if the settings are different, that means it has changed successfully.
            if (setting.ToString() != mode)
            {
                Console.WriteLine("Successfully changed attribute!");
                var ps = PowerShell.Create();

                // Statements for setting powershell script to turn registry key on / off
                if (mode == "1")
                {
                    ps.AddScript("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\" /v \"Enabled\" /t REG_DWORD /d 0 /f").Invoke();
                    PSErrorCheck(ps);
                    Console.WriteLine("Successfully turned off virtualization! Restart your computer.");
                } else if(mode == "0")
                {
                    ps.AddScript("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\" /v \"Enabled\" /t REG_DWORD /d 1 /f").Invoke();
                    PSErrorCheck(ps);
                    Console.WriteLine("Successfully turned on virtualization! Restart your computer.");
                }
            }
            else
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
                    Console.WriteLine("Found key, checking if it is correct....");
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

        // Function for checking if the powershell script returned any errors.
        public static void PSErrorCheck(PowerShell ps)
        {
            if (ps.HadErrors)
            {
                foreach (var error in ps.Streams.Error)
                {
                    Console.WriteLine(error.ToString());
                    break;
                }
            }
        }
    }
}

