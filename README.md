# Virtu-Toggler
## What is this?
Virtu-Toggler is a program that toggles on / off **'hypervisorlaunchtype'** by using *bcdedit* and sets **'HypervisorEnforcedCodeIntegrity'** to enabled or disabled via Registry. 
The project aims to assist solving a recurring problem with Anti-Cheat systems such as *"FACEIT AC"* and *"VALORANT Anti-Cheat"* by turning off virtualization. 
The Anti-Cheats tend to prohibit virtualization to counter hackers that use VM as a way to use their cheats. Not everyone who uses VM cheats obviously, so they (me included) tend to get annoyed by being blocked out because of that.
It usually is a hassle turning on and off virtualization all the time, especially for people who love playing competitive games and also do a ton of virtualization work (Docker, VMWare, WSL etc). 
The program is written in C# using wpf with the .NET version 7.

## Things to keep in mind
**Be wary that the program needs to be run with administrator privileges, as you are setting a registry key and changing BCD settings (boot configuration data**. 
The computer will **_require_** a restart after the program has been run, so the changes get applied.

## How do I use this program?
You can either build it in Visual Studio, or you can open it directly by extracting 'bin/Release' and then run the executable. 
## What is in the project?
The project has a main Program.cs file along with a class file called Toggler.cs (where I keep most of my methods). 

## How does it work?
### Program.cs
The *Program.cs* is where the main program is ran. It first checks if a registry key called "Enabled" in the directory *HypervisorEnforcedCodeIntegrity* is either 1 or 0. 
If it is 1, the program will ask if you want to turn it off and vice versa. Depending on the answer, it will run the function **Toggler(string mode)** from *Toggler.cs*.

### Toggler.cs
The *Toggler.cs* has the following functions:
- Toggler(string mode): A function that takes in either 1 or 0, depending on if virtualization is on or off in the system. Then runs a bcdedit script aswell as a powershell script to turn on / off virtualization.
- BcdChecker(): Creates a process that checks a specific bcdedit argument (hypervisorlaunchtype) is on 'auto' or 'off'.
- PSErrorCheck(PowerShell ps): A simple function that takes in a powershell process after the Invoke() call has been run, to see if the script failed to run or not.


## Can I use your project for x?
Of course, you are free to take, expand and use this project for whatever your purpose may be. A little credit would be nice, but I don't really care too much about that.

## Questions
If you have a question, don't expect me to be able to answer with a 100% certainity. You are still very welcome to do so either way.
