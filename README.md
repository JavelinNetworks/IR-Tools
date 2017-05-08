### Collection of Microsoft PowerShell modules that can be used to aid with forensics of domain based attacks on an infected host.

## CodeExecution

**Execute code on a target machine using Import-Module.**


#### `Get-ShellContent`

Extracts live input and output of any commandline process, running or dumped, encrypted or plaintext from a remote computer.


#### `Get-SessionsAnomaly`

Finds existence of Pass-The-Ticket and Pass-The-Hash attacks on a remote machine.

## License

The IT-Tools project and all individual scripts are under the [BSD 3-Clause license] unless explicitly noted otherwise.

## Usage

Refer to the comment-based help in each individual script for detailed usage information.

To install this module, drop the entire powershell scripts into one of your module directories. The default PowerShell module paths are listed in the $Env:PSModulePath environment variable.

To use any of the modules, type `Import-Module PathTo\scriptName.ps1`