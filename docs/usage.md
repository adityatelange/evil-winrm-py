# Usage Guide

## Authentication Methods

### NTLM Authentication

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD>
```

### Kerberos Authentication

Kerberos authentication supports both password-based and ticket-based authentication.

#### Generate hosts file entry

Use `netexec` to generate a hosts file entry for the target domain.

```bash
netexec smb sevenkingdoms.local --generate-hosts-file hosts.txt
```

Copy the content of `hosts.txt` to your `/etc/hosts` file.

> [!IMPORTANT]
> If you are adding an entry manually, ensure you follow the correct format for subdomains and fully qualified domain names (FQDNs). Kerberos uses SPNEGO, which relies on a specific algorithm to resolve hostnames. For more details, see [SPNEGO algorithm to resolve host names](https://www.ibm.com/docs/en/samfm/8.0.1?topic=spnego-algorithm-resolve-host-names).
>
> The format is as follows:
>
> ```
> <IP> fully_qualified_hostname short_name
> <IP> kingslanding.sevenkingdoms.local sevenkingdoms.local kingslanding
> ```

#### Generate krb5.conf file

Use `netexec` to generate a `krb5.conf` file for the target domain.

```bash
netexec smb sevenkingdoms.local --generate-krb5-file krb5.conf
```

Sample `krb5.conf` file can be found [here](https://github.com/adityatelange/evil-winrm-py/blob/main/docs/sample/krb5.conf).

#### Password-based Kerberos Authentication

This will request a Kerberos ticket and store it in memory for the session.

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --kerberos
```

#### Ticket-based Kerberos Authentication

If you already have a Kerberos ticket (e.g., from `kinit`), you can use it directly without providing a password.

Specify the `KRB5CCNAME` and `KRB5_CONFIG` environment variables to point to your Kerberos ticket cache and configuration file, respectively.

```bash
export KRB5CCNAME=/path/to/your/krb5cc_file
export KRB5_CONFIG=/path/to/your/krb5.conf
# By default, the ticket cache is stored in `/tmp/krb5cc_<UID>` on Unix-like systems.
# By default, the Kerberos configuration file is located at `/etc/krb5.conf` on Unix-like systems.
```

Then, you can run the command without providing a username or password:

```bash
evil-winrm-py -i <IP> --kerberos
```

> [!IMPORTANT]
> Make sure when you use a cache ticket, the `SPN` i.e `Service principal` is set correctly. The `SPN` is usually in the format of `http/<hostname>` or `cifs/<hostname>`. The hostname should _always_ be in lowercase.

The tool also supports direct authentication (without setting `KRB5CCNAME`) when passing username and password, which will request a ticket for the user and use it for authentication.

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --kerberos
```

Optionally, you can specify the Kerberos realm and SPN prefix/hostname
If you have a Kerberos ticket, you can use it with the following options:

```bash
evil-winrm-py -i <IP> -u <USERNAME> --kerberos --no-pass --spn-prefix <SPN_PREFIX> --spn-hostname <SPN_HOSTNAME>
```

### Pass-the-Hash Authentication

If you have the NTLM hash of the user's password, you can use it for authentication without needing the plaintext password.

```bash
evil-winrm-py -i <IP> -u <USERNAME> -H <NTLM_HASH>
```

### Certificate Authentication

If you want to use certificate-based authentication, you can specify the private key and certificate files in PEM format.

```bash
evil-winrm-py -i <IP> -u <USERNAME> --priv-key-pem <PRIVATE_KEY_PEM_PATH> --cert-pem <CERT_PEM_PATH>
```

## Connection Options

### Using SSL

This will use port 5986 for SSL connections by default. If you want to use a different port, you can specify it with [custom port option](#using-custom-port).

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --ssl
```

### Using Custom URI

If the target server has a custom WinRM URI, you can specify it using the `--uri` option. This is useful if the WinRM service is hosted on a different path than the default.

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --uri <CUSTOM_URI>
```

### Using Custom Port

If the target server is using a non-standard port for WinRM, you can specify the port using the `--port` option. The default port for WinRM over HTTP is 5985, and for HTTPS it is 5986.

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --port <PORT>
```

### Connecting to a JEA Endpoint (Just Enough Administration)

If the target server exposes a [JEA](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview) session configuration instead of (or in addition to) the default `Microsoft.PowerShell` endpoint, you can connect to it by name using the `--configuration-name` (or `-c`) option.

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --configuration-name <JEA_ENDPOINT_NAME>
```

JEA endpoints commonly run in [`NoLanguage` mode](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes), which only allows direct cmdlet invocations and rejects any form of script text: this includes `Invoke-Expression`, scriptblocks (`{ }`), variables, and operators. When `--configuration-name` is set to anything other than `Microsoft.PowerShell`, evil-winrm-py automatically switches the interactive shell to dispatch typed commands as a parsed cmdlet pipeline (`Cmdlet -Param value | Cmdlet2 -Param2 value2`) instead of wrapping them in `Invoke-Expression`, so plain cmdlet usage keeps working against `NoLanguage` endpoints.

Run `Get-Command` to see which cmdlets the endpoint actually exposes:

```bash
evil-winrm-py JEA PS> Get-NetIPAddress | Measure-Object
```

> [!IMPORTANT]
>
> - Only simple `Cmdlet -Param value` style pipelines are supported in this mode; scripting constructs (scriptblocks, variables, conditionals, etc.) cannot be expressed this way and will fail on `NoLanguage` endpoints. Note that some commands and parameters are further restricted by JEA proxy functions; for example, the built-in `Select-Object` proxy blocks `-Property`/`-ExpandProperty`/`-First` unless the endpoint's role capability re-exposes the full cmdlet.
> - Only cmdlets, functions, and parameters allowed by the endpoint's role capabilities are available; run `Get-Command` to list them.
> - Output is rendered client-side, since JEA endpoints rarely expose `Out-String`/`Format-*`. Objects with a meaningful string form (e.g. `Get-NetIPAddress`) print as-is; objects that would otherwise show only their .NET type name (e.g. the result of `Measure-Object`) are rendered as a `Name : Value` property list. This can look different from the default shell's table/list formatting.
> - The menu commands that rely on scripting (`services`, `upload`, `download`, `loadps`, `runps`, `loaddll`, `runexe`) are disabled in JEA mode, since they send script text (scriptblocks, variables, multi-line and base64 helpers) that a `NoLanguage` endpoint rejects. Only `menu`, `clear`/`cls`, and `exit` remain, alongside direct cmdlet pipelines; the disabled ones are still listed in `menu` but marked `(Disabled)`.
> - Command-name tab-completion works (it uses `Get-Command`, one of the default `RestrictedRemoteServer` commands, so it lists the cmdlets the endpoint actually exposes). Remote **path** tab-completion is unavailable, since it depends on `$pwd.Path` and `Get-ChildItem | select -ExpandProperty`, which `NoLanguage` mode blocks.
> - The prompt shows a static `JEA PS>` instead of the current working directory. A JEA session has no reliable way to read the working directory: `$pwd.Path` is a property expression (blocked in `NoLanguage` mode) and pwd cmdlets such as `Get-Location` are not part of the default `RestrictedRemoteServer` command set.

## Logging and Debugging

Logging will create a log file in the current directory named `evil-winrm-py.log`.

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --log
```

### Debugging

If Debug mode is enabled, it will also log debug information, including debug messages and stack traces from libraries used by the tool.

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --debug
```

Debugging for kerberos authentication can be enabled by setting the `KRB5_TRACE` environment variable to a file path where you want to log the Kerberos debug information.

```bash
export KRB5_TRACE=/path/to/kerberos_debug.log
```

or you can set it to `stdout` to print the debug information to the console.

```bash
export KRB5_TRACE=/dev/stdout evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --kerberos
```

## Interactive Shell

Once you have successfully authenticated, you will be dropped into an interactive shell where you can execute commands on the remote Windows machine.

```bash
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.3.0

[*] Connecting to '192.168.1.100' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> █
```

You can execute commands just like you would in a normal Windows command prompt. To exit the interactive shell, type `exit` or press `Ctrl+D`.
If you want to cancel a command that is currently running, you can use `Ctrl+C`.

### Menu Commands

Inside the interactive shell, you can use the following commands:

```bash
Menu:
[+] services                                                - Show the running services (except system services)
[+] upload <local_path> <remote_path>                       - Upload a file
[+] download <remote_path> <local_path>                     - Download a file
[+] loadps <local_path>.ps1                                 - Load PowerShell functions from a local script
[+] runps <local_path>.ps1                                  - Run a local PowerShell script on the remote host
[+] loaddll <local_path>.dll                                - Load a local DLL (in-memory) as a module on the remote host
[+] runexe <local_path>.exe [args]                          - Upload and execute (in-memory) a local EXE on the remote host
[+] menu                                                    - Show this menu
[+] clear, cls                                              - Clear the screen
[+] exit                                                    - Exit the shell
Note: Use absolute paths for upload/download for reliability.
```

### Show Running Services

You can list the running services (except system services) on the remote host using the `services` command. This will display a list of services that are currently running, which can be useful for post-exploitation tasks.

```bash
evil-winrm-py PS C:\Users\Administrator\Documents> services
```

### File Transfer

You can upload and download files using the following commands:

```bash
evil-winrm-py PS C:\Users\Administrator\Documents> upload <local_path> <remote_path>
```

```bash
evil-winrm-py PS C:\Users\Administrator\Documents> download <remote_path> <local_path>
```

### Loading PowerShell Scripts (Dot Sourcing)

You can load PowerShell functions from a local script file into the interactive shell using the `loadps` command. This allows you to use custom PowerShell functions defined in your script. This method is known as "dot sourcing".

This can be helpful when using tools like `PowerView` or `PowerUp` that provide a set of PowerShell functions for post-exploitation tasks.

```bash
evil-winrm-py PS C:\Users\Administrator\Documents> loadps <local_path>.ps1
```

These functions will be added to Command Suggestions so you can use them directly using the `Tab` key for auto-completion.

The help command can be used to get more information about the available commands in the interactive shell.

```bash
evil-winrm-py PS C:\Users\Administrator\Documents> Get-Help <LoadedFunctionName> # or help <LoadedFunctionName>
```

### Running Local PowerShell Scripts

You can run a local PowerShell script on the remote host using the `runps` command. This will read the contents of the specified PowerShell script file and execute it on the remote machine.

```bash
evil-winrm-py PS C:\Users\Administrator\Documents> runps <local_path>.ps1
```

### Loading Local DLLs as PowerShell Modules

You can load a local DLL file as a module on the remote host using the `loaddll` command. This will upload the specified DLL file in-memory and load it as a module. Note that this uses .NET's Reflection to load the DLL, so it may not work with all DLL files.

This can be helpful when using tools like [ADModule](https://github.com/samratashok/ADModule).

These Commands/Commandlets will be added to Command Suggestions so you can use them directly using the `Tab` key for auto-completion.

```bash
evil-winrm-py PS C:\Users\Administrator\Documents> loaddll <local_path>.dll
```

### Executing Local EXEs on the Remote Host

You can upload and execute a local EXE file on the remote host using the `runexe` command. This will upload the specified EXE file in-memory and execute it with optional arguments. Note that this uses .NET's Reflection to load and execute the EXE, so it may not work with all EXE files.

This can be helpful when using tools present in [SharpCollection](https://github.com/Flangvik/SharpCollection).

```bash
evil-winrm-py PS C:\Users\Administrator\Documents> runexe <local_path>.exe [args]
```

## MCP Server Mode

`evil-winrm-py` can optionally run as an MCP (Model Context Protocol) server, exposing WinRM login/execute/logout as tools for MCP-compatible clients over streamable HTTP. This requires the `mcp` extra (see [Installation Guide](install.md)) and Python 3.10+.

```bash
evil-winrm-py --mcp
```

By default, the server listens on `127.0.0.1:8000`. You can customize the address with `--mcp-host` and `--mcp-port`:

```bash
evil-winrm-py --mcp --mcp-host 0.0.0.0 --mcp-port 8000
```

Add the resulting URL (e.g. `http://127.0.0.1:8000/mcp`) to your MCP client to connect.

Available tools:

```bash
winrm_login    - Authenticate to a remote host over WinRM, returns a session_id
winrm_execute  - Run a command (via Invoke-Expression) on an authenticated session
winrm_logout   - Close a WinRM session
list_sessions  - List all active WinRM sessions
```

`winrm_login` accepts the same authentication options as the CLI (NTLM, Pass-the-Hash, Certificate, Kerberos-related SPN options, SSL, custom URI/user-agent, etc.). `session_id` is optional for `winrm_execute`/`winrm_logout` while only one session is active; once multiple sessions exist, pass it explicitly (use `list_sessions` to see active session IDs).

> [!WARNING]
> Since MCP server mode allows remote command execution on Windows hosts via MCP tools, only expose it on trusted networks and to trusted MCP clients.

## Additional Options

### Using No Colors

If you want to disable colored output in the terminal, you can use the `--no-colors` option. This is useful for logging or when your terminal does not support colors.

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --no-colors
```

### Using No Password Prompt

```bash
evil-winrm-py -i <IP> -u <USERNAME> --no-pass
```
