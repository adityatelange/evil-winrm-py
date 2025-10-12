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
