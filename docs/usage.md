# Usage Guide

## Authentication Methods

### NTLM Authentication

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD>
```

### Kerberos Authentication

Kerberos authentication supports both password-based and ticket-based authentication.

#### Password-based Kerberos Authentication

This will request a Kerberos ticket and store it in memory for the session.

```bash
evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --kerberos
```

#### Ticket-based Kerberos Authentication

If you already have a Kerberos ticket (e.g., from `kinit`), you can use it directly without providing a password.

Specify the `KRB5CCNAME` and `KRB5_CONFIG` environment variables to point to your Kerberos ticket cache and configuration file, respectively. Sample `krb5.conf` file can be found [here](sample/krb5.conf).

```bash
export KRB5CCNAME=/path/to/your/krb5cc_file
export KRB5_CONFIG=/path/to/your/krb5.conf
# By default, the ticket cache is stored in `/tmp/krb5cc_<UID>` on Unix-like systems.
# By default, the Kerberos configuration file is located at `/etc/krb5.conf` on Unix-like systems.
```

Then, you can run the command without a password:

```bash
evil-winrm-py -i <IP> -u <USERNAME> --kerberos --no-pass
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

This will use port 5986 for SSL connections by default. If you want to use a different port, you can specify it with [custom ort option](#using-custom-port).

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
export KRB5_TRACE=stdout evil-winrm-py -i <IP> -u <USERNAME> -p <PASSWORD> --kerberos
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
