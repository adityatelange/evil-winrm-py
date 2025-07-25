# -*- coding: utf-8 -*-
# This file is part of evil-winrm-py.

# Following code is a modified version of pypsrp's wsman.py
# It has been adapted to work with evil-winrm-py.
# Original source: https://github.com/jborean93/pypsrp/blob/master/src/pypsrp/wsman.py

# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import typing
import uuid
import xml.etree.ElementTree as ET

from pypsrp.wsman import NAMESPACES, WSMan, _TransportHTTP

log = logging.getLogger(__name__)


class WSManEWP(WSMan):
    """Override WSMan class to customize some stuff"""

    def __init__(
        self,
        server: str,
        max_envelope_size: int = 153600,
        operation_timeout: int = 20,
        port: typing.Optional[int] = None,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        ssl: bool = True,
        path: str = "wsman",
        auth: str = "negotiate",
        cert_validation: bool = True,
        connection_timeout: int = 30,
        encryption: str = "auto",
        proxy: typing.Optional[str] = None,
        no_proxy: bool = False,
        locale: str = "en-US",
        data_locale: typing.Optional[str] = None,
        read_timeout: int = 30,
        reconnection_retries: int = 0,
        reconnection_backoff: float = 2.0,
        **kwargs: typing.Any,
    ) -> None:
        """
        Class that handles WSMan transport over HTTP. This exposes a method per
        action that takes in a resource and the header metadata required by
        that resource.

        This is required by the pypsrp.shell.WinRS and
        pypsrp.powershell.RunspacePool in order to connect to the remote host.
        It uses HTTP(S) to send data to the remote host.

        https://msdn.microsoft.com/en-us/library/cc251598.aspx

        :param server: The hostname or IP address of the host to connect to
        :param max_envelope_size: The maximum size of the envelope that can be
            sent to the server. Use update_max_envelope_size() to query the
            server for the true value
        :param max_envelope_size: The maximum size of a WSMan envelope that
            can be sent to the server
        :param operation_timeout: Indicates that the client expects a response
            or a fault within the specified time.
        :param port: The port to connect to, default is 5986 if ssl=True, else
            5985
        :param username: The username to connect with
        :param password: The password for the above username
        :param ssl: Whether to connect over http or https
        :param path: The WinRM path to connect to
        :param auth: The auth protocol to use; basic, certificate, negotiate,
            credssp. Can also specify ntlm or kerberos to limit the negotiate
            protocol
        :param cert_validation: Whether to validate the server's SSL cert
        :param connection_timeout: The timeout for connecting to the HTTP
            endpoint
        :param read_timeout: The timeout for receiving from the HTTP endpoint
        :param encryption: Controls the encryption setting, default is auto
            but can be set to always or never
        :param proxy: The proxy URL used to connect to the remote host
        :param no_proxy: Whether to ignore any environment proxy vars and
            connect directly to the host endpoint
        :param locale: The wsmv:Locale value to set on each WSMan request. This
            specifies the language in which the client wants response text to
            be translated. The value should be in the format described by
            RFC 3066, with the default being 'en-US'
        :param data_locale: The wsmv:DataLocale value to set on each WSMan
            request. This specifies the format in which numerical data is
            presented in the response text. The value should be in the format
            described by RFC 3066, with the default being the value of locale.
        :param int reconnection_retries: Number of retries on connection
            problems
        :param float reconnection_backoff: Number of seconds to backoff in
            between reconnection attempts (first sleeps X, then sleeps 2*X,
            4*X, 8*X, ...)
        :param kwargs: Dynamic kwargs based on the auth protocol set
            # auth='certificate'
            certificate_key_pem: The path to the cert key pem file
            certificate_pem: The path to the cert pem file

            # auth='credssp'
            credssp_auth_mechanism: The sub auth mechanism to use in CredSSP,
                default is 'auto' but can be 'ntlm' or 'kerberos'
            credssp_disable_tlsv1_2: Use TLSv1.0 instead of 1.2
            credssp_minimum_version: The minimum CredSSP server version to
                allow

            # auth in ['negotiate', 'ntlm', 'kerberos']
            negotiate_send_cbt: Whether to send the CBT token on HTTPS
                connections, default is True

            # the below are only relevant when kerberos (or nego used kerb)
            negotiate_delegate: Whether to delegate the Kerb token to extra
                servers (credential delegation), default is False
            negotiate_hostname_override: Override the hostname used when
                building the server SPN
            negotiate_service: Override the service used when building the
                server SPN, default='WSMAN'
        """
        log.debug(
            "Initialising WSMan class with maximum envelope size of %d "
            "and operation timeout of %s" % (max_envelope_size, operation_timeout)
        )
        self.session_id = str(uuid.uuid4())
        self.locale = locale
        self.data_locale = self.locale if data_locale is None else data_locale
        self.transport = _TransportHTTP(
            server,
            port,
            username,
            password,
            ssl,
            path,
            auth,
            cert_validation,
            connection_timeout,
            encryption,
            proxy,
            no_proxy,
            read_timeout,
            reconnection_retries,
            reconnection_backoff,
            **kwargs,
        )
        self.max_envelope_size = max_envelope_size
        self.operation_timeout = operation_timeout

        # register well known namespace prefixes so ElementTree doesn't
        # randomly generate them, saving packet space
        for key, value in NAMESPACES.items():
            ET.register_namespace(key, value)

        # This is the approx max size of a Base64 string that can be sent in a
        # SOAP message payload (PSRP fragment or send input data) to the
        # server. This value is dependent on the server's MaxEnvelopSizekb
        # value set on the WinRM service and the default is different depending
        # on the Windows version. Server 2008 (R2) detaults to 150KiB while
        # newer hosts are 500 KiB and this can be configured manually. Because
        # we don't know the OS version before we connect, we set the default to
        # 150KiB to ensure we are compatible with older hosts. This can be
        # manually adjusted with the max_envelope_size param which is the
        # MaxEnvelopeSizekb value * 1024. Otherwise the
        # update_max_envelope_size() function can be called and it will gather
        # this information for you.
        self.max_payload_size = self._calc_envelope_size(max_envelope_size)
