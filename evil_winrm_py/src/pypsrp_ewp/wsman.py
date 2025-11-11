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

from pypsrp._utils import get_hostname
from pypsrp.encryption import WinRMEncryption
from pypsrp.exceptions import WinRMTransportError
from pypsrp.wsman import (
    AUTH_KWARGS,
    NAMESPACES,
    SUPPORTED_AUTHS,
    WSMan,
    _TransportHTTP,
    requests,
)
from urllib3.util.retry import Retry

try:
    from requests_credssp import HttpCredSSPAuth
except ImportError as err:  # pragma: no cover
    _requests_credssp_import_error = (
        "Cannot use CredSSP auth as requests-credssp is not installed: %s" % err
    )

    class HttpCredSSPAuth(object):  # type: ignore[no-redef] # https://github.com/python/mypy/issues/1153
        def __init__(self, *args, **kwargs):
            raise ImportError(_requests_credssp_import_error)


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
        user_agent: str = "Microsoft WinRM Client",
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

            # custom user-agent header
            user_agent: The user agent to use for the HTTP requests, this
                defaults to 'Microsoft WinRM Client'
        """
        log.debug(
            "Initialising WSMan class with maximum envelope size of %d "
            "and operation timeout of %s" % (max_envelope_size, operation_timeout)
        )
        self.session_id = str(uuid.uuid4())
        self.locale = locale
        self.data_locale = self.locale if data_locale is None else data_locale
        self.transport = _TransportHTTPEWP(
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
            user_agent,
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


class _TransportHTTPEWP(_TransportHTTP):
    """Override _TransportHTTP"""

    def __init__(
        self,
        server: str,
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
        read_timeout: int = 30,
        reconnection_retries: int = 0,
        reconnection_backoff: float = 2.0,
        user_agent: str = "Microsoft WinRM Client",
        **kwargs: typing.Any,
    ) -> None:
        self.server = server
        self.port = port if port is not None else (5986 if ssl else 5985)
        self.username = username
        self.password = password
        self.ssl = ssl
        self.path = path

        if auth not in SUPPORTED_AUTHS:
            raise ValueError(
                "The specified auth '%s' is not supported, "
                "please select one of '%s'" % (auth, ", ".join(SUPPORTED_AUTHS))
            )
        self.auth = auth
        self.cert_validation = cert_validation
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self.reconnection_retries = reconnection_retries
        self.reconnection_backoff = reconnection_backoff
        self.user_agent = user_agent

        # determine the message encryption logic
        if encryption not in ["auto", "always", "never"]:
            raise ValueError(
                "The encryption value '%s' must be auto, always, or never" % encryption
            )
        enc_providers = ["credssp", "kerberos", "negotiate", "ntlm"]
        if ssl:
            # msg's are automatically encrypted with TLS, we only want message
            # encryption if always was specified
            self.wrap_required = encryption == "always"
            if self.wrap_required and self.auth not in enc_providers:
                raise ValueError(
                    "Cannot use message encryption with auth '%s', either set "
                    "encryption='auto' or use one of the following auth "
                    "providers: %s" % (self.auth, ", ".join(enc_providers))
                )
        else:
            # msg's should always be encrypted when not using SSL, unless the
            # user specifies to never encrypt
            self.wrap_required = not encryption == "never"
            if self.wrap_required and self.auth not in enc_providers:
                raise ValueError(
                    "Cannot use message encryption with auth '%s', either set "
                    "encryption='never', use ssl=True or use one of the "
                    "following auth providers: %s"
                    % (self.auth, ", ".join(enc_providers))
                )
        self.encryption: typing.Optional[WinRMEncryption] = None

        self.proxy = proxy
        self.no_proxy = no_proxy

        self.certificate_key_pem: typing.Optional[str] = None
        self.certificate_pem: typing.Optional[str] = None
        for kwarg_list in AUTH_KWARGS.values():
            for kwarg in kwarg_list:
                setattr(self, kwarg, kwargs.get(kwarg, None))

        self.endpoint = self._create_endpoint(
            self.ssl, self.server, self.port, self.path
        )
        log.debug(
            "Initialising HTTP transport for endpoint: %s, user: %s, "
            "auth: %s" % (self.endpoint, self.username, self.auth)
        )
        self.session: typing.Optional[requests.Session] = None

        # used when building tests, keep commented out
        # self._test_messages = []

    def send(self, message: bytes) -> bytes:
        hostname = get_hostname(self.endpoint)
        if self.session is None:
            self.session = self._build_session()

            # need to send an initial blank message to setup the security
            # context required for encryption
            if self.wrap_required:
                request = requests.Request("POST", self.endpoint, data=None)
                prep_request = self.session.prepare_request(request)
                self._send_request(prep_request)

                protocol = WinRMEncryption.SPNEGO
                if isinstance(self.session.auth, HttpCredSSPAuth):
                    protocol = WinRMEncryption.CREDSSP
                elif self.session.auth.contexts[hostname].response_auth_header == "kerberos":  # type: ignore[union-attr] # This should not happen
                    # When Kerberos (not Negotiate) was used, we need to send a special protocol value and not SPNEGO.
                    protocol = WinRMEncryption.KERBEROS

                self.encryption = WinRMEncryption(self.session.auth.contexts[hostname], protocol)  # type: ignore[union-attr] # This should not happen

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Sending message: %s" % message.decode("utf-8"))
        # for testing, keep commented out
        # self._test_messages.append({"request": message.decode('utf-8'),
        #                             "response": None})

        headers = self.session.headers
        if self.wrap_required:
            content_type, payload = self.encryption.wrap_message(message)  # type: ignore[union-attr] # This should not happen
            protocol = (
                self.encryption.protocol if self.encryption else WinRMEncryption.SPNEGO
            )
            type_header = '%s;protocol="%s";boundary="Encrypted Boundary"' % (
                content_type,
                protocol,
            )
            headers.update(
                {
                    "Content-Type": type_header,
                    "Content-Length": str(len(payload)),
                }
            )
        else:
            payload = message
            headers["Content-Type"] = "application/soap+xml;charset=UTF-8"

        request = requests.Request("POST", self.endpoint, data=payload, headers=headers)
        prep_request = self.session.prepare_request(request)
        try:
            return self._send_request(prep_request)
        except WinRMTransportError as err:
            if err.code == 400:
                log.debug("Session invalid, resetting session")
                self.session = None  # reset the session so we can retry
                return self.send(message)
            else:
                raise

    def _build_session(self) -> requests.Session:
        log.debug("Building requests session with auth %s" % self.auth)
        self._suppress_library_warnings()

        session = requests.Session()
        session.headers["User-Agent"] = self.user_agent

        # requests defaults to 'Accept-Encoding: gzip, default' which normally doesn't matter on vanila WinRM but for
        # Exchange endpoints hosted on IIS they actually compress it with 1 of the 2 algorithms. By explicitly setting
        # identity we are telling the server not to transform (compress) the data using the HTTP methods which we don't
        # support. https://tools.ietf.org/html/rfc7231#section-5.3.4
        session.headers["Accept-Encoding"] = "identity"

        # get the env requests settings
        session.trust_env = True
        settings = session.merge_environment_settings(
            url=self.endpoint, proxies={}, stream=None, verify=None, cert=None
        )

        # set the proxy config
        session.proxies = settings["proxies"]
        proxy_key = "https" if self.ssl else "http"
        if self.proxy is not None:
            session.proxies = {
                proxy_key: self.proxy,
            }
        elif self.no_proxy:
            session.proxies = {
                proxy_key: False,  # type: ignore[dict-item] # A boolean is expected here
            }

        # Retry on connection errors, with a backoff factor
        retry_kwargs = {
            "total": self.reconnection_retries,
            "connect": self.reconnection_retries,
            "status": self.reconnection_retries,
            "read": 0,
            "backoff_factor": self.reconnection_backoff,
            "status_forcelist": (425, 429, 503),
        }
        try:
            retries = Retry(**retry_kwargs)
        except TypeError:
            # Status was added in urllib3 >= 1.21 (Requests >= 2.14.0), remove
            # the status retry counter and try again. The user should upgrade
            # to a newer version
            log.warning(
                "Using an older requests version that without support for status retries, ignoring.",
                exc_info=True,
            )
            del retry_kwargs["status"]
            retries = Retry(**retry_kwargs)

        session.mount("http://", requests.adapters.HTTPAdapter(max_retries=retries))
        session.mount("https://", requests.adapters.HTTPAdapter(max_retries=retries))

        # set cert validation config
        session.verify = self.cert_validation

        # if cert_validation is a bool (no path specified), not False and there
        # are env settings for verification, set those env settings
        if (
            isinstance(self.cert_validation, bool)
            and self.cert_validation
            and settings["verify"] is not None
        ):
            session.verify = settings["verify"]

        build_auth = getattr(self, "_build_auth_%s" % self.auth)
        build_auth(session)
        return session
