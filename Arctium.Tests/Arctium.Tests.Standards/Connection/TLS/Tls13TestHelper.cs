using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.APIModel;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Standards.Connection.Tls.Tls13.API.Messages;
using Arctium.Standards.X509.X509Cert;
using Arctium.Tests.Core.Testing;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Tests.Standards.Connection.TLS
{
    internal class Tls13TestHelper
    {
        public static readonly bool IsDebug = Debugger.IsAttached;
        public static readonly bool NotDebug = !Debugger.IsAttached;

        public class TestHandshakeClientAuthClientConfig : ClientConfigHandshakeClientAuthentication
        {
            private X509CertWithKey clientCert;
            private ExtensionServerConfigOidFilters.OidFilter[] expectedOidFilters;
            private Action<IList<Extension>> assertAction;

            public TestHandshakeClientAuthClientConfig(X509CertWithKey clientCert, ExtensionServerConfigOidFilters.OidFilter[] expectedOidFilters = null)
            {
                this.clientCert = clientCert;
                this.expectedOidFilters = expectedOidFilters;
            }

            public TestHandshakeClientAuthClientConfig(Action<IList<Extension>> assertAction)
            {
                this.assertAction = assertAction;
            }

            public override Certificates GetCertificateToSendToServer(IList<Extension> extensionInCertificateRequest)
            {
                if (assertAction != null) assertAction(extensionInCertificateRequest);

                if (expectedOidFilters != null)
                {
                    var oids = extensionInCertificateRequest.FirstOrDefault(f => f.ExtensionType == ExtensionType.OidFilters) as ExtensionOidFilters;
                    if (oids == null) Assert.Fail("expected to receive oid filters but not found");

                    if (oids.Filters.Length != expectedOidFilters.Length) Assert.Fail("expected oids does not match with received");
                    if (!oids.Filters.All(received => expectedOidFilters.Any(expected =>
                        MemOps.Memcmp(expected.CertificateExtensionOid, received.CertificateExtensionOid) &&
                        MemOps.Memcmp(expected.CertificateExtensionValues, received.CertificateExtensionValues))))
                    {
                        Assert.Fail("Expected oid filters do not match with received oid filters");
                    }
                }

                return new Certificates
                {
                    ClientCertificate = clientCert,
                    ParentCertificates = new X509Certificate[0]
                };
            }
        }

        public class TestHandshakeClientAuthServerConfig : ServerConfigHandshakeClientAuthentication
        {
            private bool expectNotEmptyCert;
            private Action action;
            private Action<byte[][], List<Extension>> assertAction;

            public TestHandshakeClientAuthServerConfig(Action<byte[][], List<Extension>> assertAction)
            {
                this.assertAction = assertAction;
            }

            public TestHandshakeClientAuthServerConfig(bool expectNotEmptyCert, Action action)
            {
                this.expectNotEmptyCert = expectNotEmptyCert;
                this.action = action;
            }

            public override Action CertificateFromClientReceived(byte[][] certificateFromClient, List<Extension> extensions)
            {
                if (expectNotEmptyCert) Assert.IsTrue(certificateFromClient.Length != 0);

                if (assertAction != null)
                {
                    assertAction(certificateFromClient, extensions);
                    return Action.Success;
                }

                return action;
            }
        }

        public class TestPHAuthClientConfig : ClientConfigPostHandshakeClientAuthentication
        {
            private Action<IList<Extension>> assertAction;

            public TestPHAuthClientConfig(Action<IList<Extension>> assertAction)
            {
                this.assertAction = assertAction;
            }

            public override Certificates GetCertificateToSendToServer(IList<Extension> extensionInCertificateRequest)
            {
                if (assertAction != null) assertAction(extensionInCertificateRequest);

                return new Certificates()
                {
                    ClientCertificate = null,
                    ParentCertificates = new X509Certificate[0]
                };
            }
        }

        public class TestPHAuthServerConfig : ServerConfigPostHandshakeClientAuthentication
        {
            private Action<byte[][], List<Extension>> assertAction;


            public TestPHAuthServerConfig() { }

            public TestPHAuthServerConfig(Action<byte[][], List<Extension>> assertAction)
            {
                this.assertAction = assertAction;
            }

            public override Action CertificateFromClientReceived(byte[][] certificateFromClient, List<Extension> extensions)
            {
                if (assertAction != null) assertAction(certificateFromClient, extensions);

                return Action.Success;
            }
        }


        class state
        {
            public StreamMediator mediator;
            public byte[] expectedreceive;
            public Tls13Client client;
            public Tls13Server server;
            public Action<Tls13ServerStream> serveraction;
            public Action<Tls13Stream> clientaction;
        }

        public static void Assert_Connect_DoAction(
            Tls13Server server,
            Tls13Client client,
            Action<Tls13ServerStream> serverAction,
            Action<Tls13Stream> clientAction,
            out Tls13ClientConnectionInfo clientConnectionInfo,
            out Tls13ServerConnectionInfo serverConnectionInfo,
            out Exception clientException,
            out Exception serverException)
        {
            StreamMediator medit = new StreamMediator(null, null);
            int const_timeout = 2000;
            int maxWaitMs = 10 * 1000;
            int sleepMs = 10;
            int sleepCount = (int)Math.Ceiling((double)maxWaitMs / sleepMs);

            if (Debugger.IsAttached) const_timeout = 1000000;

            var cs = medit.GetA();
            var ss = medit.GetB();

            //cm.stream = sm;
            //sm.stream = cm;

            var c = Task.Factory.StartNew<Tls13ServerConnectionInfo>(StartServer, new state
            {
                server = server,
                mediator = ss,
                serveraction = serverAction
            });

            var s = Task.Factory.StartNew<Tls13ClientConnectionInfo>(StartClient, new state()
            {
                client = client,
                mediator = cs,
                clientaction = clientAction
            });

            // bool success = Task.WaitAll(new Task[] { c, s }, const_timeout);

            int sleep = 0;

            while (true)
            {
                if (c.IsCompleted && s.IsCompleted) break;
                if (sleep++ > sleepCount && NotDebug)
                {
                    Assert.Fail("maybe fail because long operation or maybe fail because of real fail");
                }
                Thread.Sleep(sleepMs); //maybe this need to be longer period, maybe long calculations or smt
            }

            clientException = c.Exception;
            serverException = s.Exception;

            clientConnectionInfo = null;
            serverConnectionInfo = null;

            if (clientException == null) clientConnectionInfo = s.Result;
            if (serverException == null) serverConnectionInfo = c.Result;
        }

        public static void Assert_Connect_DoAction_Success(
            Tls13Server server,
            Tls13Client client,
            Action<Tls13ServerStream> serverAction,
            Action<Tls13Stream> clientAction,
            out Tls13ClientConnectionInfo clientConnectionInfo,
            out Tls13ServerConnectionInfo serverConnectionInfo)
        {
            Assert_Connect_DoAction(
                server,
                client,
                serverAction,
                clientAction,
                out clientConnectionInfo,
                out serverConnectionInfo,
                out var clientException,
                out var serverException);

            if (clientException != null || serverException != null) Assert.Fail();
        }

        static Tls13ServerConnectionInfo StartServer(object state)
        {
            var st = (state as state);

            try
            {
                var tlsserver = st.server;
                var tlsstream = tlsserver.Accept(st.mediator, out var serverconnectioninfo);

                st.serveraction(tlsstream);
                //tlsstream.Close();

                return serverconnectioninfo;
            }
            catch (Exception e)
            {
                st.mediator.AbortFatalException();
                throw e;
            }
        }

        static Tls13ClientConnectionInfo StartClient(object state)
        {
            var st = (state as state);
            var tlsclient = st.client;
            var tlsstream = tlsclient.Connect(st.mediator, out var clientconnectioninfo);

            st.clientaction(tlsstream);
            //tlsstream.Close();

            return clientconnectioninfo;
        }

        public static void Assert_Connect_SendReceive(
            Tls13Server server,
            Tls13Client client,
            out Tls13ClientConnectionInfo clientConnectionInfo,
            out Tls13ServerConnectionInfo serverConnectionInfo,
            out Exception clientException,
            out Exception serverException,
            int dataLengthKib = 10)
        {
            Action<Tls13Stream> caction = (tlsstream) =>
            {
                byte[] expectedreceive = new byte[dataLengthKib * 1024];
                tlsstream.Write(expectedreceive);

                BufferForStream bufForStream = new BufferForStream(tlsstream);
                bufForStream.LoadToLength(expectedreceive.Length);

                Assert.MemoryEqual(new Shared.Helpers.BytesRange(bufForStream.Buffer, 0, bufForStream.DataLength), expectedreceive);
            };

            Action<Tls13ServerStream> saction = (tlsstream) =>
            {
                byte[] expectedreceive = new byte[dataLengthKib * 1024];
                tlsstream.Write(expectedreceive);
                BufferForStream bufForStream = new BufferForStream(tlsstream);

                bufForStream.LoadToLength(expectedreceive.Length);
                Assert.MemoryEqual(new Shared.Helpers.BytesRange(bufForStream.Buffer, 0, bufForStream.DataLength), expectedreceive);
            };

            Assert_Connect_DoAction(server, client, saction, caction, out clientConnectionInfo, out serverConnectionInfo, out clientException, out serverException);
        }

        public static void Assert_Connect_SendReceive_Success(
            Tls13Server server,
            Tls13Client client,
            out Tls13ClientConnectionInfo clientConnectionInfo,
            out Tls13ServerConnectionInfo serverConnectionInfo,
            int dataLengthKib = 10)
        {
            Assert_Connect_SendReceive(
                server,
                client, 
                out  clientConnectionInfo,
                out  serverConnectionInfo,
                out var clientException,
                out var serverException,
                dataLengthKib);

            if (clientException != null || serverException != null) Assert.Fail();
        }


        public static void Assert_Connect_SendReceive(Tls13Server server, Tls13Client client, int dataLengthKib = 10)
        {
            Assert_Connect_SendReceive_Success(server, client, out var _, out var _, dataLengthKib);
        }

        public static Tls13Server DefaultServer(X509CertWithKey[] certWithKey = null,
            ExtensionServerConfigSupportedGroups supportedGroups = null,
            int? recordSizeLimit = null,
            ExtensionServerConfigALPN alpnSelector = null,
            ExtensionServerConfigServerName sni = null,
            ServerConfigHandshakeClientAuthentication hsClientAuth = null,
            ExtensionServerConfigOidFilters oidFilters = null,
            ServerConfigPostHandshakeClientAuthentication phca = null,
            ExtensionServerConfigCertificateAuthorities certAuthorities = null,
            ExtensionServerConfigGREASE grease = null,
            bool disableGrease = false)
        {
            certWithKey = certWithKey ?? new[] { Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1 };

            var serverctx = Tls13ServerContext.Default(certWithKey);
            var config = serverctx.Config;

            if (grease != null) config.ConfigureGREASE(grease);
            if (certAuthorities != null) config.ConfigureExtensionCertificateAuthorities(certAuthorities);
            if (phca != null) config.ConfigurePostHandshakeClientAuthentication(phca);
            if (oidFilters != null) config.ConfigureExtensionOidFilters(oidFilters);
            if (sni != null) config.ConfigureExtensionServerName(sni);
            if (alpnSelector != null) config.ConfigueExtensionALPN(alpnSelector);
            if (supportedGroups != null) serverctx.Config.ConfigueExtensionSupportedGroups(supportedGroups);
            if (recordSizeLimit.HasValue) config.ConfigureExtensionRecordSizeLimit(recordSizeLimit);
            if (hsClientAuth != null) config.ConfigureHandshakeClientAuthentication(hsClientAuth);
            if (disableGrease) config.ConfigureGREASE(null);

            var server = new Tls13Server(serverctx);

            return server;
        }

        /// <summary>
        /// Creates default instance. If any optional parameter is not null
        /// then this parameter will be set by invoking configuration method with value for this parameter
        /// </summary>
        public static Tls13Client DefaultClient(
            ExtensionClientConfigSupportedGroups supportedGroups = null,
            int? recordSizeLimit = null,
            ExtensionClientALPNConfig alpnConfig = null,
            ExtensionClientConfigServerName sni = null,
            ExtensionClientConfigSignatureAlgorithmsCert sacConfig = null,
            ClientConfigHandshakeClientAuthentication hsClientAuth = null,
            ClientConfigPostHandshakeClientAuthentication phca = null,
            ExtensionClientConfigCertificateAuthorities certAuthorities = null,
            ExtensionClientConfigKeyShare keyShare = null,
            ExtensionClientConfigGREASE grease = null,
            bool disableGrease = false)
        {
            var context = Tls13ClientContext.DefaultUnsafe();
            var config = context.Config;

            if (grease != null) config.ConfigureGREASE(grease);
            if (certAuthorities != null) config.ConfigureExtensionCertificateAuthorities(certAuthorities);
            if (phca != null) config.ConfigurePostHandshakeClientAuthentication(phca);
            if (sni != null) config.ConfigureExtensionServerName(sni);
            if (alpnConfig != null) config.ConfigureExtensionALPN(alpnConfig);
            if (sacConfig != null) config.ConfigureExtensionSignatureAlgorithmsCert(sacConfig);
            if (hsClientAuth != null) config.ConfigureHandshakeClientAuthentication(hsClientAuth);

            if (supportedGroups != null)
            {
                config.ConfigueExtensionKeyShare(new ExtensionClientConfigKeyShare(supportedGroups.NamedGroups.ToArray()));
                config.ConfigueExtensionSupportedGroups(supportedGroups);
            }

            if (keyShare != null) config.ConfigueExtensionKeyShare(keyShare);

            if (recordSizeLimit != null) config.ConfigueExtensionRecordSizeLimit(recordSizeLimit);

            if (disableGrease) config.ConfigureGREASE(null);

            Tls13Client client = new Tls13Client(context);

            return client;
        }
    }
}
