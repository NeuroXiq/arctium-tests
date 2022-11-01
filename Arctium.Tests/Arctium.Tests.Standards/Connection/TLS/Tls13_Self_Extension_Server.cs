using Arctium.Shared.Helpers;
using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.APIModel;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Tests.Core.Attributes;
using Arctium.Tests.Core.Testing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static Arctium.Standards.Connection.Tls.Tls13.API.Extensions.ExtensionServerConfigALPN;
using static Arctium.Tests.Standards.Connection.TLS.Tls13TestHelper;

namespace Arctium.Tests.Standards.Connection.TLS
{
    [TestsClass]
    internal class Tls13_Self_Extension_Server
    {
        #region Extension Certificate authorities

        class TestCASConfig : ExtensionServerConfigCertificateAuthorities
        {
            public static byte[][] Auths = new byte[][]
            {
                new byte[] { 1, },
                new byte[] { 1, 2 },
                new byte[] { 1, 2,3,4,5,6,7,8,9 },
            };

            public TestCASConfig() : base(Auths)
            {
            }
        }

        class TestCACConfig : ExtensionClientConfigCertificateAuthorities
        {
            public static byte[][] Auths = new byte[][]
            {
                new byte[] { 10, },
                new byte[] { 11, 21 },
                new byte[] { 11, 21,31,41,51,61,7,18,19 },
            };

            public TestCACConfig() : base(Auths) { }
        }

        [TestMethod]
        public void Extension_CertificateAuthorities_ServerWillSendInCertifiateRequest_ClientWillReceive()
        {
            var sauthorities = new TestCASConfig();
            var cauthorities = new TestCACConfig();

            Action<IList<Extension>> clientAssert = (ext) =>
            {
                var caExt = ext.FirstOrDefault(e => e.ExtensionType == ExtensionType.CertificateAuthorities) as ExtensionCertificateAuthorities;

                Assert.Equals(caExt.Authorities.Length, TestCASConfig.Auths.Length);
                bool allMatch = caExt.Authorities.All(received => TestCASConfig.Auths.Any(sended => MemOps.Memcmp(received, sended)));
                Assert.IsTrue(allMatch);
            };

            var hsAuthClient = new TestHandshakeClientAuthClientConfig(clientAssert);
            var hsAuthServer = new TestHandshakeClientAuthServerConfig(false, Arctium.Standards.Connection.Tls.Tls13.API.Messages.ServerConfigHandshakeClientAuthentication.Action.Success);
            var pauthclient = new TestPHAuthClientConfig(clientAssert);
            var pauthserver = new TestPHAuthServerConfig();

            var server = DefaultServer(certAuthorities: sauthorities, phca:pauthserver);
            var client = DefaultClient(certAuthorities: cauthorities, phca: pauthclient);

            Action<Tls13Stream> caction = (tlss) =>
            {
                tlss.Read(new byte[] { 1 });
                tlss.Read(new byte[] { 1 });
            };

            Action<Tls13ServerStream> saction = (tlss) =>
            {
                tlss.Write(new byte[] { 1 });
                tlss.PostHandshakeClientAuthentication();
                tlss.Write(new byte[] { 1 });
                tlss.TryWaitPostHandshake();
            };

            Assert_Connect_DoAction(server, client, saction, caction, out _, out _);
        }

        #endregion

        #region extension oidfilters

        [TestMethod]
        public void Extension_OidFilters_ServerSendsOidFiltersAndClientReceiveOidFilters()
        {
            var filters = new ExtensionServerConfigOidFilters.OidFilter[]
            {
                new ExtensionServerConfigOidFilters.OidFilter(new byte[1] { 1 } , new byte[] { 1 }),
                new ExtensionServerConfigOidFilters.OidFilter(new byte[2] { 2, 3 }, new byte[] { 2 }),
                new ExtensionServerConfigOidFilters.OidFilter(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, new byte[] { 1,2,3,4,5,6,7,8,9,10 }),
                new ExtensionServerConfigOidFilters.OidFilter(new byte[244], new byte[0]),
                new ExtensionServerConfigOidFilters.OidFilter(new byte[255], new byte[10000]),
            };

            var authOnServer = new TestHandshakeClientAuthServerConfig(true, Arctium.Standards.Connection.Tls.Tls13.API.Messages.ServerConfigHandshakeClientAuthentication.Action.Success);
            var authOnClient = new TestHandshakeClientAuthClientConfig(Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1, expectedOidFilters: filters);
            var oidFilters = new ExtensionServerConfigOidFilters(filters);
            var server = DefaultServer(oidFilters: oidFilters, hsClientAuth: authOnServer );
            var client = DefaultClient(hsClientAuth: authOnClient);

            Assert_Connect_SendReceive(server, client);
        }

        #endregion


        #region SignatureAlgorithmCert

        [TestMethod]
        public void Extension_SignatureAlgorithmCert_ClientWillSentExtension()
        {
            var clientSAC = new ExtensionClientConfigSignatureAlgorithmsCert(new[] { SignatureScheme.EcdsaSecp256r1Sha256, SignatureScheme.EcdsaSecp521r1Sha512 });
            var client = DefaultClient(sacConfig: clientSAC);
            var server = DefaultServer(new[] { Tls13TestResources.CERT_WITH_KEY_cert_secp256r1_sha256_1 });

            Assert_Connect_SendReceive(server, client);
        }

        #endregion

        [TestMethod]
        public void Extension_ServerName_ExtensionsWorkOnClientAndServer()
        {
            var sniClient = new ExtensionClientConfigServerName("arctium-tls13");
            var sniServer = new Test_ExtensionServerConfigServerName(ExtensionServerConfigServerName.ResultAction.Success, "arctium-tls13");

            var client = DefaultClient(sni: sniClient);
            var server = DefaultServer(sni: sniServer);

            Assert_Connect_SendReceive(server, client, out var clientinfo, out var serverinfo);

            Assert.IsTrue(clientinfo.ExtensionResultServerName);
            Assert.IsTrue(serverinfo.ExtensionResultServerName == ExtensionServerConfigServerName.ResultAction.Success);
        }

        [TestMethod]
        public void Extension_ServerName_ServerWillAbortConnection()
        {
            var sniClient = new ExtensionClientConfigServerName("arctium-tls13");
            var sniServer = new Test_ExtensionServerConfigServerName(ExtensionServerConfigServerName.ResultAction.AbortFatalAlertUnrecognizedName, "arctium-tls13");

            var client = DefaultClient(sni: sniClient);
            var server = DefaultServer(sni: sniServer);

            Assert.Throws(() => Assert_Connect_SendReceive(server, client, out var clientinfo, out var serverinfo));
        }

        [TestMethod]
        public void Extension_ServerName_ServerWillIgnoreExtension()
        {
            var sniClient = new ExtensionClientConfigServerName("arctium-tls13");
            var sniServer = new Test_ExtensionServerConfigServerName(ExtensionServerConfigServerName.ResultAction.Ignore, "arctium-tls13");

            var client = DefaultClient(sni: sniClient);
            var server = DefaultServer(sni: sniServer);

            Assert_Connect_SendReceive(server, client, out var clientinfo, out var serverinfo);

            Assert.IsFalse(clientinfo.ExtensionResultServerName);
            Assert.IsTrue(serverinfo.ExtensionResultServerName == ExtensionServerConfigServerName.ResultAction.Ignore);
        }

        #region ALPN

        class TestSALPN : ExtensionServerConfigALPN
        {
            private Func<byte[][], ResultSelect, Result> action;

            public TestSALPN(Func<byte[][], ResultSelect, Result> action)
            {
                this.action = action;
            }

            public override Result Handle(byte[][] protocolNameListFromClient, ResultSelect resultSelector)
            {
                return action(protocolNameListFromClient, resultSelector);
            }
        }

        [TestMethod]
        public void Extension_ALPN_ClientAndServerNegotiateProtocolSuccessfullyWhenOnlyOneProtocol()
        {
            var alpnClient = new ExtensionClientALPNConfig();
            alpnClient.Add(ALPNProtocol.HTTP_1_1);

            Func<byte[][], ResultSelect, Result> alpnAction = (prots, select) =>
            {
                if (ExtensionResultALPN.TryGetAsStandarizedALPNProtocol(prots[0], out var standarized))
                {
                    return select.Success(0);
                }

                return select.NotSelectedFatalAlert();
            };

            var alpnServer = new TestSALPN(alpnAction);
            var client = DefaultClient(alpnConfig: alpnClient);
            var server = DefaultServer(alpnSelector: alpnServer);


            Assert_Connect_SendReceive(server, client, out var clientInfo, out var _);

            Assert.NotNull(clientInfo.ExtensionResultALPN);

            if (ExtensionResultALPN.TryGetAsStandarizedALPNProtocol(clientInfo.ExtensionResultALPN.Protocol, out var namedProtocol))
            {
                if (namedProtocol.Value != ALPNProtocol.HTTP_1_1) Assert.Fail("must be http 1.1 because client sent this");
                return;
            }

            Assert.Fail("should select 1 protocol but not selected any");
        }

        [TestMethod]
        public void Extension_ALPN_ClientServerNegotiateProtocolSuccessfullyWhenMultipleProtocols()
        {
            var alpnClient = new ExtensionClientALPNConfig();
            alpnClient.Add("not standarized protocol name");
            alpnClient.Add(new byte[] { 65,66,67,2,3,4 });
            alpnClient.Add(ALPNProtocol.HTTP_2_over_TCP);

            Func<byte[][], ResultSelect, Result> alpnAction = (prots, selector) =>
            {
                if (prots.Length != 3) Assert.Fail("client sent 3 alpn protocol names");

                for (int i = 0; i < prots.Length; i++)
                {
                    if (ExtensionResultALPN.TryGetAsStandarizedALPNProtocol(prots[i], out var standarizedName))
                    {
                        if (standarizedName == ALPNProtocol.HTTP_2_over_TCP) return selector.Success(i);
                    }
                }

                Assert.Fail();
                return selector.NotSelectedFatalAlert();
            };

            var alpnServer = new TestSALPN(alpnAction);

            var server = DefaultServer(alpnSelector: alpnServer);
            var client = DefaultClient(alpnConfig: alpnClient);

            Assert_Connect_SendReceive(server, client, out var clientinfo, out var serverinfo);

            ExtensionResultALPN.TryGetAsStandarizedALPNProtocol(clientinfo.ExtensionResultALPN.Protocol, out var onClient);
            ExtensionResultALPN.TryGetAsStandarizedALPNProtocol(serverinfo.ExtensionResultALPN.Protocol, out var onServer);

            Assert.NotNull(onClient);
            Assert.ValuesEqual(onClient, onServer);
        }

        [TestMethod]
        public void Extension_ALPN_ServerWillThrowExceptionAndSendAlertFatal()
        {
            var alpnClient = new ExtensionClientALPNConfig();
            alpnClient.Add(ALPNProtocol.acme_tls_1);
            alpnClient.Add("123");

            Func<byte[][], ResultSelect, Result> alpnAction = (prots, selector) =>
            {
                return selector.NotSelectedFatalAlert();
            };

            var alpnServer = new TestSALPN(alpnAction);

            var server = DefaultServer(alpnSelector: alpnServer);
            var client = DefaultClient(alpnConfig: alpnClient);

            Assert.Throws(() => Assert_Connect_SendReceive(server, client));
        }

        [TestMethod]
        public void Extension_ALPN_ServerWillNotSelectALPNAndContinueIgnoringIt()
        {
            var alpnClient = new ExtensionClientALPNConfig();
            alpnClient.Add(ALPNProtocol.acme_tls_1);
            alpnClient.Add("123");

            Func<byte[][], ResultSelect, Result> alpnAction = (prots, selector) =>  selector.NotSelectedIgnore();

            var alpnServer = new TestSALPN(alpnAction);

            var server = DefaultServer(alpnSelector: alpnServer);
            var client = DefaultClient(alpnConfig: alpnClient);

            Assert_Connect_SendReceive(server, client);
        }

        #endregion

        #region record size limit

        [TestMethod]
        public void Extension_RecordSizeLimit_ServerWillSetToClientValue()
        {
            ushort? recordSizeLimit = 0x1000;
            var server = DefaultServer();
            var client = DefaultClient(recordSizeLimit: recordSizeLimit);

            Assert_Connect_SendReceive(server, client, out var clientConInfo, out var _);

            Assert.ValuesEqual(clientConInfo.ExtensionRecordSizeLimit, recordSizeLimit);
        }

        [TestMethod]
        public void Extension_RecordSizeLimit_ServerWillSetToServerIfServerLower()
        {
            // configures lower to server so server should select lower
            int clientRecordSizeLimit = 0x2000;
            ushort? serverRecordSizeLimit = 0x800;
            var server = DefaultServer(recordSizeLimit: serverRecordSizeLimit);
            var client = DefaultClient(recordSizeLimit: clientRecordSizeLimit);

            Assert_Connect_SendReceive(server, client, out var clientConInfo, out var _);

            Assert.ValuesEqual(clientConInfo.ExtensionRecordSizeLimit, serverRecordSizeLimit);
        }

        [TestMethod]
        public void Extension_RecordSizeLimit_ServerWillSetToClientIfClientLower()
        {
            ushort? clientRecordSizeLimit = 0x800;
            ushort? serverRecordSizeLimit = 0x1000;
            var server = DefaultServer(recordSizeLimit: serverRecordSizeLimit);
            var client = DefaultClient(recordSizeLimit: clientRecordSizeLimit);

            Assert_Connect_SendReceive(server, client, out var clientConInfo, out var _);

            Assert.ValuesEqual(clientConInfo.ExtensionRecordSizeLimit, clientRecordSizeLimit);
        }

        #endregion

        class Test_ExtensionServerConfigServerName : ExtensionServerConfigServerName
        {
            private ResultAction action;
            private string expectedHostName;

            public Test_ExtensionServerConfigServerName(ResultAction action, string expectedHostName)
            {
                this.action = action;
                this.expectedHostName = expectedHostName;
            }

            public override ResultAction Handle(byte[] hostName)
            {
                var s1 = Encoding.ASCII.GetString(hostName);

                if (s1 != expectedHostName) Assert.Fail("SNI Extension: received other host name than expected");

                return action;
            }
        }
    }
}
