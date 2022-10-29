using Arctium.Shared.Helpers;
using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Tests.Core.Attributes;
using Arctium.Tests.Core.Testing;
using System;
using System.Text;
using static Arctium.Tests.Standards.Connection.TLS.Tls13TestHelper;

namespace Arctium.Tests.Standards.Connection.TLS
{
    [TestsClass]
    internal class Tls13_Self_Extension_Server
    {

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

        [TestMethod]
        public void Extension_ALPN_ClientAndServerNegotiateProtocolSuccessfullyWhenOnlyOneProtocol()
        {
            var alpnClient = new ExtensionClientALPNConfig();
            alpnClient.Add(ALPNProtocol.HTTP_1_1);

            Func<ExtensionServerALPN, ExtensionServerALPN.Result> alpnServer = (selector) =>
            {
                if (ExtensionResultALPN.TryGetAsStandarizedALPNProtocol(selector.ProtocolNameListFromClient[0], out var standarized))
                {
                    return selector.Success(0);
                }

                return selector.NotSelectedFatalAlert();
            };

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

            Func<ExtensionServerALPN, ExtensionServerALPN.Result> alpnServer = (selector) =>
            {
                if (selector.ProtocolNameListFromClient.Length != 3) Assert.Fail("client sent 3 alpn protocol names");

                for (int i = 0; i < selector.ProtocolNameListFromClient.Length; i++)
                {
                    if (ExtensionResultALPN.TryGetAsStandarizedALPNProtocol(selector.ProtocolNameListFromClient[i], out var standarizedName))
                    {
                        if (standarizedName == ALPNProtocol.HTTP_2_over_TCP) return selector.Success(i);
                    }
                }

                Assert.Fail();
                return selector.NotSelectedFatalAlert();
            };

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

            Func<ExtensionServerALPN, ExtensionServerALPN.Result> alpnServer = (selector) => selector.NotSelectedFatalAlert();

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

            Func<ExtensionServerALPN, ExtensionServerALPN.Result> alpnServer = (selector) => selector.NotSelectedIgnore();

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
