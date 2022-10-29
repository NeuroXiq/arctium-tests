using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.APIModel;
using Arctium.Standards.Connection.Tls.Tls13.API.Messages;
using Arctium.Standards.X509.X509Cert;
using Arctium.Tests.Core.Attributes;
using Arctium.Tests.Core.Testing;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using static Arctium.Tests.Standards.Connection.TLS.Tls13TestHelper;

namespace Arctium.Tests.Standards.Connection.TLS
{
    [TestsClass]
    class Self_Tls13Server
    {
        #region ClientAuth handshake
        
        class TestHandshakeClientAuthClientConfig : ClientConfigHandshakeClientAuthentication
        {
            private X509CertWithKey clientCert;

            public TestHandshakeClientAuthClientConfig(X509CertWithKey clientCert)
            {
                this.clientCert = clientCert;
            }

            public override Certificates GetCertificateToSendToServer(List<Extension> extensionInCertificateRequest)
            {
                return new Certificates
                {
                    ClientCertificate = clientCert,
                    ParentCertificates = new X509Certificate[0]
                };
            }
        }

        class TestHandshakeClientAuthServerConfig : ServerConfigHandshakeClientAuthentication
        {
            private bool expectNotEmptyCert;
            private Action action;

            public TestHandshakeClientAuthServerConfig(bool expectNotEmptyCert, Action action)
            {
                this.expectNotEmptyCert = expectNotEmptyCert;
                this.action = action;
            }

            public override Action CertificateFromClientReceived(byte[][] certificateFromClient, List<Extension> extensions)
            {
                if (expectNotEmptyCert) Assert.IsTrue(certificateFromClient.Length != 0);

                return action;
            }
        }

        [TestMethod]
        public void Message_ServerSentCertificateRequest_ClientSentEmptyCertificate_ServerWillAbort()
        {
            var server = DefaultServer(hsClientAuth: new TestHandshakeClientAuthServerConfig(false, ServerConfigHandshakeClientAuthentication.Action.AlertFatalCertificateRequired));
            var client = DefaultClient(hsClientAuth: new TestHandshakeClientAuthClientConfig(null));

            Assert.Throws(() => Assert_Connect_SendReceive(server, client));
        }

        [TestMethod]
        public void Message_ServerSentCertificateRequest_ClientSentEmptyCertificate_Success()
        {
            var server = DefaultServer(hsClientAuth: new TestHandshakeClientAuthServerConfig(false, ServerConfigHandshakeClientAuthentication.Action.Success));
            var client = DefaultClient(hsClientAuth: new TestHandshakeClientAuthClientConfig(null));

            Assert_Connect_SendReceive(server, client, out var cinfo, out var sinfo);

            Assert.NotNull(cinfo.ResultHandshakeClientAuthentication);
            Assert.NotNull(sinfo.ResultHandshakeClientAuthentication);
        }

        [TestMethod]
        public void Message_ClientAuthenticationDuringHandshake_ServerWillAuthenticateClientWithCertificate()
        {
            var server = DefaultServer(hsClientAuth: new TestHandshakeClientAuthServerConfig(true, ServerConfigHandshakeClientAuthentication.Action.Success));
            var client = DefaultClient(hsClientAuth: new TestHandshakeClientAuthClientConfig(Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1));

            Assert_Connect_SendReceive(server, client, out var cinfo, out var sinfo);

            Assert.NotNull(cinfo.ResultHandshakeClientAuthentication);
            Assert.NotNull(sinfo.ResultHandshakeClientAuthentication);
            Assert.NotEmpty(cinfo.ResultHandshakeClientAuthentication.ClientCertificate);
            Assert.NotEmpty(sinfo.ResultHandshakeClientAuthentication.ClientCertificate);
        }
        
        #endregion

        [TestMethod]
        public void AcceptSimplestConnection_RSA_Certificate()
        {
            var client = DefaultClient();
            var serverCtx = Tls13ServerContext.Default(new[] { Tls13TestResources.CERT_WITH_KEY_CERT1_RSA_SIG_sha256RSA });
            var server = new Tls13Server(serverCtx);

            Assert_Connect_SendReceive(server, client);
        }

       

        [TestMethod]
        public void AcceptSimplestConnection_ECC_Certificate()
        {
            var client = DefaultClient();
            var serverctx = Tls13ServerContext.Default(new[] { Tls13TestResources.CERT_WITH_KEY_CERT3_ecc_secp384r1 });
            var server = new Tls13Server(serverctx);

            Assert_Connect_SendReceive(server, client);
        }

        [TestMethod]
        public void AcceptAllSupportedCipherSuites()
        {
            var allsuites = Enum.GetValues<Arctium.Standards.Connection.Tls.Tls13.API.CipherSuite>();
            var serverctx = Tls13ServerContext.Default(new[] { Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1 });
            var server = new Tls13Server(serverctx);

            foreach (var suite in allsuites)
            {
                var clientctx = Tls13ClientContext.DefaultUnsave();
                clientctx.Config.ConfigueCipherSuites(new[] { suite });
                var client = new Tls13Client(clientctx);

                Assert_Connect_SendReceive(server, client);
            }
        }

        [TestMethod]
        public void ServerWillAcceptClientForAllExistingSupportedSignaturesSchemesForDefaultServerConfiguration()
        {
            // all certificates -> all signatures schemes possible
            // server must correctly choose valid one
            var certs = new X509CertWithKey[]
            {
                Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1,
                Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha384_1,
                Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha512_1,
                Tls13TestResources.CERT_WITH_KEY_cert_secp256r1_sha256_1,
                Tls13TestResources.CERT_WITH_KEY_cert_secp256r1_sha384_1,
                Tls13TestResources.CERT_WITH_KEY_cert_secp256r1_sha512_1,
                Tls13TestResources.CERT_WITH_KEY_cert_secp384r1_sha256_1,
                Tls13TestResources.CERT_WITH_KEY_cert_secp384r1_sha384_1,
                Tls13TestResources.CERT_WITH_KEY_cert_secp384r1_sha512_1,
                Tls13TestResources.CERT_WITH_KEY_cert_secp521r1_sha256_1,
                Tls13TestResources.CERT_WITH_KEY_cert_secp521r1_sha384_1,
                Tls13TestResources.CERT_WITH_KEY_cert_secp521r1_sha512_1,
            };

            var allsigschemes = Enum.GetValues<SignatureScheme>();

            foreach (var s in allsigschemes)
            {
                var serverctx = Tls13ServerContext.Default(certs);
                var server = new Tls13Server(serverctx);
                var clientctx = Tls13ClientContext.DefaultUnsave();

                clientctx.Config.ConfigueSupportedSignatureSchemes(new[] { s });
                var client = new Tls13Client(clientctx);

                Assert_Connect_SendReceive(server, client);
            }
        }

        [TestMethod]
        public void ServerWillAcceptAllPossibleGroupsInKeyExchangeExtensionInClientHello1()
        {
            var cert = new[] { Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha224_1 };

            var allgroups = Enum.GetValues<NamedGroup>();

            foreach (var group in allgroups)
            {
                var serverctx = Tls13ServerContext.Default(cert);
                var server = new Tls13Server(serverctx);
                var clientctx = Tls13ClientContext.DefaultUnsave();
                var client = new Tls13Client(clientctx);

                clientctx.Config.ConfigueSupportedGroups(new[] { group });

                Assert_Connect_SendReceive(server, client);
            }
        }

        [TestMethod]
        public void ServerWillThrowAlertExceptionAndAbortIfClientAndServerDoesNotSupportMutuallyKeyExchangeModes()
        {
            var client = DefaultClient(new[] { NamedGroup.Ffdhe2048 });
            var server = DefaultServer(new[] { Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha224_1 }, new[] { NamedGroup.X25519 });

            Assert.Throws(() => Assert_Connect_SendReceive(server, client));
        }

        [TestMethod]
        public void AcceptWithPskSessionResumptionTicket()
        {
            var server = DefaultServer();
            var client = DefaultClient();

            Assert_Connect_SendReceive(server, client);

            Assert_Connect_SendReceive(server, client, out var clientinfo, out var serverinfo);

            Assert.IsTrue(clientinfo.IsPskSessionResumption);
        }

        
    }
}
