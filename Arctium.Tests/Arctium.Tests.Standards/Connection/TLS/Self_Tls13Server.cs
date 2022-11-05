using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.APIModel;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
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
        [TestMethod]
        public void SupportedGroups_ClientWillSentMultipleKeySharesServerSelectOne()
        {
            var server = DefaultServer(supportedGroups: new ExtensionServerConfigSupportedGroups(new [] { NamedGroup.Ffdhe6144 }));
            var client = DefaultClient(keyShare: new ExtensionClientConfigKeyShare(new[] { NamedGroup.Ffdhe2048, NamedGroup.Ffdhe3072, NamedGroup.Ffdhe6144, NamedGroup.X25519 }));

            Assert_Connect_SendReceive(server, client);
        }

        [TestMethod]
        public void Message_GenerateTest_ServerClientExchange1MBData()
        {
            var server = DefaultServer();
            var client = DefaultClient();

            Assert_Connect_SendReceive(server, client, 1 * 1024);
        }

        #region KeyUpdate

        [TestMethod]
        public void Message_KeyUpdate_ClientAndServerSendsKeyUpdateAndAllWorksFine()
        {
            var server = DefaultServer();
            var client = DefaultClient();

            int datalen = 1024;
            byte[] writedata = new byte[datalen];

            // read count (on both sides)
            // must be equal write count (on second side
            // keyupdate must not be last action invoked

            Action<Tls13ServerStream> saction = (sstream) =>
            {
                sstream.Write(writedata);
                sstream.PostHandshakeKeyUpdate(true);
                sstream.Write(writedata);
                sstream.Write(writedata);
                sstream.PostHandshakeKeyUpdate(false);
                sstream.PostHandshakeKeyUpdate(true);
                sstream.Write(writedata);
                sstream.Write(writedata);
                sstream.Write(writedata);
                sstream.PostHandshakeKeyUpdate(false);
                sstream.PostHandshakeKeyUpdate(true);
                sstream.PostHandshakeKeyUpdate(true);
                sstream.Write(writedata);

                byte[] readb = new byte[datalen];
                for (int i = 0; i < 7; i++) sstream.Read(readb);
            };

            Action<Tls13Stream> caction = (cstream) =>
            {
                byte[] readbuf = new byte[datalen];

                for (int i = 0; i < 7; i++)
                {
                    if (i == 1 || i == 5) cstream.PostHandshakeKeyUpdate(true);

                    cstream.Read(readbuf);
                }

                cstream.Write(writedata);
                cstream.PostHandshakeKeyUpdate(true);
                cstream.Write(writedata);
                cstream.Write(writedata);
                cstream.PostHandshakeKeyUpdate(false);
                cstream.PostHandshakeKeyUpdate(true);
                cstream.Write(writedata);
                cstream.Write(writedata);
                cstream.Write(writedata);
                cstream.PostHandshakeKeyUpdate(false);
                cstream.PostHandshakeKeyUpdate(true);
                cstream.PostHandshakeKeyUpdate(true);
                cstream.Write(writedata);
            };

            Assert_Connect_DoAction_Success(server, client, saction, caction, out _, out _);
        }

        #endregion

        #region Post Handshake Client Auth 

        class TestPHCA_Server : ServerConfigPostHandshakeClientAuthentication
        {
            public bool AuthSuccess { get; private set; } = false;

            public TestPHCA_Server()
            {
                base.ClientAuthSuccess += TestPHCA_Server_ClientAuthSuccess;
            }

            private void TestPHCA_Server_ClientAuthSuccess(object sender, ClientAuthSuccessEventArgs e)
            {
                AuthSuccess = true;
                Assert.IsTrue(AuthSuccess);
            }

            public override Action CertificateFromClientReceived(byte[][] certificateFromClient, List<Extension> extensions)
            {
                return Action.Success;
            }
        }

        class TestPHCA_Client : ClientConfigPostHandshakeClientAuthentication
        {
            private X509CertWithKey certWithKey;

            public TestPHCA_Client(X509CertWithKey certWithKey)
            {
                this.certWithKey = certWithKey;
            }

            public override Certificates GetCertificateToSendToServer(IList<Extension> extensionInCertificateRequest)
            {
                return new Certificates
                {
                    ClientCertificate = certWithKey,
                    ParentCertificates = new X509Certificate[0]
                };
            }
        }

        [TestMethod]
        public void Message_PostHandshakeClientAuthentication_MultipleInterleavedWithDataExchangeMessages()
        {
            var sauth = new TestPHCA_Server();
            var server = DefaultServer(phca: sauth);
            var client = DefaultClient(phca: new TestPHCA_Client(Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1));

            byte[] towrite = new byte[1024];

            Action<Tls13ServerStream> sAction = (stream) =>
            {
                stream.Write(towrite);
                stream.PostHandshakeClientAuthentication();
                stream.Write(towrite);
                stream.Write(towrite);
                stream.PostHandshakeClientAuthentication();
                stream.PostHandshakeClientAuthentication();
                stream.Write(towrite);
                stream.Write(towrite);
                stream.Write(towrite);
                stream.PostHandshakeClientAuthentication();
                stream.PostHandshakeClientAuthentication();
                stream.PostHandshakeClientAuthentication();
                stream.PostHandshakeClientAuthentication();
                stream.Write(towrite);
            };

            Action<Tls13Stream> cAction = (stream) =>
            {
                int len = towrite.Length;
                byte[] buf = new byte[len];

                for (int i = 0; i < 7; i++) stream.Read(buf);
            };

            Assert_Connect_DoAction_Success(server, client, sAction, cAction, out _, out _);

        }

        [TestMethod]
        public void Message_PostHandshakeClientAuthentication_ClientAndServerSuccessWhenNoClientCertificate()
        {
            var sauth = new TestPHCA_Server();
            var server = DefaultServer(phca: sauth);
            var client = DefaultClient(phca: new TestPHCA_Client(null));

            Action<Tls13ServerStream> serverAction = (s) =>
            {
                s.PostHandshakeClientAuthentication();
                s.WaitForAnyProtocolData();
                s.Write(new byte[123]);
            };

            Action<Tls13Stream> clientAction = (c) =>
            {
                c.Read(new byte[123]);
            };

            Assert_Connect_DoAction_Success(server, client, serverAction, clientAction, out _, out _);
            Assert.IsTrue(sauth.AuthSuccess);
        }

        [TestMethod]
        public void Message_PostHandshakeClientAuthentication_ClientAndServerSuccessWhenClientHasCertificate()
        {
            var serverAuth = new TestPHCA_Server();
            var server = DefaultServer(phca: serverAuth);
            var client = DefaultClient(phca: new TestPHCA_Client(Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1));

            Action<Tls13ServerStream> serverAction = (tlstream) =>
            {
                tlstream.PostHandshakeClientAuthentication();
                tlstream.WaitForAnyProtocolData();
                tlstream.Write(new byte[1]);
            };

            Action<Tls13Stream> clientAction = (Tls13Stream) =>
            {
                Tls13Stream.Read(new byte[1], 0, 1);
            };

            Assert_Connect_DoAction_Success(server, client, serverAction, clientAction, out var cinfo, out var sinfo);
            Assert.IsTrue(serverAuth.AuthSuccess);
        }


        #endregion

        #region ClientAuth handshake

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

            Assert_Connect_SendReceive_Success(server, client, out var cinfo, out var sinfo);

            Assert.NotNull(cinfo.ResultHandshakeClientAuthentication);
            Assert.NotNull(sinfo.ResultHandshakeClientAuthentication);
        }

        [TestMethod]
        public void Message_ClientAuthenticationDuringHandshake_ServerWillAuthenticateClientWithCertificate()
        {
            var server = DefaultServer(hsClientAuth: new TestHandshakeClientAuthServerConfig(true, ServerConfigHandshakeClientAuthentication.Action.Success));
            var client = DefaultClient(hsClientAuth: new TestHandshakeClientAuthClientConfig(Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1));

            Assert_Connect_SendReceive_Success(server, client, out var cinfo, out var sinfo);

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
                var clientctx = Tls13ClientContext.DefaultUnsafe();
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
                var clientctx = Tls13ClientContext.DefaultUnsafe();

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
                var clientctx = Tls13ClientContext.DefaultUnsafe();
                var client = new Tls13Client(clientctx);

                clientctx.Config.ConfigueExtensionSupportedGroups(new ExtensionClientConfigSupportedGroups( new[] { group }));

                Assert_Connect_SendReceive(server, client);
            }
        }

        [TestMethod]
        public void ServerWillThrowAlertExceptionAndAbortIfClientAndServerDoesNotSupportMutuallyKeyExchangeModes()
        {
            var client = DefaultClient(supportedGroups: new ExtensionClientConfigSupportedGroups(new[] { NamedGroup.Ffdhe2048 }));
            var server = DefaultServer(
                new[] { Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha224_1 },
                new ExtensionServerConfigSupportedGroups(new[] { NamedGroup.X25519 }));

            Assert.Throws(() => Assert_Connect_SendReceive(server, client));
        }

        [TestMethod]
        public void AcceptWithPskSessionResumptionTicket()
        {
            var server = DefaultServer();
            var client = DefaultClient();

            Assert_Connect_SendReceive(server, client);

            Assert_Connect_SendReceive_Success(server, client, out var clientinfo, out var serverinfo);

            Assert.IsTrue(clientinfo.IsPskSessionResumption);
        }

        
    }
}
