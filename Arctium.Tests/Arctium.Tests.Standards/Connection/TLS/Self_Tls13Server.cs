using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.X509.X509Cert;
using Arctium.Tests.Core.Attributes;
using Arctium.Tests.Core.Testing;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Tests.Standards.Connection.TLS
{
    [TestsClass]
    class Self_Tls13Server
    {
        

        [TestMethod]
        public void AcceptSimplestConnection_RSA_Certificate()
        {
            var client = DefaultClient();
            var serverCtx = Tls13ServerContext.Default(new[] { Tls13TestResources.CERT_WITH_KEY_CERT1_RSA_SIG_sha256RSA });
            var server = new Tls13Server(serverCtx);

            Assert_Connect_SendReceive(server, client);
        }

        class state
        {
            public StreamMediator mediator;
            public byte[] expectedreceive;
            public Tls13Client client;
            public Tls13Server server;
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
            //Assert.Fail();
        }

        static void Assert_Connect_SendReceive(Tls13Server server, Tls13Client client, int dataLengthKib = 10)
        {
            StreamMediator medit = new StreamMediator(null, null);
            int const_timeout = 2000;

            if (Debugger.IsAttached) const_timeout = 1000000;

            var cs = medit.GetA();
            var ss = medit.GetB();
            
            byte[] Data_10Kib = new byte[0x1000 * dataLengthKib];
            for (int i = 0; i < Data_10Kib.Length; i++) Data_10Kib[i] = (byte)i;

            //cm.stream = sm;
            //sm.stream = cm;

            var c = Task.Factory.StartNew(state =>
            {
                var st = (state as state);
                
                try
                {
                    var tlsserver = st.server;
                    var tlsstream = tlsserver.Accept(st.mediator);
                    BufferForStream bufForStream = new BufferForStream(tlsstream);
                    bufForStream.LoadToLength(st.expectedreceive.Length);
                    tlsstream.Write(st.expectedreceive, 0, st.expectedreceive.Length);

                    Assert.MemoryEqual(new Shared.Helpers.BytesRange(bufForStream.Buffer, 0, bufForStream.DataLength), st.expectedreceive);
                }
                catch (Exception e)
                {
                    st.mediator.AbortFatalException();
                    throw e;
                }
            }, new state
            {
                server = server,
                mediator = ss,
                expectedreceive = Data_10Kib
            });

            var s = Task.Factory.StartNew(state =>
            {
                var st = (state as state);
                var tlsclient= st.client;
                var tlsstream = tlsclient.Connect(st.mediator);

                tlsstream.Write(st.expectedreceive);
                BufferForStream bufForStream = new BufferForStream(tlsstream);

                bufForStream.LoadToLength(st.expectedreceive.Length);

                Assert.MemoryEqual(new Shared.Helpers.BytesRange(bufForStream.Buffer, 0, bufForStream.DataLength), st.expectedreceive);
            }, new state()
            {
                client = client,
                mediator = cs,
                expectedreceive = Data_10Kib
            });

            // bool success = Task.WaitAll(new Task[] { c, s }, const_timeout);

            int sleep = 0;

            while (true)
            {
                if (c.IsCompleted && s.IsCompleted) break;
                if (sleep++ > 10) Assert.Fail();
                Thread.Sleep(400);
            }

            if (c.Exception != null || s.Exception != null) Assert.Fail();
        }

        static Tls13Server DefaultServer(X509CertWithKey[] certWithKey, NamedGroup[] keyExchangeGroups = null)
        {
            var serverctx = Tls13ServerContext.Default(certWithKey);

            if (keyExchangeGroups != null)
            {
                serverctx.Config.ConfigueSupportedNamedGroupsForKeyExchange(keyExchangeGroups);
            }

            var server = new Tls13Server(serverctx);

            return server;
        }

        static Tls13Client DefaultClient(NamedGroup[] supportedGroups= null)
        {
            var context = Tls13ClientContext.DefaultUnsave();
            var config = context.Config;

            if (supportedGroups != null)
            {
                config.ConfigueClientKeyShare(supportedGroups);
                config.ConfigueSupportedGroups(supportedGroups);
            }

            Tls13Client client = new Tls13Client(context);

            return client;
        }
    }
}
