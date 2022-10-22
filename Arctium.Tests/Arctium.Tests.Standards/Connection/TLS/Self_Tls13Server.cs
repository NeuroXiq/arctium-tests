using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Tests.Core.Attributes;
using Arctium.Tests.Core.Testing;
using System;
using System.IO;
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
            public Stream mediator;
            public byte[] expectedreceive;
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
        public void AcceptAllSupportedSignatureAlgorithms()
        {

        }

        [TestMethod]
        public void AcceptWithPskSessionResumptionTicket()
        {

        }

        static void Assert_Connect_SendReceive(Tls13Server server, Tls13Client client, int dataLengthKib = 10)
        {
            StreamMediator medit = new StreamMediator(null, null);

            var cs = medit.GetA();
            var ss = medit.GetB();
            
            byte[] Data_10Kib = new byte[0x1000 * dataLengthKib];
            for (int i = 0; i < Data_10Kib.Length; i++) Data_10Kib[i] = (byte)i;

            //cm.stream = sm;
            //sm.stream = cm;

            var c = Task.Factory.StartNew(state =>
            {
                var st = (state as state);
                
                var tlsstream = server.Accept(st.mediator);

                BufferForStream bufForStream = new BufferForStream(tlsstream);

                bufForStream.LoadToLength(st.expectedreceive.Length);

                tlsstream.Write(st.expectedreceive, 0, st.expectedreceive.Length);

                Assert.MemoryEqual(new Shared.Helpers.BytesRange(bufForStream.Buffer, 0, bufForStream.DataLength), st.expectedreceive);

            }, new state
            {
                mediator = ss,
                expectedreceive = Data_10Kib
            });

            var s = Task.Factory.StartNew(state =>
            {
                var st = (state as state);
                var tlsstream = client.Connect(st.mediator);

                tlsstream.Write(st.expectedreceive);
                BufferForStream bufForStream = new BufferForStream(tlsstream);

                bufForStream.LoadToLength(st.expectedreceive.Length);

                Assert.MemoryEqual(new Shared.Helpers.BytesRange(bufForStream.Buffer, 0, bufForStream.DataLength), st.expectedreceive);
            }, new state()
            {
                mediator = cs,
                expectedreceive = Data_10Kib
            });

            bool success = Task.WaitAll(new Task[] { c, s }, 2000);

            if (c.Exception != null || s.Exception != null) Assert.Fail();

            if (!success)
            {
                throw new System.Exception("failed to execute tests. waited and not completed, maybe long operation or something goes wrong");
            }
        }

        static Tls13Client DefaultClient()
        {
            var context = Tls13ClientContext.DefaultUnsave();

            Tls13Client client = new Tls13Client(context);

            return client;
        }
    }
}
