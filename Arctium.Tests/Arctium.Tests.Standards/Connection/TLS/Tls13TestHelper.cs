using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
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
        class state
        {
            public StreamMediator mediator;
            public byte[] expectedreceive;
            public Tls13Client client;
            public Tls13Server server;
        }

        public static void Assert_Connect_SendReceive(
            Tls13Server server,
            Tls13Client client,
            out Tls13ClientConnectionInfo clientConnectionInfo,
            out Tls13ServerConnectionInfo serverConnectionInfo,
            int dataLengthKib = 10)
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

            var c = Task.Factory.StartNew<Tls13ServerConnectionInfo>(StartServer, new state
            {
                server = server,
                mediator = ss,
                expectedreceive = Data_10Kib
            });

            var s = Task.Factory.StartNew<Tls13ClientConnectionInfo>(StartClient, new state()
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
                Thread.Sleep(400); //maybe this need to be longer period, maybe long calculations or smt
            }

            if (c.Exception != null || s.Exception != null) Assert.Fail();

            clientConnectionInfo = s.Result;
            serverConnectionInfo = c.Result;
        }

        static Tls13ServerConnectionInfo StartServer(object state)
        {
            var st = (state as state);

            try
            {
                var tlsserver = st.server;
                var tlsstream = tlsserver.Accept(st.mediator, out var serverconnectioninfo);
                BufferForStream bufForStream = new BufferForStream(tlsstream);
                bufForStream.LoadToLength(st.expectedreceive.Length);
                tlsstream.Write(st.expectedreceive, 0, st.expectedreceive.Length);

                Assert.MemoryEqual(new Shared.Helpers.BytesRange(bufForStream.Buffer, 0, bufForStream.DataLength), st.expectedreceive);

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

            tlsstream.Write(st.expectedreceive);
            BufferForStream bufForStream = new BufferForStream(tlsstream);

            bufForStream.LoadToLength(st.expectedreceive.Length);

            Assert.MemoryEqual(new Shared.Helpers.BytesRange(bufForStream.Buffer, 0, bufForStream.DataLength), st.expectedreceive);

            return clientconnectioninfo;
        }

        public static void Assert_Connect_SendReceive(Tls13Server server, Tls13Client client, int dataLengthKib = 10)
        {
            Assert_Connect_SendReceive(server, client, out _, out _, dataLengthKib);
        }

        public static Tls13Server DefaultServer(X509CertWithKey[] certWithKey = null,
            NamedGroup[] keyExchangeGroups = null,
            int? recordSizeLimit = null,
            Func<ExtensionServerALPNSelector, ExtensionServerALPNSelector.Result> alpnSelector = null)
        {
            certWithKey = certWithKey ?? new[] { Tls13TestResources.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1 };

            var serverctx = Tls13ServerContext.Default(certWithKey);
            var config = serverctx.Config;

            if (alpnSelector != null)
            {
                config.ConfigueExtensionALPN(alpnSelector);
            }


            if (keyExchangeGroups != null)
            {
                serverctx.Config.ConfigueSupportedNamedGroupsForKeyExchange(keyExchangeGroups);
            }

            if (recordSizeLimit.HasValue) config.ConfigureExtensionRecordSizeLimit(recordSizeLimit);

            var server = new Tls13Server(serverctx);

            return server;
        }

        /// <summary>
        /// Creates default instance. If any optional parameter is not null
        /// then this parameter will be set by invoking configuration method with value for this parameter
        /// </summary>
        public static Tls13Client DefaultClient(
            NamedGroup[] supportedGroups = null,
            int? recordSizeLimit = null,
            ExtensionClientALPNConfig alpnConfig = null)
        {
            var context = Tls13ClientContext.DefaultUnsave();
            var config = context.Config;

            if (alpnConfig != null)
            {
                config.ConfigureExtensionALPN(alpnConfig);
            }

            if (supportedGroups != null)
            {
                config.ConfigueClientKeyShare(supportedGroups);
                config.ConfigueSupportedGroups(supportedGroups);
            }

            if (recordSizeLimit != null) config.ConfigueExtensionRecordSizeLimit(recordSizeLimit);

            Tls13Client client = new Tls13Client(context);

            return client;
        }
    }
}
