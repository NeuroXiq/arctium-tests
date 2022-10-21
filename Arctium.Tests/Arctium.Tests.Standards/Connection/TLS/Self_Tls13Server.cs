using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Tests.Core.Attributes;
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
            var serverCtx = Tls13ServerContext.DefaultUnsafe(new[] { Tls13TestResources.CERT_WITH_KEY_CERT1_RSA_SIG_sha256RSA });
            var server = new Tls13Server(serverCtx);

            StreamMediator medit = new StreamMediator(null, null);

            var cs = medit.GetA();
            var ss = medit.GetB();

            //cm.stream = sm;
            //sm.stream = cm;

            var c = Task.Factory.StartNew(state =>
            {
                server.Accept((state as state).mediator);
                var x = "";
            }, new state
            {
                mediator = ss
            });

            var s = Task.Factory.StartNew(state =>
            {
                client.Connect((state as state).mediator);

                var x = "";
            }, new state()
            {
                mediator = cs
            });

            c.Wait();
            s.Wait();
        }

        class state
        {
            public Stream mediator;
        }

        [TestMethod]
        public void AcceptSimplestConnection_ECC_Certificate()
        {

        }

        [TestMethod]
        public void AcceptAllSupportedCipherSuites()
        {

        }

        [TestMethod]
        public void AcceptAllSupportedSignatureAlgorithms()
        {

        }

        [TestMethod]
        public void AcceptWithPskSessionResumptionTicket()
        {

        }

        static Tls13Client DefaultClient()
        {
            var context = Tls13ClientContext.DefaultUnsave();

            Tls13Client client = new Tls13Client(context);

            return client;
        }
    }
}
