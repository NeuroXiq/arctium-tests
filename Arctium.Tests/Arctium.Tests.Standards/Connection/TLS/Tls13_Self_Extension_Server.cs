using Arctium.Tests.Core.Attributes;
using Arctium.Tests.Core.Testing;
using static Arctium.Tests.Standards.Connection.TLS.Tls13TestHelper;

namespace Arctium.Tests.Standards.Connection.TLS
{
    [TestsClass]
    internal class Tls13_Self_Extension_Server
    {
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
            int clientRecordSizeLimit = 0x1000;
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


    }
}
