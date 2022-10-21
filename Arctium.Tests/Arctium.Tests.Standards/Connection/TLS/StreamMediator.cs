using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Tests.Standards.Connection.TLS
{
    internal class StreamMediator : Stream
    {
        static object _lock = new object();

        public override bool CanRead => throw new NotImplementedException();

        public override bool CanSeek => throw new NotImplementedException();

        public override bool CanWrite => throw new NotImplementedException();

        public override long Length => throw new NotImplementedException();

        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public ByteBuffer writtenByA = new ByteBuffer();
        public ByteBuffer writtenByB = new ByteBuffer();

        public Stream GetA() => new StreamMediator(writtenByA, writtenByB);
        public Stream GetB() => new StreamMediator(writtenByB, writtenByA);

        ByteBuffer readFrom;
        ByteBuffer writeTo;

        public StreamMediator(ByteBuffer readFrom, ByteBuffer writeTo)
        {
            this.readFrom = readFrom;
            this.writeTo = writeTo;
        }

        public int _Read(byte[] buffer, int offset, int count)
        {
            int ex = 0;
            int readed = 0;

            while (readed == 0)
            {
                int cpy = readFrom.DataLength > count ? count : readFrom.DataLength;

                if (cpy > 0)
                {
                    MemCpy.Copy(readFrom.Buffer, 0, buffer, offset, cpy);
                    readFrom.TrimStart(cpy);
                    return cpy;
                }

                if (ex++ > 5) throw new Exception("tests -> problem with readng from stream");

                if (readed == 0) Thread.Sleep(300);
            }

            return readed;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            lock (_lock)
            {
                return _Read(buffer, offset, count);
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public void _Write(byte[] buffer, int offset, int count)
        {
            int offs = writeTo.OutsideAppend(count);
            MemCpy.Copy(buffer, offset, writeTo.Buffer, offs, count);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            lock (_lock)
            {
                _Write(buffer, offset, count);
            }
        }
    }

    public class ByteBufer
    {
    }
}
