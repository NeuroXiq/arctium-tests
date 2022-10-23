using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Tests.Standards.Connection.TLS
{
    /// <summary>
    /// Very easy to get deadlock (lock on read/write buffer), now seems to works
    /// </summary>
    internal class StreamMediator : Stream
    {
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

        public StreamMediator GetA() => new StreamMediator(writtenByA, writtenByB);
        public StreamMediator GetB() => new StreamMediator(writtenByB, writtenByA);

        ByteBuffer readFrom;
        ByteBuffer writeTo;
        private bool abortFatalException = false;

        public StreamMediator(ByteBuffer readFrom, ByteBuffer writeTo)
        {
            this.readFrom = readFrom;
            this.writeTo = writeTo;
        }

        public void AbortFatalException()
        {
            this.abortFatalException = true;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int ex = 0;
            int readed = 0;
            int timeout = 500;
            if (Debugger.IsAttached) timeout = 111111111;

            while (true)
            {
                if (abortFatalException) throw new Exception("aborted everyting, fatal exception");

                // need to release lock right after read, can't hold because of deadlock (maybe other thread want to write into 'readFrom' buffer)
                lock (readFrom)
                {
                    int cpy = readFrom.DataLength > count ? count : readFrom.DataLength;

                    if (cpy > 0)
                    {
                        MemCpy.Copy(readFrom.Buffer, 0, buffer, offset, cpy);
                        readFrom.TrimStart(cpy);
                        return cpy;
                    }
                }

                if (ex++ > 500) throw new Exception("tests -> problem with reading from stream");
                if (readed == 0) Thread.Sleep(10);
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
            int offs = writeTo.MallocAppend(count);
            MemCpy.Copy(buffer, offset, writeTo.Buffer, offs, count);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (abortFatalException) throw new Exception("aborted everyting, fatal exception");

            lock (writeTo)
            {
                _Write(buffer, offset, count);
            }
        }
    }

    public class ByteBufer
    {
    }
}
