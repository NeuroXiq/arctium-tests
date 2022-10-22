using Arctium.Shared.Helpers;
using System;

namespace Arctium.Tests.Core.Testing
{
    public static class Assert
    {
        public static void MemoryEqual(BytesRange mem1, BytesRange mem2)
        {
            int indvalidBytesPos = -1;

            if (mem1.Length == mem2.Length)
            {
                bool byteseq = true;
                for (int i = 0; i < mem1.Length && indvalidBytesPos != -1; i++)
                {
                    bool ok = (mem1.Buffer[i + mem1.Offset] == mem2.Buffer[mem2.Offset + i]);
                    
                    if (!ok) indvalidBytesPos = i;
                }
            }

            if (indvalidBytesPos != -1)
            {
                string msg = string.Format("MemoryEqual false. Not Equal byte start at position: {0}", indvalidBytesPos);
                msg = string.Format("{0}. (offset mem1: '{1}' offset mem2: '{2}')", mem1.Offset + indvalidBytesPos, mem2.Offset + indvalidBytesPos);
                
                throw new AssertException(msg);
            }
        }

        public static void Fail()
        {
            throw new AssertException("Test failed");
        }
    }
}
