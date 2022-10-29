using Arctium.Shared.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Arctium.Tests.Core.Testing
{
    public static class Assert
    {
        public static void ValuesEqual<T>(T expected, T current)
        {
            if (EqualityComparer<T>.Default.Equals(expected, current)) return;

            throw new AssertException(String.Format("Values are not equal: expected: {0}, current: {1}", expected, current));
        }

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

        public static void NotNull(object obj)
        {
            if (obj != null) return;

            throw new AssertException("Value should not be null but it is null");
        }

        public static void Fail(string info = null)
        {
            var msg = string.Format("Test failed. {0}", info ?? String.Empty);
            throw new AssertException(msg);
        }

        public static void Throws(Action p)
        {
            bool catched = false;
            
            try
            {
                p();
            }
            catch (Exception)
            {
                catched = true;
            }

            if (!catched)
            {
                throw new AssertException("Expected to throw exception but nothing throw");
            }
        }

        public static void IsTrue(bool value)
        {
            if (value) return;

            throw new AssertException("Expected to be true but is false");
        }

        public static void IsFalse(bool value)
        {
            if (!value) return;

            throw new AssertException("Expected to be false but is true");
        }

        public static void NotEmpty<T>(IEnumerable<T> array)
        {
            if (array != null && array.Any()) return;

            throw new AssertException("Not empty: Expected to be not empty but is null or empty");
        }
    }
}
