using System;

namespace Arctium.Tests.Core.Testing
{
    public class AssertException : Exception
    {
        public AssertException(string msg) : base(msg)
        {
            
        }

        public AssertException() : this (String.Empty)
        {
        }
    }
}
