using PkcsExtensions.ASN1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PkcsExtensions.Blazor.ASN1
{
    public class X509Name : IAsn1Node
    {
        private readonly List<X509NameEntry> entries;

        public IEnumerable<X509NameEntry> Entries
        {
            get => this.entries;
        }

        public X509Name()
        {
            this.entries = new List<X509NameEntry>();
        }

        public void Add(string oid, string value)
        {
            if (oid == null) throw new ArgumentNullException(nameof(oid));
            if (value == null) throw new ArgumentNullException(nameof(value));

            this.entries.Add(new X509NameEntry(oid, value));
        }

        public void Write(AsnWriter asnWriter)
        {
            if (asnWriter == null) throw new ArgumentNullException(nameof(asnWriter));

            asnWriter.PushSequence();
            foreach (X509NameEntry entry in this.entries)
            {
                asnWriter.PushSetOf();
                asnWriter.PushSequence();
                asnWriter.WriteObjectIdentifier(entry.Oid);
                asnWriter.WriteCharacterString(UniversalTagNumber.PrintableString, entry.Value);
                asnWriter.PopSequence();
                asnWriter.PopSetOf();
            }
            asnWriter.PopSequence();
        }
    }

    public struct X509NameEntry
    {
        public string Oid
        {
            get;
        }

        public string Value
        {
            get;
        }

        public X509NameEntry(string oid, string value)
        {
            this.Oid = oid;
            this.Value = value;
        }
    }
}
