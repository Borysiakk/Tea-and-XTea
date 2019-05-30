using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kryptografia
{
    class XTeaEncryption : EncryptionProvider
    {
        public UInt32 Rounds {get;set;}
        public XTeaEncryption(UInt32 rounds = 32)
        {
            Rounds = rounds;
        }

        public override void Decrypt()
        {
            List<UInt32> descryptblocks = new List<UInt32>();
            List<UInt32> blocks = ByteToUInt32Converter(ref data);

            for (int i = 0; i < blocks.Count; i = i + 2)
            {
                uint sum;
                UInt32 v0 = blocks[i];
                UInt32 v1 = blocks[i + 1];
                uint delta = 0x9e3779b9;

                sum = delta * Rounds;

                for (int j = 0; j < Rounds; j++)
                {

                    v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + Key[((int)sum >> 11) & 3]);
                    sum -= delta;
                    v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + Key[(int)sum & 3]);
                }

                descryptblocks.Add(v0);
                descryptblocks.Add(v1);

                value++;
            }
            saveData = UInt32ToByteConverter(ref descryptblocks);
        }

        public override void Encrypt()
        {
            AddBlockComplete();

            List<UInt32> encryptblocks = new List<UInt32>();

            List<UInt32> blocks = ByteToUInt32Converter(ref data);

            for (int i = 0; i < blocks.Count; i += 2)
            {
                uint sum = 0;
                UInt32 v0 = blocks[i];
                UInt32 v1 = blocks[i + 1];
                uint delta = 0x9e3779b9;

                for (int j = 0; j < Rounds; j++)
                {
                    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + Key[(int)sum & 3]);
                    sum += delta;
                    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + Key[((int)sum >> 11) & 3]);
                }

                encryptblocks.Add(v0);
                encryptblocks.Add(v1);

                value++;
            }
            saveData = UInt32ToByteConverter(ref encryptblocks);
        }
    }
}
