using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kryptografia
{
    class TeaEncryption : EncryptionProvider
    {
        public override void Decrypt()
        {
            List<UInt32> descryptblocks = new List<uint>();

            List<UInt32> blocks = ByteToUInt32Converter(ref data);

            for (int i = 0; i < blocks.Count; i=i+2)
            {
                uint sum;
                uint v0 = blocks[i];
                uint v1 = blocks[i+1];
                uint delta = 0x9e3779b9;

                sum = delta << 5;

                for(int j = 0;j<32;j++)
                {
                    v1 -= (v0 << 4 ^ v0 >> 5) + v0 ^ sum + Key[(int)sum >> 11 & 3];
                    sum -= delta;
                    v0 -= (v1 << 4 ^ v1 >> 5) + v1 ^ sum + Key[(int)sum & 3];
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

            List<UInt32> encryptblocks = new List<uint>();
           
            List<UInt32> blocks = ByteToUInt32Converter(ref data);
            
            for (int i = 0; i < blocks.Count; i += 2)
            {
                uint sum = 0;
                uint v0 = blocks[i];
                uint v1 = blocks[i+1];
                uint delta = 0x9e3779b9;

                for (int j = 0; j < 32; j++)
                {
                    v0 += (v1 << 4 ^ v1 >> 5) + v1 ^ sum + Key[(int)sum & 3];
                    sum += delta;
                    v1 += (v0 << 4 ^ v0 >> 5) + v0 ^ sum + Key[(int)sum >> 11 & 3];
                }

                encryptblocks.Add(v0);
                encryptblocks.Add(v1);

                value++;
            }
            saveData = UInt32ToByteConverter(ref encryptblocks);
        }
    }
}
