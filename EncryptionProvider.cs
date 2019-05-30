using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kryptografia
{
    abstract public class EncryptionProvider
    {
        
        protected long value;
        protected byte[] data;
        protected long maximum;
        protected int countFile;
        protected byte[] saveData;
        protected List<UInt32> Key;


        public long MaximumProgress
        {
            get {return maximum;}
        }

        public long StatusProgress
        {
            get {return value;}
        }

        protected void AddBlockComplete()
        {

            long count = countFile;
            if (count % 8 != 0)
            {
                long m = 8 - (count % 8);
                countFile = (int)count + (int)m;
                //Array.Resize(ref data,(int)(count + m));
                for (long i = count; i < count + m ; i++)
                {
                    data[i] = 48;
                }
                data[countFile - 1] = Encoding.ASCII.GetBytes(m.ToString())[0];

            }
            else
            {
                //Array.Resize(ref data,(int)(count + 8));
                for (long i = count; i < count + 8; i++)
                {
                    data[i] = 48;
                }
                data[data.Length - 1] = Encoding.ASCII.GetBytes("8")[0];
            }
        }

        public void LoadFromToFile(string name)
        {
            using (FileStream fs = new FileStream(name, FileMode.Open, FileAccess.Read))
            {
                countFile = (int)fs.Length;
                data = new byte[fs.Length + 8];
                fs.Read(data, 0, (int)fs.Length);
               
                long count = fs.Length;
                if (count % 8 == 0)
                {
                    maximum = ((int)count)/8;
                }
                else
                {
                    long m = 8 - (count % 8);
                    maximum = ((int)count + m) / 8;
                }
            }
        }

        public void SaveToFile(String filename)
        {
            int x = saveData[saveData.Length - 1] - 48;
            if (x > 8 || x < 0) x = 0;
            using (var fs = new FileStream(filename, FileMode.Create, FileAccess.Write))
            {
                fs.Write(saveData, 0, countFile - x);
            }
            Debug.WriteLine("X = {0}", x);
        }

        public void AddKey(string text)
        {
            Key = new List<UInt32>();
            int count = text.Length;
            if (count != 16)
            {
                int m = 16 - count;
                for (int i = 0; i < m; i++)
                {
                    text += 0;
                }

                byte[] array = Encoding.ASCII.GetBytes(text);
                for (int j = 0; j < array.Length; j = j + 4)
                {
                    Key.Add(0);
                }
            }
            else
            {
                byte[] array = Encoding.ASCII.GetBytes(text);
                for (int j = 0; j < array.Length; j = j + 4)
                {
                    Key.Add(0);
                }
            }
        }

        public List<UInt32> ByteToUInt32Converter(ref byte[] data)
        {
            List<UInt32> blocks = new List<uint>();
           
            for (int i = 0; i < countFile; i = i + 4)
            {
                blocks.Add(BitConverter.ToUInt32(data, i));
            }
            return blocks;
        }

        public byte[] UInt32ToByteConverter(ref List<UInt32> blocks)
        {
            byte[] data = new byte[blocks.Count * sizeof(UInt32)];
            Buffer.BlockCopy(blocks.ToArray(), 0, data, 0, data.Length);
            return data;
        }


        abstract public void Encrypt();
        abstract public void Decrypt();
    }
}

