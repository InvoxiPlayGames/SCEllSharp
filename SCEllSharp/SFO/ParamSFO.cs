using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SCEllSharp.SFO
{
    public class ParamSFO
    {
        private List<SFOKey> keys = new List<SFOKey>();

        public ParamSFO() { }

        public ParamSFO(Stream file)
        {
            file.Position = 0;

            // read the header
            uint magic = file.ReadUInt32BE();
            if (magic != 0x00505346) // "PSF"
                throw new Exception("PARAM.SFO file does not have PSF header.");
            uint version = file.ReadUInt32LE();
            if (version != 0x00000101) // 1.1
                throw new Exception("PARAM.SFO is not version 1.1.");
            uint key_start_offset = file.ReadUInt32LE();
            uint data_start_offset = file.ReadUInt32LE();
            uint num_keys = file.ReadUInt32LE();

            // enumerate through every key in the index table
            for (int i = 0; i < num_keys; i++)
            {
                SFOKey key = new SFOKey();

                // seek to the position in the index table
                file.Position = 0x14 + (i * 0x10);

                ushort key_name_offset = file.ReadUInt16LE();
                short data_fmt = file.ReadInt16LE();
                if (data_fmt != (short)SFODataFormat.UTF8 &&
                    data_fmt != (short)SFODataFormat.Int32)
                    throw new Exception("PARAM.SFO has a key that is not UTF-8 or an Int32.");
                int data_len = file.ReadInt32LE();
                int data_max = file.ReadInt32LE();
                uint data_offset = file.ReadUInt32LE();

                key.Type = (SFODataFormat)data_fmt;
                key.TotalLength = data_len;
                key.MaxLength = data_max;

                // seek to the key name position
                file.Position = key_start_offset + key_name_offset;
                key.Name = file.ReadASCIINullTerminated();

                // seek to the data position
                file.Position = data_start_offset + data_offset;
                byte[] data = file.ReadBytes(data_max);

                if (key.Type == SFODataFormat.UTF8)
                    key.UTF8String = Encoding.UTF8.GetString(data, 0, data_len - 1); // we're .NET so chop off null terminator
                else if (key.Type == SFODataFormat.Int32)
                    key.Int32Value = BitConverter.ToInt32(data);

                keys.Add(key);
            }
        }

        public SFOKey[] GetKeys() => keys.ToArray();

        public string GetStringValue(string key)
        {
            SFOKey? keyTo = keys.Find((k) => { return k.Name == key; });
            if (keyTo == null || keyTo.Type != SFODataFormat.UTF8)
                throw new Exception("Key does not exist or is not a UTF-8 string.");
            return keyTo.UTF8String!;
        }

        public int GetIntValue(string key)
        {
            SFOKey? keyTo = keys.Find((k) => { return k.Name == key; });
            if (keyTo == null || keyTo.Type != SFODataFormat.Int32)
                throw new Exception("Key does not exist or is not an int32.");
            return keyTo.Int32Value;
        }

        public void AddValue(string key, string value, int max_len)
        {
            // find an existing key and if we don't have one make one
            SFOKey? keyTo = keys.Find((k) => { return k.Name == key; });
            if (keyTo == null)
            {
                keyTo = new SFOKey();
                keys.Add(keyTo);
            }
            // set the values in our key
            keyTo.Name = key;
            keyTo.Type = SFODataFormat.UTF8;
            keyTo.TotalLength = value.Length + 1;
            keyTo.MaxLength = max_len;
            keyTo.UTF8String = value;
        }

        public void AddValue(string key, int int32)
        {
            // find an existing key and if we don't have one make one
            SFOKey? keyTo = keys.Find((k) => { return k.Name == key; });
            if (keyTo == null)
            {
                keyTo = new SFOKey();
                keys.Add(keyTo);
            }
            // set the values in our key
            keyTo.Name = key;
            keyTo.Type = SFODataFormat.Int32;
            keyTo.TotalLength = 4;
            keyTo.MaxLength = 4;
            keyTo.Int32Value = int32;
        }

        public void Write(Stream output)
        {
            long index_table_start = 0x14;
            long key_table_start = index_table_start + (keys.Count * 0x10);

            // calculate the sizes of the key and data table
            long key_table_size = 0;
            long data_table_size = 0;
            foreach(SFOKey k in keys)
            {
                key_table_size += k.Name!.Length + 1; // add space for null terminator
                data_table_size += k.MaxLength;
                if (k.MaxLength % 0x4 > 0) // hacky alignment to 0x4 bytes
                    data_table_size += 0x4 - (k.MaxLength % 0x4);
            }
            if (key_table_size % 0x4 > 0)
                key_table_size += 0x4 - (key_table_size % 0x4);
            long data_table_start = key_table_start + key_table_size;

            byte[] key_table = new byte[key_table_size];
            // might be inefficient to do it like this for larger files
            byte[] data_table = new byte[data_table_size];

            // write out the PARAM.SFO header
            output.WriteUInt32BE(0x00505346); // "PSF"
            output.WriteInt32LE(0x00000101); // 1.1
            output.WriteUInt32LE((uint)key_table_start);
            output.WriteUInt32LE((uint)data_table_start);
            output.WriteInt32LE(keys.Count);

            long key_table_used = 0;
            long data_table_used = 0;
            foreach (SFOKey k in keys)
            {
                // write out the entry in the sfo index table
                output.WriteInt16LE((short)key_table_used);
                output.WriteInt16LE((short)k.Type);
                output.WriteInt32LE(k.TotalLength);
                output.WriteInt32LE(k.MaxLength);
                output.WriteInt32LE((int)data_table_used);

                // copy the key into the key table
                byte[] key_name_bytes = Encoding.UTF8.GetBytes(k.Name!);
                Array.Copy(key_name_bytes, 0, key_table, key_table_used, key_name_bytes.Length);
                key_table_used += key_name_bytes.Length + 1; // +1 for null terminator

                // copy the data into the data table
                byte[] data_bytes = BitConverter.GetBytes(k.Int32Value);
                if (k.Type == SFODataFormat.UTF8)
                {
                    data_bytes = Encoding.UTF8.GetBytes(k.UTF8String!);
                }
                Array.Copy(data_bytes, 0, data_table, data_table_used, data_bytes.Length);
                data_table_used += k.MaxLength;
                if (k.MaxLength % 0x4 > 0) // hacky alignment to 0x4 bytes
                    data_table_used += 0x4 - (k.MaxLength % 0x4);
            }

            // write out the key and data tables
            output.Write(key_table);
            output.Write(data_table);
        }
    }
}
