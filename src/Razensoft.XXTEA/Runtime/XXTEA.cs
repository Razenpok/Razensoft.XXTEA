using System;
using System.Text;
using JetBrains.Annotations;

namespace Razensoft
{
    public sealed class XXTEA
    {
        [NotNull]
        private static UTF8Encoding UTF8NoBom => new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true
        );

        [NotNull]
        private readonly uint[] _key;

        public XXTEA([NotNull] string key)
        {
            key = key ?? throw new ArgumentNullException(nameof(key));
            _key = FixKey(key);
        }

        public XXTEA([NotNull] byte[] key)
        {
            key = key ?? throw new ArgumentNullException(nameof(key));
            _key = FixKey(key);
        }

        [NotNull]
        public byte[] Encrypt([NotNull] string data)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            return Encrypt(UTF8NoBom.GetBytes(data));
        }

        [NotNull]
        public byte[] Encrypt([NotNull] byte[] data)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            return Encrypt(data, _key);
        }

        [NotNull]
        public static byte[] Encrypt([NotNull] string data, [NotNull] byte[] key)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            key = key ?? throw new ArgumentNullException(nameof(key));
            return Encrypt(UTF8NoBom.GetBytes(data), key);
        }

        [NotNull]
        public static byte[] Encrypt([NotNull] byte[] data, [NotNull] string key)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            key = key ?? throw new ArgumentNullException(nameof(key));
            return Encrypt(data, UTF8NoBom.GetBytes(key));
        }

        [NotNull]
        public static byte[] Encrypt([NotNull] string data, [NotNull] string key)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            key = key ?? throw new ArgumentNullException(nameof(key));
            return Encrypt(UTF8NoBom.GetBytes(data), UTF8NoBom.GetBytes(key));
        }

        [NotNull]
        public static byte[] Encrypt([NotNull] byte[] data, [NotNull] byte[] key)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            key = key ?? throw new ArgumentNullException(nameof(key));
            return Encrypt(data, FixKey(key));
        }

        [NotNull]
        private static byte[] Encrypt([NotNull] byte[] data, [NotNull] uint[] key)
        {
            if (data.Length == 0)
            {
                return data;
            }

            var v = ToUInt32Array(data, true);
            var encrypted = Encrypt(v, key);
            return ToByteArray(encrypted, false);
        }

        [NotNull]
        public string DecryptString([NotNull] byte[] data)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            return UTF8NoBom.GetString(Decrypt(data));
        }

        [NotNull]
        public byte[] Decrypt([NotNull] byte[] data)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            return Decrypt(data, _key);
        }

        [NotNull]
        public static byte[] Decrypt([NotNull] byte[] data, [NotNull] byte[] key)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            key = key ?? throw new ArgumentNullException(nameof(key));
            return Decrypt(data, FixKey(key));
        }

        [NotNull]
        public static byte[] Decrypt([NotNull] byte[] data, [NotNull] string key)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            key = key ?? throw new ArgumentNullException(nameof(key));
            return Decrypt(data, UTF8NoBom.GetBytes(key));
        }

        [NotNull]
        public static string DecryptString([NotNull] byte[] data, [NotNull] byte[] key)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            key = key ?? throw new ArgumentNullException(nameof(key));
            return UTF8NoBom.GetString(Decrypt(data, key));
        }

        [NotNull]
        public static string DecryptString([NotNull] byte[] data, [NotNull] string key)
        {
            data = data ?? throw new ArgumentNullException(nameof(data));
            key = key ?? throw new ArgumentNullException(nameof(key));
            return UTF8NoBom.GetString(Decrypt(data, key));
        }

        [NotNull]
        private static byte[] Decrypt([NotNull] byte[] data, [NotNull] uint[] key)
        {
            if (data.Length == 0)
            {
                return data;
            }

            var v = ToUInt32Array(data, false);
            var decrypted = Decrypt(v, key);
            return ToByteArray(decrypted, true);
        }

        [NotNull]
        private static uint[] FixKey([NotNull] string key)
        {
            return FixKey(UTF8NoBom.GetBytes(key));
        }

        [NotNull]
        private static uint[] FixKey([NotNull] byte[] key)
        {
            var fixedKey = new uint[4];
            Buffer.BlockCopy(key, 0, fixedKey, 0, 16);
            return fixedKey;
        }

        [NotNull]
        private static uint[] Encrypt([NotNull] uint[] v, [NotNull] uint[] k)
        {
            const uint delta = 0x9E3779B9;
            var n = v.Length - 1;
            if (n < 1)
            {
                return v;
            }

            var z = v[n];
            uint sum = 0;
            var q = 6 + 52 / (n + 1);
            unchecked
            {
                while (0 < q--)
                {
                    sum += delta;
                    var e = (sum >> 2) & 3;
                    uint y;
                    int p;
                    for (p = 0; p < n; p++)
                    {
                        y = v[p + 1];
                        z = v[p] += MX(sum, y, z, p, e, k);
                    }

                    y = v[0];
                    z = v[n] += MX(sum, y, z, p, e, k);
                }
            }

            return v;
        }

        [NotNull]
        private static uint[] Decrypt([NotNull] uint[] v, [NotNull] uint[] k)
        {
            const uint delta = 0x9E3779B9;
            var n = v.Length - 1;
            if (n < 1)
            {
                return v;
            }

            var y = v[0];
            var q = 6 + 52 / (n + 1);
            unchecked
            {
                var sum = (uint) (q * delta);
                while (sum != 0)
                {
                    var e = (sum >> 2) & 3;
                    uint z;
                    int p;
                    for (p = n; p > 0; p--)
                    {
                        z = v[p - 1];
                        y = v[p] -= MX(sum, y, z, p, e, k);
                    }

                    z = v[n];
                    y = v[0] -= MX(sum, y, z, p, e, k);
                    sum -= delta;
                }
            }

            return v;
        }

        [NotNull]
        private static uint[] ToUInt32Array([NotNull] byte[] data, bool includeLength)
        {
            var length = data.Length;
            var n = (length & 3) == 0 ? length >> 2 : (length >> 2) + 1;
            uint[] result;
            if (includeLength)
            {
                result = new uint[n + 1];
                result[n] = (uint) length;
            }
            else
            {
                result = new uint[n];
            }

            Buffer.BlockCopy(data, 0, result, 0, length);
            return result;
        }

        [NotNull]
        private static byte[] ToByteArray([NotNull] uint[] data, bool includeLength)
        {
            var n = data.Length << 2;
            if (includeLength)
            {
                var m = (int) data[data.Length - 1];
                n -= 4;
                if (m < n - 3 || m > n)
                {
                    throw new Exception("Input data is invalid");
                }

                n = m;
            }

            var result = new byte[n];
            Buffer.BlockCopy(data, 0, result, 0, n);
            return result;
        }

        private static uint MX(uint sum, uint y, uint z, int p, uint e, [NotNull] uint[] k)
        {
            return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
        }
    }
}
