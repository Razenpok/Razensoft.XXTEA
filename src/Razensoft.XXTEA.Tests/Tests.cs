using System;
using System.Linq;
using FluentAssertions;
using NUnit.Framework;

namespace Razensoft.Tests
{
    public class Tests
    {
        private const string Key = "3GU45RUJR58xHub9";
        private const string Data = "Lorem ipsum dolor sit amet";
        private const string EncodedHex = "955748C89F385B6F5DE92530FA281DFE9EDE0407AAD8DB07B3A1FA8E00E4D2D6";

        private static readonly byte[] KeyBytes =
        {
            51, 71, 85, 52, 53, 82, 85, 74, 82, 53, 56, 120, 72, 117, 98, 57
        };

        private static readonly byte[] DataBytes =
        {
            76, 111, 114, 101, 109, 32, 105, 112, 115, 117, 109, 32, 100,
            111, 108, 111, 114, 32, 115, 105, 116, 32, 97, 109, 101, 116
        };

        [Test]
        public void Should_encrypt_string_using_string_key()
        {
            var encrypted = XXTEA.Encrypt(Data, Key);
            var hex = ByteArrayToHex(encrypted);
            hex.Should().Be(EncodedHex);

            var instance = new XXTEA(Key);
            encrypted = instance.Encrypt(Data);
            hex = ByteArrayToHex(encrypted);
            hex.Should().Be(EncodedHex);

            var refEncrypted = XXTEADotNet.Encrypt(Data, Key);
            var refHex = ByteArrayToHex(refEncrypted);
            hex.Should().Be(refHex);
        }

        [Test]
        public void Should_encrypt_string_using_byte_key()
        {
            var encrypted = XXTEA.Encrypt(Data, KeyBytes);
            var hex = ByteArrayToHex(encrypted);
            hex.Should().Be(EncodedHex);

            var instance = new XXTEA(KeyBytes);
            encrypted = instance.Encrypt(Data);
            hex = ByteArrayToHex(encrypted);
            hex.Should().Be(EncodedHex);

            var refEncrypted = XXTEADotNet.Encrypt(Data, KeyBytes);
            var refHex = ByteArrayToHex(refEncrypted);
            hex.Should().Be(refHex);
        }

        [Test]
        public void Should_encrypt_bytes_using_string_key()
        {
            var encrypted = XXTEA.Encrypt(DataBytes, Key);
            var hex = ByteArrayToHex(encrypted);
            hex.Should().Be(EncodedHex);

            var instance = new XXTEA(Key);
            encrypted = instance.Encrypt(DataBytes);
            hex = ByteArrayToHex(encrypted);
            hex.Should().Be(EncodedHex);

            var refEncrypted = XXTEADotNet.Encrypt(DataBytes, Key);
            var refHex = ByteArrayToHex(refEncrypted);
            hex.Should().Be(refHex);
        }

        [Test]
        public void Should_encrypt_bytes_using_byte_key()
        {
            var encrypted = XXTEA.Encrypt(DataBytes, KeyBytes);
            var hex = ByteArrayToHex(encrypted);
            hex.Should().Be(EncodedHex);

            var instance = new XXTEA(KeyBytes);
            encrypted = instance.Encrypt(DataBytes);
            hex = ByteArrayToHex(encrypted);
            hex.Should().Be(EncodedHex);

            var refEncrypted = XXTEADotNet.Encrypt(DataBytes, KeyBytes);
            var refHex = ByteArrayToHex(refEncrypted);
            hex.Should().Be(refHex);
        }

        [Test]
        public void Should_decrypt_bytes_using_string_key()
        {
            var bytes = HexToByteArray(EncodedHex);
            var decrypted = XXTEA.Decrypt(bytes, Key);
            decrypted.Should().ContainInConsecutiveOrder(DataBytes);

            var instance = new XXTEA(Key);
            decrypted = instance.Decrypt(bytes);
            decrypted.Should().ContainInConsecutiveOrder(DataBytes);

            var refDecrypted = XXTEADotNet.Decrypt(bytes, Key);
            decrypted.Should().ContainInConsecutiveOrder(refDecrypted);
        }

        [Test]
        public void Should_decrypt_bytes_using_byte_key()
        {
            var bytes = HexToByteArray(EncodedHex);
            var decrypted = XXTEA.Decrypt(bytes, KeyBytes);
            decrypted.Should().ContainInConsecutiveOrder(DataBytes);

            var instance = new XXTEA(KeyBytes);
            decrypted = instance.Decrypt(bytes);
            decrypted.Should().ContainInConsecutiveOrder(DataBytes);

            var refDecrypted = XXTEADotNet.Decrypt(bytes, KeyBytes);
            decrypted.Should().ContainInConsecutiveOrder(refDecrypted);
        }

        [Test]
        public void Should_decrypt_string_using_string_key()
        {
            var bytes = HexToByteArray(EncodedHex);
            var decrypted = XXTEA.DecryptString(bytes, Key);
            decrypted.Should().Be(Data);

            var instance = new XXTEA(Key);
            decrypted = instance.DecryptString(bytes);
            decrypted.Should().Be(Data);

            var refDecrypted = XXTEADotNet.DecryptToString(bytes, Key);
            decrypted.Should().Be(refDecrypted);
        }

        [Test]
        public void Should_decrypt_string_using_byte_key()
        {
            var bytes = HexToByteArray(EncodedHex);
            var decrypted = XXTEA.DecryptString(bytes, KeyBytes);
            decrypted.Should().Be(Data);

            var instance = new XXTEA(KeyBytes);
            decrypted = instance.DecryptString(bytes);
            decrypted.Should().Be(Data);

            var refDecrypted = XXTEADotNet.DecryptToString(bytes, KeyBytes);
            decrypted.Should().Be(refDecrypted);
        }

        [Test]
        public void Should_fail_to_decrypt_invalid_input()
        {
            const string encodedHex = "5748C89F385B6F5DE92530FA281DFE9EDE0407AAD8DB07B3A1FA8E00E4D2D6";
            var bytes = HexToByteArray(encodedHex);

            Action act = () => XXTEA.DecryptString(bytes, KeyBytes);
            act.Should().Throw<Exception>();

            var instance = new XXTEA(KeyBytes);
            act = () => instance.DecryptString(bytes);
            act.Should().Throw<Exception>();

            act = () => XXTEADotNet.DecryptToString(bytes, KeyBytes);
            act.Should().Throw<Exception>();
        }

        [Test]
        public void Should_be_able_to_encrypt_zero_bytes()
        {
            var bytes = Array.Empty<byte>();
            const string expected = "";

            var encrypted = XXTEA.Encrypt(bytes, Key);
            var hex = ByteArrayToHex(encrypted);
            hex.Should().Be(expected);

            var instance = new XXTEA(Key);
            encrypted = instance.Encrypt(bytes);
            hex = ByteArrayToHex(encrypted);
            hex.Should().Be(expected);

            var refEncrypted = XXTEADotNet.Encrypt(bytes, Key);
            var refHex = ByteArrayToHex(refEncrypted);
            hex.Should().Be(refHex);
        }

        [Test]
        public void Should_be_able_to_decrypt_zero_bytes()
        {
            var bytes = Array.Empty<byte>();
            const string expected = "";

            var decrypted = XXTEA.Decrypt(bytes, Key);
            var hex = ByteArrayToHex(decrypted);
            hex.Should().Be(expected);

            var instance = new XXTEA(Key);
            decrypted = instance.Decrypt(bytes);
            hex = ByteArrayToHex(decrypted);
            hex.Should().Be(expected);

            var refDecrypted = XXTEADotNet.Decrypt(bytes, Key);
            var refHex = ByteArrayToHex(refDecrypted);
            hex.Should().Be(refHex);
        }

        [Test]
        public void Random_test()
        {
            for (var i = 0; i < 2048; i++)
            {
                var random = new Random();
                var data = new byte[i];
                random.NextBytes(data);
                var key = new byte[16];
                random.NextBytes(key);

                var encrypted = XXTEA.Encrypt(data, key);
                var refEncrypted = XXTEADotNet.Encrypt(data, key);

                if (!encrypted.SequenceEqual(refEncrypted))
                {
                    Assert.Fail("Encryption implementation mismatch for input:" +
                                $" DATA = {ByteArrayToHex(data)}," +
                                $" KEY = {ByteArrayToHex(key)}");
                }

                var decrypted = XXTEA.Decrypt(encrypted, key);
                var refDecrypted = XXTEADotNet.Decrypt(encrypted, key);

                if (!decrypted.SequenceEqual(refDecrypted))
                {
                    Assert.Fail("Decryption implementation mismatch for input:" +
                                $" DATA = {ByteArrayToHex(data)}," +
                                $" KEY = {ByteArrayToHex(key)}");
                }

                if (!decrypted.SequenceEqual(data))
                {
                    Assert.Fail("Encryption reversal is incorrect for input:" +
                                $" DATA = {ByteArrayToHex(data)}," +
                                $" KEY = {ByteArrayToHex(key)}");
                }
            }
        }

        private static string ByteArrayToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-","");
        }

        public static byte[] HexToByteArray(string hex) {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }
    }
}