using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;

namespace Razensoft.Tests
{
    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class Benchmarks
    {
        private byte[] key = new byte[16];
        private byte[] data;
        private byte[] encrypted;

        [Params(10000, 100000)]
        public int N;

        [GlobalSetup]
        public void Setup()
        {
            data = new byte[N];
            var random = new Random(42);
            random.NextBytes(key);
            random.NextBytes(data);
            encrypted = XXTEA.Encrypt(data, key);
        }

        [Benchmark]
        [BenchmarkCategory("Encrypt")]
        public byte[] XxteaEncrypt() => XXTEA.Encrypt(data, key);

        [Benchmark]
        [BenchmarkCategory("Encrypt")]
        public byte[] XxteaDotNetEncrypt() => XXTEADotNet.Encrypt(data, key);

        [Benchmark]
        [BenchmarkCategory("Decrypt")]
        public byte[] XxteaDecrypt() => XXTEA.Decrypt(encrypted, key);

        [Benchmark]
        [BenchmarkCategory("Decrypt")]
        public byte[] XxteaDotNetDecrypt() => XXTEADotNet.Decrypt(encrypted, key);
    }
}