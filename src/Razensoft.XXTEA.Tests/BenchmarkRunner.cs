using BenchmarkDotNet.Configs;

namespace Razensoft.Tests
{
    public class BenchmarkRunner
    {
        public static void Run()
        {
            BenchmarkDotNet.Running.BenchmarkRunner.Run<Benchmarks>(
                ManualConfig
                    .Create(DefaultConfig.Instance)
                    .WithOptions(ConfigOptions.DisableOptimizationsValidator)
            );
        }
    }
}