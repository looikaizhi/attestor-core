
``` bash
sudo apt update
sudo apt install -y \
  build-essential \
  cmake \
  python3 \
  python3-pip \
  pkg-config

npm install
npm run download:zk-files
npm run run:tsc -- src/benchmarks/run.ts

```

### Bandwidth sweep (25ms latency, 1KB req, 4KB res)

``` bash
# defaults: iface=lo, tls=TLS1_3, kind=snarkjs, bandwidths=10/50/100/250/1000 Mbps, runsPerBandwidth=10
npm run run:tsc -- src/benchmarks/prover-bench-bandwidth.ts [TLS_VERSION] [gnark|snarkjs|wasm]

# optional overrides
BENCH_IFACE=lo BENCH_LATENCY_MS=25 BENCH_REQUEST_BYTES=1024 BENCH_RESPONSE_BYTES=4096 BENCH_USE_IPTABLES=1 BENCH_CSV=benchmarks/prover-bench-bandwidth.csv npm run run:tsc -- src/benchmarks/prover-bench-bandwidth.ts
```

### Latency sweep (1 Gbps, 1KB req, 4KB res)

``` bash
# defaults: iface=lo, bandwidth=1000 Mbps, latencies=10/25/50/100/200 ms, runsPerLatency=10
npm run run:tsc -- src/benchmarks/prover-bench-latency.ts [TLS_VERSION] [gnark|snarkjs|wasm]

# optional overrides
BENCH_IFACE=lo BENCH_BANDWIDTH_MBPS=1000 BENCH_LATENCIES_MS=10,25,50,100,200 BENCH_REQUEST_BYTES=1024 BENCH_RESPONSE_BYTES=4096 BENCH_RUNS=5 BENCH_CSV=benchmarks/prover-bench-latency.csv npm run run:tsc -- src/benchmarks/prover-bench-latency.ts
```

### Response-size sweep (200 Mbps, 10 ms, 2KB req)

```bash
# defaults: response sizes 1KB/2KB/4KB/8KB/16KB/32KB/64KB/128KB, runsPerResponse=10
npm run run:tsc -- src/benchmarks/prover-bench-response.ts [TLS_VERSION] [gnark|snarkjs|wasm]

# optional overrides
BENCH_IFACE=lo BENCH_BANDWIDTH_MBPS=200 BENCH_LATENCY_MS=10 BENCH_REQUEST_BYTES=2048 BENCH_RESPONSE_SIZES=1024,2048,4096,8192,16384,32768,65536,131072 BENCH_RUNS=10 BENCH_WARMUP=3 BENCH_CSV=benchmarks/prover-bench-response.csv npm run run:tsc -- src/benchmarks/prover-bench-response.ts
```
