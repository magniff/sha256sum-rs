# sha256sum-rs

Hardware-accelerated SHA-256 checksum utility for the x86_64 architecture.

```
$ hyperfine --warmup 30 -m 20 "./target/release/sha256sum-rs data.dat"
Benchmark 1: ./target/release/sha256sum-rs data.dat
  Time (mean ± σ):     467.8 ms ±  12.9 ms    [User: 311.8 ms, System: 155.3 ms]
  Range (min … max):   450.2 ms … 501.9 ms    20 runs

$ hyperfine --warmup 30 -m 20 "openssl sha256 data.dat"
Benchmark 1: openssl sha256 data.dat
  Time (mean ± σ):     477.3 ms ±  11.3 ms    [User: 288.9 ms, System: 187.9 ms]
  Range (min … max):   461.8 ms … 499.3 ms    20 runs

$ hyperfine --warmup 30 -m 20 "sha256sum data.dat"
Benchmark 1: sha256sum data.dat
  Time (mean ± σ):      1.598 s ±  0.029 s    [User: 1.384 s, System: 0.212 s]
  Range (min … max):    1.557 s …  1.640 s    20 runs
```

The code have been written during that coding session: https://youtu.be/SPvcIjRUg5Q?si=GlXsbQYXNAk-QLRm
