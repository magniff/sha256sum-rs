# sha256sum-rs

A straight forward implementaion of the coreutils's `sha256sum` util in Rust:
```
$ hyperfine --warmup 5 -m 20 "./target/release/sha256sum-rs data.dat"
Benchmark 1: ./target/release/sha256sum-rs data.dat
  Time (mean ± σ):      1.501 s ±  0.036 s    [User: 1.422 s, System: 0.079 s]
  Range (min … max):    1.456 s …  1.554 s    20 runs
                                                        
$ hyperfine --warmup 20 -m 50 "sha256sum data.dat"   
Benchmark 1: sha256sum data.dat
  Time (mean ± σ):      1.485 s ±  0.029 s    [User: 1.381 s, System: 0.103 s]
  Range (min … max):    1.439 s …  1.527 s    50 runs
```
