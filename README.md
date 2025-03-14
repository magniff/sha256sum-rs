# sha256sum-rs

A straight forward implementaion of the coreutils's `sha256sum` util in Rust:
```
# the Rust code been built w/ PGO:
$ hyperfine --warmup 20 -m 50 "./target/x86_64-unknown-linux-gnu/release/sha256sum-rs data.dat"
Benchmark 1: ./target/x86_64-unknown-linux-gnu/release/sha256sum-rs data.dat
  Time (mean ± σ):      1.448 s ±  0.018 s    [User: 1.374 s, System: 0.073 s]
  Range (min … max):    1.434 s …  1.499 s    50 runs
                                                        
$ hyperfine --warmup 20 -m 50 "sha256sum data.dat"   
Benchmark 1: sha256sum data.dat
  Time (mean ± σ):      1.485 s ±  0.029 s    [User: 1.381 s, System: 0.103 s]
  Range (min … max):    1.439 s …  1.527 s    50 runs
```
