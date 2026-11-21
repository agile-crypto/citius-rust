# Phases 0–2, before and after (2026-11-20, macOS arm64)

`before`: perf-study at 0cf822a (main 0abdc52 + benches). `after`: improve/hot-path
at 9bb1d53 + benches (this branch). Same machine, same session, one side after the other.

- `allocs-*`: `cargo bench --features bench --bench allocs`
- `baselines-*`: `cargo bench --features bench --bench baselines -- 10 100`
- `c-latency-*`: `cargo xtask bench --only latency`
- `c-threads-*`: `cargo xtask bench --only threads`
