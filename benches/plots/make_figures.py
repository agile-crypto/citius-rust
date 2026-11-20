"""Figures for presenting docs/performance.md. Data copied from the doc's tables
(sources named per figure). Run: python3 benches/plots/make_figures.py
(needs matplotlib); writes docs/perf-figures/*.png."""
import os
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = os.path.join(os.path.dirname(__file__), "../../docs/perf-figures")
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"  # validated slots 1-3
INK, INK2, MUTED, GRID, AXIS, SURF = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"
plt.rcParams.update({
    "font.family": "sans-serif", "font.sans-serif": ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
    "font.size": 11, "axes.edgecolor": AXIS, "axes.labelcolor": INK2, "xtick.color": MUTED, "ytick.color": INK2,
    "axes.facecolor": SURF, "figure.facecolor": SURF, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.spines.top": False, "axes.spines.right": False, "axes.titlelocation": "left", "axes.titlesize": 14,
    "axes.titlecolor": INK, "legend.frameon": False, "axes.axisbelow": True,
})


def save(fig, name):
    fig.tight_layout(rect=(0, 0.04, 1, 1))  # room for a footnote
    fig.savefig(os.path.join(OUT, name), dpi=200)
    plt.close(fig)


def signing():
    # §2.1 / F4 (interleaved for ECDSA): µs per 1 KiB signature.
    rows = [("Ed25519", 32.6, 67.5, 70.1), ("ECDSA P-256", 69.2, 190.5, 194.4), ("ECDSA P-384", 172.3, 485.9, 491.0),
            ("ECDSA P-521", 129.1, 339.1, 365.8), ("ML-DSA-44", 205.4, 294.2, 297.0),
            ("ML-DSA-65", 331.8, 483.7, 491.9), ("ML-DSA-87", 372.4, 614.1, 614.1)]
    fig, ax = plt.subplots(figsize=(10, 4.8))
    for i, (name, l0, l0p, ffi) in enumerate(reversed(rows)):
        parts = [(l0, BLUE), (l0p - l0, ORANGE), (max(ffi - l0p, 0), AQUA)]
        left = 0
        for w, c in parts:
            ax.barh(i, w, left=left, height=0.55, color=c, edgecolor=SURF, linewidth=2)
            left += w
        ax.text(left + 8, i, f"{ffi:.0f} µs  ({ffi / l0:.1f}× RustCrypto)", va="center", color=INK2, fontsize=10)
    ax.set_yticks(range(len(rows)), [r[0] for r in reversed(rows)])
    ax.set_xlabel("µs per signature (1 KiB message)")
    ax.set_xlim(0, 820)
    ax.grid(axis="y", visible=False)
    ax.set_title("Signing: most of the overhead is re-parsing the key on every call")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=BLUE, label="RustCrypto signature"), Patch(color=ORANGE, label="key parsed per call (F1)"),
                       Patch(color=AQUA, label="our orchestration + FFI")],
              loc="upper left", bbox_to_anchor=(0, -0.14), ncol=3)
    save(fig, "1-signing.png")


def symmetric():
    # §2.2: added µs over RustCrypto, AES-256-GCM. enc: L2ffi - L0; dec: L2 - L0.
    sizes = [32, 1024, 16384, 1048576]
    enc = [5.04 - 1.32, 5.65 - 1.84, 13.29 - 9.38, 531 - 521]
    dec = [2.05 - 0.10, 3.05 - 0.60, 16.49 - 8.11, 930 - 518]
    fig, ax = plt.subplots(figsize=(10, 4.8))
    for ys, c, lab in [(enc, BLUE, "encrypt"), (dec, ORANGE, "decrypt")]:
        ax.plot(sizes, ys, color=c, lw=2, marker="o", ms=7, mec=SURF, mew=2, label=lab)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(sizes, ["32 B", "1 KiB", "16 KiB", "1 MiB"])
    ax.set_ylabel("time added over RustCrypto (µs)")
    ax.text(40, 5.2, "encrypt: a fixed ~4 µs per call (F3)", color=INK2, fontsize=10)
    ax.text(700000, dec[3], "decrypt: +0.4 ms/MiB for wiping\nthe plaintext (F2)  ", color=INK2, fontsize=10,
            ha="right", va="center")
    ax.set_title("AES-256-GCM: a fixed cost per call; decryption adds a wipe that grows with size")
    ax.legend(loc="upper left")
    save(fig, "2-symmetric-overhead.png")


def stack():
    # F12: KiB of stack via agc_* (release); the gray row is RustCrypto with the key parsed once,
    # what fixing F1 would give.
    rows = [("AES-GCM encrypt", 10, BLUE), ("Ed25519 / ECDSA sign", 12, BLUE), ("first use of P-521", 128, BLUE),
            ("ML-DSA-44 sign", 221, BLUE), ("ML-DSA-65 sign", 287, BLUE), ("ML-DSA-87 sign", 507, BLUE),
            ("ML-DSA-87 sign, key cached (F1)", 120, MUTED), ("ML-DSA-87 create key", 631, BLUE)]
    fig, ax = plt.subplots(figsize=(10, 5))
    n = len(rows)
    for i, (name, kib, c) in enumerate(reversed(rows)):
        ax.barh(i, kib, height=0.55, color=c)
        ax.text(kib + 8, i, f"{kib} KiB", va="center", color=INK2, fontsize=10)
    for x, lab in [(128, "musl default\n128 KiB"), (512, "macOS default\n512 KiB")]:
        ax.axvline(x, color=INK2, lw=1)
        ax.text(x + 6, n - 0.45, lab, color=INK2, fontsize=9.5, va="bottom")
    ax.set_yticks(range(n), [r[0] for r in reversed(rows)])
    ax.set_ylim(-0.6, n + 0.6)
    ax.set_xlabel("stack needed (KiB)")
    ax.set_xlim(0, 760)
    ax.grid(axis="y", visible=False)
    ax.set_title("Stack: ML-DSA outgrows default thread stacks", pad=12)
    fig.text(0.01, 0.01, "Operations that do not fit now run on a helper thread (~25–45 µs) instead of crashing. "
             "Gray: RustCrypto with the key parsed once.", color=MUTED, fontsize=9)
    save(fig, "3-stack.png")


def threads():
    # F7, C harness on macOS M4 Pro (8 performance + 4 efficiency cores): throughput relative to 1 thread.
    t = [1, 2, 4, 8, 12]
    fig, ax = plt.subplots(figsize=(10, 4.8))
    ax.plot(t, t, color=AXIS, lw=1.5, label="ideal")
    series = [("Ed25519 sign 1 KiB, own key", [1, 1.99, 3.97, 7.84, 9.09], BLUE),
              ("AES-GCM 32 B, own key", [1, 1.96, 3.80, 5.38, 5.15], ORANGE),
              ("AES-GCM 32 B, shared key", [1, 1.88, 3.58, 4.68, 4.91], AQUA)]
    for lab, ys, c in series:
        # The two AES lines end too close for end labels: the value rides in the legend.
        ax.plot(t, ys, color=c, lw=2, marker="o", ms=7, mec=SURF, mew=2, label=f"{lab}: {ys[-1]:.1f}× at 12")
    ax.set_xticks(t)
    ax.set_xlim(0.5, 12.5)
    ax.set_xlabel("threads on one context")
    ax.set_ylabel("throughput relative to 1 thread")
    ax.set_title("Threads: small operations stop scaling at ~5× (shared locks, malloc, getentropy)")
    fig.text(0.01, 0.01, "One context, macOS M4 Pro (8 performance + 4 efficiency cores).", color=MUTED, fontsize=9)
    ax.legend(loc="upper left")
    save(fig, "4-thread-scaling.png")


def tail():
    # F10, benches/tail.rs: ML-DSA-65 sign, per-call percentiles (µs).
    q = ["p50", "p90", "p99", "p99.9"]
    l0 = [262, 673, 1370, 2023]
    ours = [425, 837, 1443, 2038]
    fig, ax = plt.subplots(figsize=(10, 4.8))
    x = range(len(q))
    ax.plot(x, l0, color=BLUE, lw=2, marker="o", ms=7, mec=SURF, mew=2, label="RustCrypto, key parsed once")
    ax.plot(x, ours, color=ORANGE, lw=2, marker="o", ms=7, mec=SURF, mew=2, label="via agc_sign")
    ax.text(3.08, 2030, "~2 ms", va="center", color=INK2, fontsize=10)
    ax.set_xticks(list(x), q)
    ax.set_xlim(-0.3, 3.5)
    ax.set_ylabel("µs per signature")
    ax.set_title("ML-DSA-65 signing: the tail is the algorithm's, not ours")
    fig.text(0.01, 0.01, "FIPS 204 signs in a retry loop with a random number of rounds; "
             "we add ~160 µs at p50/p90 (key parsing, F1) and almost nothing at p99.9.", color=MUTED, fontsize=9)
    ax.legend(loc="upper left")
    save(fig, "5-mldsa-tail.png")


def small_encrypt():
    # F7 profile, 1 thread: where the 4.8 µs of a 32-byte AES-256-GCM agc_encrypt go.
    parts = [("malloc / free (~100 allocations)", 1.54), ("getentropy (nonce syscall)", 1.22),
             ("other: lookups, metadata, FFI", 0.88), ("repository read locks", 0.46),
             ("copying key, policy, template", 0.41), ("AES-256-GCM itself", 0.31)]
    fig, ax = plt.subplots(figsize=(10, 4.4))
    for i, (name, us) in enumerate(reversed(parts)):
        c = BLUE if name.startswith("AES") else AXIS
        ax.barh(i, us, height=0.55, color=c)
        ax.text(us + 0.03, i, f"{us:.2f} µs", va="center", color=INK2, fontsize=10)
    ax.set_yticks(range(len(parts)), [p[0] for p in reversed(parts)])
    ax.set_xlabel("µs per call (profile shares × 4.82 µs)")
    ax.set_xlim(0, 1.9)
    ax.grid(axis="y", visible=False)
    ax.set_title("A 32-byte encrypt: the cryptography is 6 % of the call")
    save(fig, "6-small-encrypt.png")


def verify():
    # §2.5, interleaved: verify time relative to RustCrypto with the public key parsed once.
    rows = [("Ed25519", 1.14), ("ECDSA P-256", 1.01), ("ECDSA P-384", 0.99), ("ECDSA P-521", 1.07),
            ("ML-DSA-44", 2.4), ("ML-DSA-65", 2.7), ("ML-DSA-87", 3.1)]
    fig, ax = plt.subplots(figsize=(10, 4.4))
    for i, (name, r) in enumerate(reversed(rows)):
        c = BLUE if name.startswith("ML") else AXIS
        ax.barh(i, r, height=0.55, color=c)
        ax.text(r + 0.04, i, f"{r:.2f}×", va="center", color=INK2, fontsize=10)
    ax.axvline(1, color=INK2, lw=1)
    ax.set_yticks(range(len(rows)), [r[0] for r in reversed(rows)])
    ax.set_xlabel("verify time relative to RustCrypto (1× = as fast)")
    ax.set_xlim(0, 3.5)
    ax.grid(axis="y", visible=False)
    ax.set_title("Verification: only ML-DSA pays, for decoding the public key on every call")
    save(fig, "7-verify.png")


def binary_size():
    # F11: stripped, static, dead-stripped C client (MiB).
    rows = [("RustCrypto only: AES-GCM", 0.31, AXIS), ("RustCrypto only: same algorithms", 0.94, AXIS),
            ("citius: one AEAD encrypt", 2.20, BLUE), ("citius: every operation", 2.27, BLUE)]
    fig, ax = plt.subplots(figsize=(10, 3.8))
    for i, (name, mib, c) in enumerate(reversed(rows)):
        ax.barh(i, mib, height=0.55, color=c)
        ax.text(mib + 0.03, i, f"{mib:.2f} MiB", va="center", color=INK2, fontsize=10)
    ax.set_yticks(range(len(rows)), [r[0] for r in reversed(rows)])
    ax.set_xlabel("stripped size of a statically linked C client (MiB)")
    ax.set_xlim(0, 2.7)
    ax.grid(axis="y", visible=False)
    ax.set_title("Binary size: every client carries every algorithm (chosen at run time)")
    save(fig, "8-binary-size.png")


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    signing()
    symmetric()
    stack()
    threads()
    tail()
    small_encrypt()
    verify()
    binary_size()
