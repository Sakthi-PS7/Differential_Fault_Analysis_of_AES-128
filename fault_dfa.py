import os
import random
import statistics
from typing import List, Tuple, Dict, Set
 

# Use the provided AES 
from aes import AES, bytes2matrix, matrix2bytes, inv_s_box, sub_bytes, shift_rows, mix_columns, add_round_key

def gf_mul2(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF

def gf_mul3(a: int) -> int:
    return gf_mul2(a) ^ (a & 0xFF)

def alpha_vector(fault_row: int) -> List[int]:
    # This returns the four constants used for MixColumns for the chosen row
    if fault_row == 0:
        return [0x02, 0x01, 0x01, 0x03]
    elif fault_row == 1:
        return [0x03, 0x02, 0x01, 0x01]
    elif fault_row == 2:
        return [0x01, 0x03, 0x02, 0x01]
    else:
        return [0x01, 0x01, 0x03, 0x02]


def encrypt_block_with_fault(aes: "AES", plaintext: bytes, *, fault_round=9, fault_row=0, fault_col=0, delta=None) -> bytes:
    assert len(plaintext) == 16
    state = bytes2matrix(plaintext)
    add_round_key(state, aes._key_matrices[0])

    for i in range(1, aes.n_rounds):
        sub_bytes(state)
        shift_rows(state)
        if delta is not None and i == fault_round:
            assert 0 <= fault_row < 4 and 0 <= fault_col < 4
            state[fault_col][fault_row] ^= (delta & 0xFF)
        mix_columns(state)
        add_round_key(state, aes._key_matrices[i])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, aes._key_matrices[-1])
    return matrix2bytes(state)


def generate_pairs(key: bytes, n: int, *, fault_row: int, fault_col: int, delta: int, seed: int = 1337) -> List[Tuple[bytes, bytes, bytes]]:
    assert len(key) in AES.rounds_by_key_size
    assert 0 <= fault_row < 4 and 0 <= fault_col < 4
    assert 1 <= delta <= 0xFF

    rng = random.Random(seed)
    aes = AES(key)
    out = []
    for _ in range(n):
        P = bytes(rng.getrandbits(8) for _ in range(16))
        C = aes.encrypt_block(P)
        F = encrypt_block_with_fault(aes, P, fault_round=9, fault_row=fault_row, fault_col=fault_col, delta=delta)
        out.append((P, C, F))
    return out


def analyze_pairs_for_column(pairs: List[Tuple[bytes, bytes, bytes]], *, fault_row: int, fault_col: int, verbose: bool = True) -> Dict[str, object]:
    assert pairs, "No pairs provided"
    alpha = alpha_vector(fault_row)
    j_for_row = {r: (fault_col - r) % 4 for r in range(4)}

    # Initializing candidates: for each delta value, make four sets of 0..255
    delta_sets: Dict[int, List[Set[int]]] = {}
    for d in range(1, 256):
        delta_sets[d] = [set(range(256)) for _ in range(4)]
    pairs_used = None

    for idx, (_, C, F) in enumerate(pairs, 1):
        Cmat, Fmat = bytes2matrix(C), bytes2matrix(F)
        for d, sets_per_row in list(delta_sets.items()):
            for r in range(4):
                # decide which multiple of delta we are expecting
                if alpha[r] == 0x02:
                    req = gf_mul2(d)
                elif alpha[r] == 0x03:
                    req = gf_mul3(d)
                else:
                    req = d

                j = j_for_row[r]
                Cb, Fb = Cmat[j][r], Fmat[j][r]
                newset = set()
                for k in sets_per_row[r]:
                    yC = inv_s_box[Cb ^ k]
                    yF = inv_s_box[Fb ^ k]
                    if (yC ^ yF) == req:
                        newset.add(k)
                sets_per_row[r] = newset

        # remove deltas that can't work anymore
        bad_list = []
        for d, s in delta_sets.items():
            for rowset in s:
                if len(rowset) == 0:
                    bad_list.append(d)
                    break
        for d in bad_list:
            delta_sets.pop(d, None)

        if verbose:
            per_row_sizes = []
            for r in range(4):
                sizes_here = [len(s[r]) for s in delta_sets.values()]
                if sizes_here:
                    per_row_sizes.append((min(sizes_here), max(sizes_here)))
                else:
                    per_row_sizes.append((0, 0))
            plural = '' if idx == 1 else 's'
            print(f"After {idx} pair{plural}: remaining Δ = {len(delta_sets)}; per-row candidate sizes = {per_row_sizes}")

        if len(delta_sets) == 1 and all(len(s) == 1 for s in next(iter(delta_sets.values()))):
            pairs_used = idx
            break

    result = {"solved": False, "solution": None, "delta_candidates": list(delta_sets.keys()), "pairs_used": pairs_used}
    if len(delta_sets) == 1:
        d, sets_per_row = next(iter(delta_sets.items()))
        if all(len(s) == 1 for s in sets_per_row):
            key_bytes = [next(iter(s)) for s in sets_per_row]
            result["solved"] = True
            result["solution"] = {
                "delta": d,
                "key_bytes": key_bytes,
                "positions": {r: (r, j_for_row[r]) for r in range(4)},
            }
            if verbose:
                print(f"Solved with Δ = 0x{d:02x}")
                for r, kb in enumerate(key_bytes):
                    rr, cc = result['solution']['positions'][r]
                    print(f"  key byte at (row {rr}, col {cc}) is 0x{kb:02x}")
    return result


def last_round_key_bytes_for_column(aes, fault_col: int) -> List[Tuple[int, int, int]]:
    K = aes._key_matrices[-1]
    out = []
    for r in range(4):
        j = (fault_col - r) % 4
        out.append((r, j, K[j][r]))
    return out

def batch_trials(key, fault_row, fault_col, delta, trials=20, pairs_per_trial=16, seed_base=100):
    # This runs several times to see how many pairs we are usually needing
    pairs_needed = []
    for t in range(trials):
        seed = seed_base + t
        pairs = generate_pairs(key, pairs_per_trial, fault_row=fault_row, fault_col=fault_col, delta=delta, seed=seed)
        res = analyze_pairs_for_column(pairs, fault_row=fault_row, fault_col=fault_col, verbose=False)
        used = res.get('pairs_used', None)
        if used is None:
            # try to find how many pairs were actually enough
            for i in range(1, pairs_per_trial + 1):
                solved_now = analyze_pairs_for_column(pairs[:i], fault_row=fault_row, fault_col=fault_col, verbose=False).get('solved')
                if solved_now:
                    used = i
                    break
        if used is None:
            used = pairs_per_trial
        pairs_needed.append(used)

    print("Trials:", trials)
    median_val = int(statistics.median(pairs_needed)) if pairs_needed else 0
    print("Pairs needed — min/median/max:", f"{min(pairs_needed)} / {median_val} / {max(pairs_needed)}")
    return pairs_needed

def demo_run():
    key = os.urandom(16)
    aes = AES(key)
    fault_row = 1
    fault_col = 2
    delta = random.randint(1, 255)

    total_pairs = 8  # generate a moderate number of pairs
    pairs_all = generate_pairs(key, total_pairs, fault_row=fault_row, fault_col=fault_col, delta=delta, seed=42)

    print("Showing target last-round key bytes (row, col, value):")
    for (r, j, kb) in last_round_key_bytes_for_column(aes, fault_col):
        print(f"  row {r}, col {j} -> 0x{kb:02x}")

    res = analyze_pairs_for_column(pairs_all, fault_row=fault_row, fault_col=fault_col, verbose=True)
    if res.get("solved"):
        print("\nRecovering with provided pairs.")
    else:
        print("\nNot getting a unique result with provided pairs.")

    # Showing how many pairs we are needing on average
    print("\nBatch trials: seeing how many pairs we are needing on average:")
    batch_trials(key, fault_row, fault_col, delta, trials=20, pairs_per_trial=9)


if __name__ == '__main__':
    demo_run()
