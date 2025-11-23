#Extra Credit 1
import os
import random
from typing import List

from aes import AES
import fault_dfa as dfa


def recover_last_round_key(aes: AES, fault_row: int = 1, delta: int = None, pairs_per_column: int = 8, seed_base: int = 200) -> List[List[int]]:
    """Return 4x4 K10[col][row]; fault_row/delta/pairs_per_column control generation."""
    if delta is None:
        delta = random.randint(1, 255)

    K10 = [[0] * 4 for _ in range(4)]  # K10[col][row]

    for fault_col in range(4):
        seed = seed_base + fault_col
        rng = random.Random(seed)
        pairs = []
        for _ in range(pairs_per_column):
            P = bytes(rng.getrandbits(8) for _ in range(16))
            C = aes.encrypt_block(P)
            F = dfa.encrypt_block_with_fault(aes, P, fault_round=9, fault_row=fault_row, fault_col=fault_col, delta=delta)
            pairs.append((P, C, F))

        res = dfa.analyze_pairs_for_column(pairs, fault_row=fault_row, fault_col=fault_col, verbose=False)
        if not res.get('solved'):
            # add more pairs if needed
            extra_rng = random.Random(seed + 999)
            for _ in range(8):
                P = bytes(extra_rng.getrandbits(8) for _ in range(16))
                C = aes.encrypt_block(P)
                F = dfa.encrypt_block_with_fault(aes, P, fault_round=9, fault_row=fault_row, fault_col=fault_col, delta=delta)
                pairs.append((P, C, F))
                res = dfa.analyze_pairs_for_column(pairs, fault_row=fault_row, fault_col=fault_col, verbose=False)
                if res.get('solved'):
                    break

        assert res.get('solved'), f"Column {fault_col} not solved; try increasing pairs."
        kb = res['solution']['key_bytes']           # rows 0..3
        positions = res['solution']['positions']    # row -> (row, col)
        for r, byte_val in enumerate(kb):
            _, j = positions[r]
            K10[j][r] = byte_val

    return K10


def _print_key_matrix(name: str, K: List[List[int]]):
    print(name)
    for r in range(4):
        row_bytes = [K[c][r] for c in range(4)]
        print('  ' + ' '.join(f'{b:02x}' for b in row_bytes))


def demo():
    key = os.urandom(16)
    aes = AES(key)
    fault_row = 1
    delta = random.randint(1, 255)

    K10 = recover_last_round_key(aes, fault_row=fault_row, delta=delta, pairs_per_column=8)
    _print_key_matrix("Recovered last-round key (round 10):", K10)

    # Quick check
    true_K10 = aes._key_matrices[-1]
    true_bytes = [[true_K10[c][r] for r in range(4)] for c in range(4)]
    _print_key_matrix("True last-round key (from AES):", true_bytes)


if __name__ == '__main__':
    demo()
