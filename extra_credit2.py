#Extra Credit 2
from typing import List

from aes import AES, s_box, r_con, bytes2matrix
import extra_credit1 as ec1
import os
import random


def rot_word(word: List[int]) -> List[int]:
    return word[1:] + word[:1]


def sub_word(word: List[int]) -> List[int]:
    return [s_box[b] for b in word]


def g_func(word: List[int], rcon_val: int) -> List[int]:
    w = rot_word(word)
    w = sub_word(w)
    w[0] ^= rcon_val
    return w


def xor_words(a: List[int], b: List[int]) -> List[int]:
    return [(x ^ y) & 0xFF for x, y in zip(a, b)]


def invert_from_last_round(K10: List[List[int]]) -> bytes:
    """
    Given K10[col][row], compute the AES‑128 master key (16 bytes).
    """
    # Build words W[40..43] from K10 columns
    W = [None] * 44  # 44 words of 4 bytes
    for i in range(4):
        # K10[i] is a column (4 rows)
        W[40 + i] = [K10[i][r] for r in range(4)]

    # Walk rounds backward: r = 10 down to 1
    for r in range(10, 0, -1):
        b = 4 * r
        V0, V1, V2, V3 = W[b], W[b + 1], W[b + 2], W[b + 3]
        # U3 = W[b-1] = V3 ^ V2
        U3 = xor_words(V3, V2)
        U2 = xor_words(V2, V1)
        U1 = xor_words(V1, V0)
        # U0 = W[b-4] = V0 ^ g(U3) with rcon[r]
        U0 = xor_words(V0, g_func(U3, r_con[r]))
        W[b - 4], W[b - 3], W[b - 2], W[b - 1] = U0, U1, U2, U3

    # Master key is words W[0..3]
    master_cols = W[0:4]
    # Convert to bytes in matrix order: columns then rows
    key_bytes = bytes(sum(([c[r] for r in range(4)] for c in master_cols), []))
    return key_bytes


def demo():
    key = os.urandom(16)
    aes = AES(key)
    fault_row = 1
    delta = random.randint(1, 255)

    # Recover last-round key first (EC1)
    K10 = ec1.recover_last_round_key(aes, fault_row=fault_row, delta=delta, pairs_per_column=8)
    # Invert schedule to get master key
    recovered_master = invert_from_last_round(K10)

    print("Recovered master key:", recovered_master.hex())
    print("True master key     :", key.hex())

    # Quick check: expand recovered_master and compare
    aes2 = AES(recovered_master)
    ok = all(aes2._key_matrices[-1][c][r] == K10[c][r] for c in range(4) for r in range(4))
    print("Round-10 key matches:", ok)


if __name__ == '__main__':
    demo()
