import numpy as np
from secrets import randbits
import time
from pathos.multiprocessing import ProcessingPool as Pool


def bitarr(i):
    r = randbits(i)
    return [int(d) for d in bin(r)[2:].zfill(i)]

def generateLPN(bits, k, ecc_len, l, counter):
    t1 = time.time()
    p = Pool()
    matrices = p.map(lambda a : np.save(f"LPN_Matrices/{a+counter}", np.array([bits(k) for _ in range(ecc_len)])), range(l))
    # np.save("LPN_Arrays/test.npy", self.lpn_matrices[0])
    t2 = time.time()
    print(f"Generated {len(matrices)} LPN matrices in {t2 - t1} seconds")

    return matrices

def main(total=1000000, step=20000):
    # End goal: generate 10^6 matrices
    # Counter starts at 0
    counter = 0
    # step = 20000
    # Generate 20000 matrices at a time and save them until we have 10^6
    while counter < total:
        matrices = generateLPN(bitarr, 43, 1224, step, counter)
        counter += step


if __name__ == "__main__":
    main(total=1000, step=200)