# Imports
import galois
from multiprocessing.pool import ThreadPool as Pool
import multiprocessing
import numpy as np

import time


def generateLPN(bits, k, ecc_len, l):
    t1 = time.time()
    p = Pool()
    matrices = p.map(lambda a : np.array([bits(k) for _ in range(ecc_len)]), range(l))
    
    t2 = time.time()
    print(f"Generated {len(matrices)} LPN matrices in {t2 - t1} seconds")

    return matrices


def mx_parallel(fm, fx, fL, poly):
    t1 = time.time()
    p = Pool()
    results = p.map(lambda a : pow(fx, a, poly) * fm[a], range(fL))
    t2 = time.time()
    s = galois.Poly.Int(0)
    for i in results:
        s = s + i
    s = s % poly
    print(f"Parallel m with {p.ncpus} workers took {time.time() - t1} seconds. {t2-t1} for map, {time.time() - t2} for sum")
    # p.close()
    return s


def mx_serial(fm, fx, fL, poly):
    s = galois.Poly.Int(0)
    for i in range(fL):
        s = (s + (pow(fx, i, poly) * fm[i])) % poly
    
    return s

def f(i):
    '''
    Gen/Rep helper's helper lol
    '''
    a, b, m = i
    return ((a @ b) % 2) ^ m

def gen_helper(matrices, keys, messages):
    '''
    Takes the matrix read fuction, # of lockers, and the iris subsamples
    Returns l products of matrix and subsample (binary vectors)
    '''

    t1 = time.time()
    p = Pool(processes=multiprocessing.cpu_count() // 3)

    d = p.map(f, zip(matrices, keys, messages))

    p.close()
    p.join()
    t2 = time.time()

    
    print(f"Parallel took {t2-t1} seconds")

    return d

def rep_helper(matrices, keys, ciphertexts):
    '''
    Takes the matrices, keys, and ciphertexts
    Performs multiplies matrix with key and XORs with ciphertext
    '''

    t1 = time.time()
    p = Pool()

    d = p.map(f, zip(matrices, keys, ciphertexts))

    p.close()
    p.join()
    t2 = time.time()

    
    print(f"Parallel took {t2-t1} seconds")

    return d