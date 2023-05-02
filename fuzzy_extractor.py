# IMPORTS
from math import ceil
import numpy as np
from secrets import randbits
from subprocess import check_output
import galois
from PIL import Image
import multiprocessing
import hashlib
import threading
import sys, time, random
import mx_par
import iris_dictionary


# RUNS ON PYTHON 3.8.9 +
#   (on my system its in /usr/bin/python3, with /usr/bin/pip3 package manager)


class FuzzyExtractor:

    def __init__(self, k=43, l=1000000, err=0.11, ecc_len=1224, lbd=128, xi = 128, t=12, file_prefix='', pwd_len=0):
        '''
        Specify subsample size, number of lockers. and LPN encryption error rate
        Default parameters are k=43, l=10^6, err=0.12, etc.
        '''
        self.k = k
        self.l = l
        self.error_rate = err
        self.nu = ecc_len
        self.lbd = lbd
        self.xi = xi

        # ------------
        self.t = t
        self.ecc_msg_len = t + lbd * 2 + xi

        # ------------
        self.gamma = 1 - (err * 2)
        self.dec_check = ecc_len * (0.5 - self.gamma/3)

        # Irreducible polynomial for GF(2^128)
        self.irreducible_poly = galois.primitive_poly(2, 128)

        # SHA3-512 and corresponding parameters
        self.hash = hashlib.sha3_512()
        self.L = ceil((self.hash.digest_size * 8) / self.lbd) + 4
        self.hash = hashlib.sha3_512().name
        self.bigctxt = ''

        # File prefix
        self.file_prefix = file_prefix


        # Pre-load all matrices
        t=time.time()
        self.LPN_Matrices = [np.load(f"LPN_Matrices/{index}.npy") for index in range(self.l)]
        
        print(f"Done initializing. Loaded {len(self.LPN_Matrices)} matrices in {time.time() - t} seconds...")


    def bitarr(self, i):
        r = randbits(i)
        return [int(d) for d in bin(r)[2:].zfill(i)]
    
    def read_matrix(self, index):
        return np.load(f"LPN_Matrices/{index}.npy")

    # def LPN_enc_batch(self, A)
    # * precompute the noisy msg X self.l in GEN
    # * call the batch enc function with all the LPN matrices & the subsamples
    def LPN_batch_enc(self, keys, msgs):
        # Prep the messages to encode (put each on a new line)
        t = time.time()
        with open(f'{self.file_prefix}.src', 'w') as f:
            f.writelines(msgs[0])
        print(f"Gen: Writing to file took {time.time()-t} seconds")
        # Encode message
        check_output(["./encode", "parity.pchk", "gen.gen", f"{self.file_prefix}.src", f"{self.file_prefix}.enc"])
        
        t = time.time()
        # Setup for adding errors to l encodings 
        code = []
        with open(f'{self.file_prefix}.enc', 'r') as f:
            code = f.read().strip()
        code = [code+'\n'] * self.l
        
        with open(f'{self.file_prefix}.enc', 'w') as f:
            f.writelines(code)
        print(f"Gen: File IO for adding noise took {time.time()-t} seconds")

        t = time.time()
        # Adding errors
        # check_output(["./transmit", "e.enc", "r.rec", f"{randbits(32)}", "bsc", f"{self.error_rate}"])
        check_output(["bash", "ldpc_enc_batch.bash", f"-s {randbits(12)}", f"-e {self.error_rate}", "-f", self.file_prefix])
        print(f"Gen: Adding noise took {time.time()-t} seconds")
        

        t = time.time()
        # Reading noisy codes
        with open(f'{self.file_prefix}.rec', 'r') as f:
            noisy_msg = f.readlines()

        # Transform the str output to a binary vector
        messages = [np.array([int(b) for b in nm.strip()], dtype=np.uint8) for nm in noisy_msg]
        print(f"Gen: Reading noisy messages and type-casting to np arrays took {time.time()-t} seconds")
        
        # Multiply LPN matrices by the LPN keys (subsamples of iris code)
        t = time.time()
        ctxt = mx_par.gen_helper(self.LPN_Matrices, keys, messages)
        print(f"Computed {len(ctxt)} ciphertexts in {time.time() - t} seconds")

        return ctxt


    def LPN_dec_batch(self, As, keys, ctxts, process):
    # def LPN_dec_batch(self, d, process):
        '''
        Decypts a batch of ciphertexts in one call
        '''

        t = time.time()
        # multiply LPN matrix by the key
        d = [(As[i] @ keys[i]) % 2 ^ ctxts[i] for i in range(len(ctxts))]
        # print(f"Rep: Process {process} matrix mult in {time.time() - t} seconds")

        # Add (mod 2) d and ctxt (assuming ctxt is a numpy array)
        tmp = ''
        for i in d:
            for j in i:
                tmp += str(j)

        # print(f'Testing LPN_dec_batch. Process id: {process}\n temp: {len(tmp)}')
        
        # Encode temp into a bitstring
        input_file_name = f'{self.file_prefix}-{process}.rec'
        with open(input_file_name, 'w') as f:
            f.write(tmp)
        
        t1 = time.time()
        # Call LDPC code (C) and decode temp
        decoded = check_output(["bash", "ldpc_dec_batch.bash", f"-c {input_file_name}", f"-e {self.error_rate}", "-p", str(process), "-f", self.file_prefix])
        decoded = decoded.decode("ASCII").split("\n")
        details, test = [i.split() for i in decoded[1:-3]], decoded[-3]

        # print(f"Rep: Process {process} decoded in {time.time() - t1} seconds")
        # print(f'Testing LPN_dec_batch. Process id: {process}\n bash script output:',details)
        if (test.split()[3]) == '0':
            # print(f'Testing LPN_dec_batch. Process id: {process}. All invalid...')
            return np.array([]) # Invalid decryption
        
        print(f'Rep: Testing LPN_dec_batch. Process id: {process}. Found valid decoding!')
        valid_msg_index = -1
        for i in details:
            # Layout of i: [index_of_msg, num_of_iterations, valid/invalid (0/1), change%]; 
            if i[2] == '1':
                valid_msg_index = int(i[0])
                break
        

        output_file_name = f'{self.file_prefix}-{process}.ext'
        with open(output_file_name, 'r') as f:
            out = f.readlines()

        decoded = out[valid_msg_index].strip()
        
        g_i = np.array([int(b) for b in decoded], dtype=np.uint8)
        return g_i
    

    def LPN_dec_batch_serial(self, d, process):
        '''
        Decypts a batch of ciphertexts in one call
        '''
        t = time.time()
        # Add (mod 2) d and ctxt (assuming ctxt is a numpy array)
        tmp = ''
        for i in d:
            for j in i:
                tmp += str(j)
        print(f"Rep serial: Took {time.time() - t} seconds to convert messages to string")

        # print(f'Testing LPN_dec_batch. Process id: {process}\n temp: {len(tmp)}')
        
        t = time.time()
        # Encode temp into a bitstring
        input_file_name = f'{self.file_prefix}-{process}.rec'
        with open(input_file_name, 'w') as f:
            f.write(tmp)
        print(f"Rep serial: Created .rec file in {time.time() - t} seconds")
        
        t1 = time.time()
        # Call LDPC code (C) and decode temp
        decoded = check_output(["bash", "ldpc_dec_batch.bash", f"-c {input_file_name}", f"-e {self.error_rate}", "-p", str(process), "-f", self.file_prefix])
        decoded = decoded.decode("ASCII").split("\n")
        details, test = [i.split() for i in decoded[1:-3]], decoded[-3]
        print(f"Rep serial: Decoded in {time.time() - t1} seconds")

        # print(f'Testing LPN_dec_batch. Process id: {process}\n bash script output:',details)
        if (test.split()[3]) == '0':
            # print(f'Testing LPN_dec_batch. Process id: {process}. All invalid...')
            return np.array([]) # Invalid decryption
        
        print(f'Rep: Testing LPN_dec_batch. Process id: {process}. Found valid decoding!')
        valid_msg_index = -1
        for i in details:
            # Layout of i: [index_of_msg, num_of_iterations, valid/invalid (0/1), change%]; 
            if i[2] == '1':
                valid_msg_index = int(i[0])
                break
        

        output_file_name = f'{self.file_prefix}-{process}.ext'
        with open(output_file_name, 'r') as f:
            out = f.readlines()

        decoded = out[valid_msg_index].strip()
        
        g_i = np.array([int(b) for b in decoded], dtype=np.uint8)
        return g_i
    
    

    def mac(self, key, ciphertexts):
        t = time.time()
        h = hashlib.new(self.hash)

        if not self.bigctxt: self.bigctxt = str(ciphertexts)
        bigctxt = self.bigctxt

        # Generate a digest of entire ciphertexts
        bigctxt = bigctxt.encode()
        h.update(bigctxt)
        bigctxt = h.hexdigest()
        bigctxt = bin(int(bigctxt, base=16))[2:].zfill(512)

        # Encode digest into vector m
        m = [galois.Poly.Int(int(bigctxt[i:i+self.lbd], base=2)) for i in range(0, len(bigctxt), self.lbd)]

        # split key into x and y
        x = galois.Poly.Int(int(key[:self.lbd], base=2))
        y = galois.Poly.Int(int(key[self.lbd:], base=2))

        mx = mx_par.mx_serial(m, x, self.L-4, self.irreducible_poly) 

        T_rep = (pow(x, self.L, self.irreducible_poly) + (pow(x, 2, self.irreducible_poly) * mx) + (x * y)) % self.irreducible_poly
        
        print(f'Calculated MAC in {time.time() - t} seconds')

        return T_rep
        


    # w is the input string (iris encoding), n is the iris mask (used for sampling unmasked bits)
    def gen(self, w, n, pwd=np.array([], dtype='B')):
        # step 1: generate R and R_1
        R = bin(randbits(self.xi))[2:].zfill(self.xi)
        R_1 = bin(randbits(self.lbd * 2))[2:].zfill(self.lbd * 2)

        to_enc = (R + R_1).zfill(self.ecc_msg_len)

        # Generate l sets of unmasked positions 
        t = time.time()
        self.positions = [ random.SystemRandom().sample(np.flatnonzero(n).tolist(), k=self.k) for _ in range(self.l) ]
        print(f"Generating sample positions: {time.time() - t} sec ")
        samples = []
        # step 2: start a loop
        for i in range(self.l):
            # Get a sample of w at positions
            sample_i = np.array([w[pos] for pos in self.positions[i]], dtype=np.uint8)
            samples.append(np.concatenate((sample_i, pwd)))


        t = time.time()
        self.ctexts = self.LPN_batch_enc(samples, [to_enc for _ in range(self.l)])
        print(f"Generating ciphertexts + LDPC calls: {time.time() - t} sec ")

        self.T = self.mac(R_1, self.ctexts) 

        # step 7: Output key R, self.ctexts, and self.T
        return R
        
    # # w is W' in the paper, ciphertext and T can be found in self.ctexts and self.T respectively
    def rep_serial(self, w, pwd=np.array([], dtype='B')):
        #PARALLEL, TEST ONLY
        samples = []

        for i in range(self.l):
            # Get a sample of w at positions
            sample_i = np.array([w[pos] for pos in self.positions[i]], dtype=np.uint8)
            samples.append(np.concatenate((sample_i,pwd)))
    
        split = np.array_split(range(self.l), 100)

        
        for slice in split:
            m_slice = []
            k_slice = []
            c_slice = []
            for i in slice:
                m_slice.append(self.LPN_Matrices[i])
                k_slice.append(samples[i])
                c_slice.append(self.ctexts[i])

            t = time.time()
            d = mx_par.rep_helper(
                matrices = m_slice,
                keys = k_slice,
                ciphertexts=c_slice
            )
            print(f"Decrypting 10'000 ciphertexts: {time.time() - t} sec ")

            t = time.time()
            dec = self.LPN_dec_batch_serial(d, process=0)
            print(f"Decoding 10'000 ciphertexts: {time.time() - t} sec ")

            if len(dec) > 0: print(dec[:15])

            # STEP iv
            if not (len(dec) == 0 or dec[:self.t].any()): # i.e., if dec is not None
                R = ''
                for c in dec[self.t:self.t + self.xi]:
                    R += str(c)
                
                R_1 = ''
                for c in dec[self.t + self.xi:]:
                    R_1 += str(c)

                T_rep = self.mac(R_1, self.ctexts)

                if T_rep == self.T:
                    print("Check passed")
                    # with lock:
                    return R
        return
                    


    # w is W' in the paper, ciphertext and T can be found in self.ctexts and self.T respectively
    def rep_parallel(self, w, pwd=np.array([], dtype='B'), num_processes=1):
        # finished = multiprocessing.Array('b', False)
        a = np.array_split(range(self.l), 1000)
        b = np.array_split(range(1000), num_processes)

        finished = multiprocessing.Manager().list([None for _ in range(num_processes)])
        processes = []
        for x in range(num_processes):
            p = multiprocessing.Process(
                target=self.rep_process, 
                args=(w, [a[i] for i in b[x]], finished, x, pwd)
            )
            processes.append(p)
            p.start()
        for p1 in processes:
            p1.join()
        if any(finished):
            print("Rep succeeded")
            return next(item for item in finished if item is not None)
        print("Rep failed")

    
    def rep_process(self, w_, arr_of_indices, finished, process_id, pwd):
    # def rep_process(self, w_, arr_of_indices, finished, process_id, d):
        for indices in arr_of_indices:
            if any(finished):
                # print("One of the other threads returned")
                return 

            samples = []
            matrices = []
            ctxts = []
            for i in indices:
                sample_i = np.array([w_[pos] for pos in self.positions[i]], dtype=np.uint8)
                samples.append(np.concatenate((sample_i, pwd)))
                matrices.append(self.LPN_Matrices[i])
                ctxts.append(self.ctexts[i])
            # d_slice = [d[i] for i in indices]
            
            dec = self.LPN_dec_batch(matrices, samples, ctxts, process_id)
            # dec = self.LPN_dec_batch(d_slice, process_id)

            if len(dec) > 0: print(dec[:15])

            # STEP iv
            if not (len(dec) == 0 or dec[:self.t].any()): # i.e., if dec is not None
                R = ''
                for c in dec[self.t:self.t + self.xi]:
                    R += str(c)
                
                R_1 = ''
                for c in dec[self.t + self.xi:]:
                    R_1 += str(c)

                T_rep = self.mac(R_1, self.ctexts)

                if T_rep == self.T:
                    print("Check passed")
                    # with lock:
                    finished[process_id] = R
                    return
        
        return



def img_opener(path, mask=False):
    ''' 
    INPUTS:
    `path`: String - Path to an image to be opened
    `mask`: Boolean - Optional flag to indicate whether the image is a mask
    OUTPUT: Flattened (1D) NumPy array of bits.
    Depending on `mask`, this is either just one or six array(s) of length 512 x 64
    '''
    image = Image.open(path)
    data = np.asarray(image) % 2 # map everything to 0 or 1 since it's B&W values (0 or 255)
    if mask:
        return data.flatten()
    else:
        return [data[i:i+64].flatten() for i in range(0, 384, 64)]


def main(first, toTest):
    mask1 = f"./NEWOutput/NormalizedMasks/{first}_mano.bmp"
    code1 = f"./NEWOutput/IrisCodes/{first}_code.bmp"

    m1 = img_opener(mask1, mask=True)
    c1 = [ m1 & c for c in img_opener(code1) ] # XOR all 6 codes (one per Gabor filter pair) with mask here

    PASSWORD_LENGTH = 0
    PASSWORD = np.random.default_rng().integers(low=0, high=1, endpoint=True, size=(PASSWORD_LENGTH), dtype=np.uint8)
    print(f"Password: {PASSWORD}")

    print("Testing ", first)
    t1 = time.time()
    fe = FuzzyExtractor(l=1_000_000, file_prefix=first, pwd_len=PASSWORD_LENGTH)
    t2 = time.time()
    print(f"Initialized (generated lpn arrays & GF(2^128)) in {t2 - t1} seconds")

    # HACK ACCORDING TO FULLERS PAPER (SECTION 4), TRANSFORM #5 HAS THE BEST RATE FOR IMAGES OF SAME IRIS
    a = fe.gen(
        c1[5],
        m1, 
        pwd=PASSWORD
    )
    t3 = time.time()
    print(f"Ran GEN in {t3 - t2} seconds")

    results = []

    for t in toTest:
        maskt = f"./NEWOutput/NormalizedMasks/{t}_mano.bmp"
        codet = f"./NEWOutput/IrisCodes/{t}_code.bmp"

        mt = img_opener(maskt, mask=True)
        ct = [ mt & c for c in img_opener(codet) ] # XOR all 6 codes (one per Gabor filter pair) with mask here

        t1 = time.time()
        b = fe.rep_parallel(
            ct[5], 
            pwd=PASSWORD, 
            num_processes=multiprocessing.cpu_count() // 3
        )
        # b = fe.rep_parallel(ct[5], num_processes=multiprocessing.cpu_count())
        results.append(b)
        t2 = time.time()
        print(f"Ran REP parallel in {t2 - t1} seconds")




    print(a)
    print(results)


    print("no problems so far")


if __name__ == '__main__':

    # keys = ['04423', '04692', '04857', '04633', '04311', '04347', '04613', '04747', '04632', '04233', '04754', '04876', '04556', '04821', '04730', '04603', '04461', '04703', '04823', '04320', '04890', '04622', '04225', '04763', '04557', '04670', '04810', '04892', '04239', '04916', '04748', '04922', '04843', '04598', '04697', '04349', '04418', '04727', '04907', '04871', '04286', '04888', '04816', '04813', '04725', '04615', '04302', '04689', '04496', '04481', '04853', '04585', '04831', '04893', '04855', '04701', '04904', '04387', '04476', '04838', '04889', '04883', '04827', '04327', '04848', '04673', '04343', '04580', '04509', '04460', '04767', '04774', '04924', '04427', '04866', '04878', '04911', '04863', '04344', '04880', '04797', '04309', '04910', '04470', '04851', '04840', '04724', '04600', '04896', '04934', '04881', '04400', '04869', '04297', '04626', '04839', '04846', '04339', '04768', '04873', '04882', '04803', '04933', '04434', '04449', '04850', '04581', '04683', '04684', '04482', '04514', '04301', '04495', '04914', '04885', '04609', '04811', '04786', '04867', '04350', '04341', '04745', '04596', '04213', '04542', '04629', '04900', '04477', '04505', '04379', '04841', '04530', '04388', '04628', '04738', '04473', '04588', '04587', '04682', '04447', '04872', '04463', '04404', '04849', '04936', '04472', '04324', '04901', '04798', '04511', '04734', '04265', '04334', '04829', '04370', '04815', '04891', '04446', '04765', '04715', '04921', '04719', '04776', '04744', '04711', '04905', '04842', '04833', '04854', '04667', '04456', '04899', '04884', '04419', '04915', '04743', '04336', '04488', '04699', '04312', '04708', '04407', '04372', '04385', '04202', '04201', '04453', '04261', '04898', '04749', '04928', '04894', '02463', '04531', '04772', '04338', '04773', '04822', '04430', '04702', '04319', '04731', '04777', '04647', '04726', '04917', '04709', '04870', '04887', '04691', '04760', '04830', '04631', '04436', '04429', '04493', '04675', '04790', '04451', '04782', '04868', '04485', '04203', '04714', '04716', '04593', '04758', '04475', '04865', '04351', '04221', '04537', '04284', '04847', '04408', '04507', '04757', '04796']

    # input_key = sys.argv[1]

    # key = keys[int(input_key)]

    # irises = iris_dictionary.big_dict[key]

    gen_iris = "04560d631"

    # rep_irises = ["04857d138", "04857d136", "04857d196"]
    rep_irises = ['04854d278', '04854d279', '04854d280', '04855d100', '04855d101', '04855d102', '04853d320', '04853d321', '04853d322', '04850d196', '04850d197', '04850d198', '04851d1000', '04851d1001', '04851d1002', '04907d883', '04907d884', '04907d885', '04786d565', '04786d566', '04786d567', '04312d952', '04312d953', '04312d954', '04782d570', '04782d571', '04782d572', '04418d414', '04418d415', '04418d416', '04419d382', '04419d383', '04419d384', '04731d149', '04731d150', '04731d151', '04730d1005', '04730d1006', '04730d1007', '04734d217', '04734d218', '04734d219', '04738d169', '04738d170', '04738d171', '04647d409', '04647d410', '04647d411', '04609d217', '04609d218', '04609d219', '04351d110', '04351d111', '04351d112', '04350d456', '04350d457', '04350d458', '04600d377', '04600d378', '04600d379', '04813d280', '04813d281', '04813d282', '04810d141', '04810d142', '04810d143', '04811d246', '04811d247', '04811d248', '04816d076', '04816d077', '04816d078', '04815d349', '04815d350', '04815d351']

    print(gen_iris, rep_irises)

    main(first=gen_iris, toTest=rep_irises)
    # main(first=gen_iris, toTest=[])

    # check_output(["rm", f"{gen_iris}*"])


