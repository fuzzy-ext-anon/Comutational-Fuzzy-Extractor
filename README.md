# Computational Fuzzy Extractor for the Human Iris
 Fuzzy Extractor Implementation with LPN encryption and LDPC error-correcting codes.
 
# Setup
This software has been tested for Unix systems only (standard Linux distributions and MacOS).

* Install LPDC module. Instructions: https://glizen.com/radfordneal/ftp/LDPC-2012-02-11/index.html
  * Install the functions in the main directory
* Prepare the parity check and generator matrices. Run:
  * ```./alist-to-pchk NR_1_4_18.alist parity.pchk ```
  * ```./make-gen parity.pchk gen.gen dense```
* Install the python modules given in `requirements.txt`
* Create a directory "LPN_Matrices". Run `generate_matrices.py` to generate the LPN Matrices for encryption/decryption.

# Testing
## PPFE
* Run `python3 fuzzy_extractor.py`
* This tests `test.bin` against `same.bin` (code of iris from the same class), and `diff.bin` (code of iris from a different class).
## PPMR
* Generate a ciphertext file `ctxt.bin` of length 154'000'000 bytes
  * Include this file in the same directory as `PPMR_server`
* Edit the IP adresses and ports in `PPMR_server` and `PPMR_client`
* Run `python3 PPMR_server` on your first machine
* Run `python3 PPMR_client` on a different machine

# Further use
Import `FuzzyExtractor` into your python code. You may need to edit the functions to accept inputs with non-list types
