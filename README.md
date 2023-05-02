# Computational Fuzzy Extractor for the Human Iris
 Fuzzy Extractor Implementation with LPN encryption and LDPC error-correcting codes.
 
# How To Run
This software has been tested for Unix systems only (standard Linux distributions and MacOS).

* Install LPDC module. Instructions: https://glizen.com/radfordneal/ftp/LDPC-2012-02-11/index.html
  * Install the functions in the main directory
* Prepare the parity check and generator matrices. Run:
  * ```./alist-to-pchk NR_1_4_18.alist parity.pchk ```
  * ```./make-gen parity.pchk gen.gen dense```
* Install the python modules given in `requirements.txt`
* Create a directory "LPN_Matrices". Run `generate_matrices.py` to generate the LPN Matrices for encryption/decryption.
* Edit `fuzzy_extractor.py`'s `main` function to run the Gen and Rep algorithms on specific iris codes
  * You will need to use OSIRIS to generate iris codes and normalized masks (.bmp) from iris images (.tiff)
