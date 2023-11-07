# Image Steganography Program

To use the program, use python 3 with the libraries in [requirements.txt](requirements.txt) installed

I used python 3.12 on windows to develop with. 
Passwords use the python random library and a seed set by the hash of the password.
It is possible that different versions/platforms of python might have different implementations of seeded random numbers which would break passwords.


Using the password option causes the program to take more time and memory to encode and decode because instead of streaming the entire process
the random order of pixels needs to be determined ahead of time.


The program acts like a normal command line application and takes an input image and can either
 - Output the encoded data to an output file
 - Take an input file and write the encoded image to an output file

While encoding there are parameters that control: 
 - the maximum and minimum number of bits to use for the lsb (defaults to 1-4 bits)
 - an optional password to use for encoding and decoding
 - an optional flag to fill the unused lsb bits with random data

To see more exact documentation, run the program with -h for help.

## Examples:

### Bee movie script
#### Encoding
`Steganography.py 'Test Input Images\bee_movie.jpg' -i 'Test Input Data\input_text.txt' encoded_script.png`

#### Decoding
`Steganography.py encoded_script.png output_script.txt`


### Decoding Included File:
This decodes the included file using the password jazz

`Steganography.py included_test.png -p jazz output_video.mp4`

