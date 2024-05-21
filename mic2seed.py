import sounddevice as sd
import numpy as np
import hashlib
import binascii
import time


class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def record_audio(duration):
    print('Grabbing entropy from the air...')
    fs = 44100  # Sampling frequency
    seconds = duration  # Duration in seconds
    recording = sd.rec(int(seconds * fs), samplerate=fs, channels=1, dtype=np.int16)
    sd.wait()
    return recording, fs


def calculate_sha256(data):
    sha256_hash = hashlib.sha256(data)
    return sha256_hash.hexdigest()


def sha256(input_data):
    return hashlib.sha256(input_data).digest()


def sha256_to_binary_string(hash_result):
    binary_string = ""
    for byte in hash_result:
        # Convert each byte to its binary representation and pad with zeros to ensure it's 8 bits long
        binary_string += format(byte, '08b')
    return binary_string


def binToHexa(n):
    bnum = int(n)
    temp = 0
    mul = 1
    # counter to check group of 4
    count = 1
    # char array to store hexadecimal number
    hexaDeciNum = ['0'] * 100
    # counter for hexadecimal number array
    i = 0
    while bnum != 0:
        rem = bnum % 10
        temp = temp + (rem * mul)
        # check if group of 4 completed
        if count % 4 == 0:
            # check if temp < 10
            if temp < 10:
                hexaDeciNum[i] = chr(temp + 48)
            else:
                hexaDeciNum[i] = chr(temp + 55)
            mul = 1
            temp = 0
            count = 1
            i = i + 1
        # group of 4 is not completed
        else:
            mul = mul * 2
            count = count + 1
        bnum = int(bnum / 10)
    # check if at end the group of 4 is not completed
    if count != 1:
        hexaDeciNum[i] = chr(temp + 48)
    # check at end the group of 4 is completed
    if count == 1:
        i = i - 1
    return hexaDeciNum[i]


def bytes_to_binary_string(byte_data):
    binary_string = ''.join(format(byte, '08b') for byte in byte_data)
    return binary_string


def binary_string_to_mnemonic(binary_string, word_list_file):
    bytes = 32
    tmp_bin = binary_string
    # convert string with 0 and 1 to hex and to binary
    bin_list = []
    start = 0
    part = 4
    while start < len(tmp_bin):  # Splitting string in 4 digits parts
        bin_list.append(tmp_bin[start: start + part])
        start += part
    # convert list with four 0 and 1 digits to list with hexadecimal letters
    hex_list = []
    for bn in bin_list:
        hex_list.append(binToHexa(bn))
    hex_ent = ''.join(hex_list)  # creates hexadecimal string of entropy
    tmp_bin = binascii.unhexlify(hex_ent)  # binary of entropy
    tmp_hex = binascii.hexlify(tmp_bin)  # hexadecimal of entropy
    str_hash = hashlib.sha256(tmp_bin).hexdigest()  # hashing binary of entropy
    # Converting hash to binary
    int_hash = int(str_hash, base=16)
    bin_hash = str(bin(int_hash))[2:]
    # Adding checksum to entropy
    checksum = bin(int(str_hash, 16))[2:].zfill(256)[: bytes * 8 // 32]
    print(color.YELLOW + 'Checksum: ' + color.END + f'{checksum}')
    binary_seed = (bin(int(tmp_hex, 16))[2:].zfill(bytes * 8) + checksum)
    print(f'binary_seed: {binary_seed}')

    index_list = []
    start = 0
    part = 11
    while start < len(binary_seed):
        index_list.append(binary_seed[start: start + part])
        start += part

    # Converting binary indexes to integer
    index_list_int = []
    b = 0
    while b < len(index_list):
        index_list_int.append(int(index_list[b], 2))
        b += 1

    f = open('Wordlists/b39en', 'r')  # Opening English wordlist, just because the others are useless
    mnemonic = []
    w = 0
    while w < len(index_list_int):
        f.seek(0)
        for i, line in enumerate(f):
            if i == index_list_int[w]:
                mnemonic.append(line.strip('\n'))
        w += 1

    # Verify conversion
    c = 0
    print(color.DARKCYAN + '\nVerify indexes' + color.END)
    while c < len(index_list):
        if c < 9: # when index is less than 9 it adds a 0 to the output to align it
            print(f'Index 0{c + 1}: {index_list[c]} -> {str(index_list_int[c]).zfill(4)} -> {mnemonic[c]}')
        else:
            print(f'Index {c + 1}: {index_list[c]} -> {str(index_list_int[c]).zfill(4)} -> {mnemonic[c]}')
        c += 1
    mnemonic_clean = ' '.join(mnemonic) # converting list to string
    return mnemonic_clean

# START
print(color.RED + 'Note that this tool may have undesired results with not properly working hardware. Check your hardware before continuing' + color.END)
input('Press enter to continue...')
duration = 30  # Duration in seconds
recording, fs = record_audio(duration)

if recording is None or fs is None:
    exit(color.RED + 'No recording available, check your hardware\nEXITING\n' + color.END)

audio_bytes = recording.tobytes()
#print('audio bytes: ' + str(audio_bytes))
hashed_data = sha256(audio_bytes)
binary_string = sha256_to_binary_string(hashed_data)
print("Binary string:", binary_string)

word_list_file = "Wordlists/b39en"  # Replace this with the path to your BIP39 word list file

# Generate the BIP39 mnemonic directly from the binary string
mnemonic = binary_string_to_mnemonic(binary_string, word_list_file)

print('==========')
print(color.DARKCYAN + mnemonic + color.END)
print('==========')
print(color.BLUE + 'Made by the AnuBitux Team!' + color.END)
print('==========')
