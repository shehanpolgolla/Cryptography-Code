# Constants for Block Size and Key Size
BLOCK_SIZE = 8  # 8-bit blocks
KEY_SIZE = 8    # 8-bit key

# Part 1: Implement a Simple Substitution Box (S-box)

# Define a 4x4 substitution box (S-box) for 4-bit values
S_box = {
    0x0: 0xE, 0x1: 0x4, 0x2: 0xD, 0x3: 0x1,
    0x4: 0x2, 0x5: 0xF, 0x6: 0xB, 0x7: 0x8,
    0x8: 0x3, 0x9: 0xA, 0xA: 0x6, 0xB: 0xC,
    0xC: 0x5, 0xD: 0x9, 0xE: 0x0, 0xF: 0x7
}

# Substitution function using the S-box
def substitute(input_4bit):
    """
    Substitute the input 4-bit value using the S-box.
    :param input_4bit: 4-bit value (0-15)
    :return: Substituted 4-bit value
    """
    return S_box[input_4bit]

# Part 2: Implement a Simplified Permutation

# Permutation function using a defined permutation table
def permute(input_block):
    """
    Permute the input 8-bit block using the defined permutation table.
    :param input_block: 8-bit input block
    :return: Permuted 8-bit block
    """
    permutation_table = [1, 5, 2, 0, 3, 7, 4, 6]
    output_block = 0
    for i in range(BLOCK_SIZE):
        output_block |= ((input_block >> i) & 1) << permutation_table[i]
    return output_block

# Part 3: Implement a Basic Feistel Function

# Feistel function for 4-bit input using XOR with the subkey
def feistel_function(input_4bits, subkey):
    """
    Apply the Feistel function (XOR with the subkey) to the 4-bit input.
    :param input_4bits: 4-bit input
    :param subkey: Subkey to XOR with
    :return: Transformed 4-bit value
    """
    return input_4bits ^ subkey

# Part 4: Combine Components for Encryption

# Encryption function combining substitution, permutation, and Feistel function
def encrypt_block(block, key):
    """
    Encrypt a single 8-bit block using substitution, permutation, and Feistel function.
    :param block: 8-bit input block
    :param key: 8-bit key for Feistel function
    :return: Encrypted 8-bit block
    """
    left = (block >> 4) & 0xF  # Extract left 4 bits
    right = block & 0xF         # Extract right 4 bits
    
    # Feistel round: apply Feistel function and swap left and right
    temp = right
    right = left ^ feistel_function(right, key)
    left = temp
    
    # Combine the left and right halves
    return (left << 4) | right

# Part 5: Modes of Operation

# Implement Electronic Codebook (ECB) Mode
def ecb_encrypt(plaintext, key):
    """
    Encrypt plaintext using ECB mode, block by block.
    :param plaintext: List of 8-bit blocks
    :param key: 8-bit key for encryption
    :return: List of encrypted blocks
    """
    ciphertext = []
    for block in plaintext:
        ciphertext.append(encrypt_block(block, key))
    return ciphertext

def ecb_decrypt(ciphertext, key):
    """
    Decrypt ciphertext using ECB mode, block by block.
    :param ciphertext: List of encrypted 8-bit blocks
    :param key: 8-bit key for decryption
    :return: List of decrypted blocks
    """
    plaintext = []
    for block in ciphertext:
        plaintext.append(encrypt_block(block, key))  # Symmetric decryption
    return plaintext

# Implement Cipher Block Chaining (CBC) Mode
def cbc_encrypt(plaintext, key, iv):
    """
    Encrypt plaintext using CBC mode, XORing with the previous ciphertext block.
    :param plaintext: List of 8-bit blocks
    :param key: 8-bit key for encryption
    :param iv: 8-bit initialization vector (IV)
    :return: List of encrypted blocks
    """
    ciphertext = []
    previous_block = iv
    for block in plaintext:
        block = block ^ previous_block  # XOR with previous ciphertext (or IV for first block)
        encrypted_block = encrypt_block(block, key)
        ciphertext.append(encrypted_block)
        previous_block = encrypted_block
    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    """
    Decrypt ciphertext using CBC mode, XORing with the previous ciphertext block.
    :param ciphertext: List of encrypted 8-bit blocks
    :param key: 8-bit key for decryption
    :param iv: 8-bit initialization vector (IV)
    :return: List of decrypted blocks
    """
    plaintext = []
    previous_block = iv
    for block in ciphertext:
        decrypted_block = encrypt_block(block, key)
        plaintext.append(decrypted_block ^ previous_block)
        previous_block = block
    return plaintext

# Part 6: Encryption and Decryption of Sample Input

# Example of plaintext and key
key = 0b10101010  # 8-bit key
iv = 0b11001100   # 8-bit initialization vector (IV)

# Define a list of 8-bit plaintext blocks
plaintext = [0b11010010, 0b10110101]  # Example plaintext blocks

# Encrypt and decrypt using ECB mode
ciphertext_ecb = ecb_encrypt(plaintext, key)
decrypted_ecb = ecb_decrypt(ciphertext_ecb, key)

# Encrypt and decrypt using CBC mode
ciphertext_cbc = cbc_encrypt(plaintext, key, iv)
decrypted_cbc = cbc_decrypt(ciphertext_cbc, key, iv)

# Output the results
print("ECB Mode Encryption: ", ciphertext_ecb)
print("ECB Mode Decryption: ", decrypted_ecb)
print("CBC Mode Encryption: ", ciphertext_cbc)
print("CBC Mode Decryption: ", decrypted_cbc)