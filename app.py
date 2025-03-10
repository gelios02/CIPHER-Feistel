import hashlib
import struct
import sys


BLOCK_SIZE = 8
NUM_ROUNDS = 8

def derive_round_keys(key: str) -> list:

    try:
        key_bytes = key.encode('utf-8')
    except Exception as e:
        raise ValueError(f"Ошибка при кодировании ключа: {e}")
    try:
        hash_digest = hashlib.sha256(key_bytes).digest()  # 32 байта
        # Разбиваем на 8 4-байтовых чисел (big-endian)
        round_keys = [struct.unpack('>I', hash_digest[i*4:(i+1)*4])[0] for i in range(8)]
    except Exception as e:
        raise ValueError(f"Ошибка при генерации раундовых ключей: {e}")
    return round_keys

def feistel_F(right: int, round_key: int) -> int:

    try:
        result = (right + round_key) % (2**32)
        # Циклический сдвиг влево на 3 бита
        result = ((result << 3) | (result >> (32 - 3))) & 0xFFFFFFFF
    except Exception as e:
        raise ValueError(f"Ошибка в функции F: {e}")
    return result

def feistel_encrypt_block(block: bytes, round_keys: list) -> bytes:

    if len(block) != BLOCK_SIZE:
        raise ValueError("Размер блока должен быть ровно {} байт.".format(BLOCK_SIZE))
    try:
        left, right = struct.unpack('>II', block)
    except struct.error as e:
        raise ValueError("Ошибка при разборе блока: {}".format(e))
    try:
        for i in range(NUM_ROUNDS):
            temp = right
            right = left ^ feistel_F(right, round_keys[i])
            left = temp
        encrypted_block = struct.pack('>II', left, right)
    except Exception as e:
        raise ValueError(f"Ошибка при шифровании блока: {e}")
    return encrypted_block

def feistel_decrypt_block(block: bytes, round_keys: list) -> bytes:

    if len(block) != BLOCK_SIZE:
        raise ValueError("Размер блока должен быть ровно {} байт.".format(BLOCK_SIZE))
    try:
        left, right = struct.unpack('>II', block)
    except struct.error as e:
        raise ValueError("Ошибка при разборе блока: {}".format(e))
    try:
        for i in reversed(range(NUM_ROUNDS)):
            temp = left
            left = right ^ feistel_F(left, round_keys[i])
            right = temp
        decrypted_block = struct.pack('>II', left, right)
    except Exception as e:
        raise ValueError(f"Ошибка при расшифровке блока: {e}")
    return decrypted_block

def pad(data: bytes) -> bytes:

    try:
        padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        padded_data = data + bytes([padding_length]) * padding_length
    except Exception as e:
        raise ValueError(f"Ошибка при добавлении паддинга: {e}")
    return padded_data

def unpad(data: bytes) -> bytes:

    if not data:
        raise ValueError("Данные пусты, нет паддинга для удаления.")
    try:
        padding_length = data[-1]
        if padding_length < 1 or padding_length > BLOCK_SIZE:
            raise ValueError("Неверное значение паддинга.")
        unpadded_data = data[:-padding_length]
    except Exception as e:
        raise ValueError(f"Ошибка при удалении паддинга: {e}")
    return unpadded_data

def encrypt_file(input_filename: str, output_filename: str, key: str):

    try:
        round_keys = derive_round_keys(key)
    except Exception as e:
        print(f"Ошибка генерации ключей: {e}")
        return
    try:
        with open(input_filename, 'rb') as fin:
            data = fin.read()
    except FileNotFoundError:
        print(f"Ошибка: входной файл '{input_filename}' не найден.")
        return
    except Exception as e:
        print(f"Ошибка при чтении файла '{input_filename}': {e}")
        return
    try:
        padded_data = pad(data)
    except Exception as e:
        print(f"Ошибка при добавлении паддинга: {e}")
        return
    ciphertext = b""
    try:
        for i in range(0, len(padded_data), BLOCK_SIZE):
            block = padded_data[i:i+BLOCK_SIZE]
            ciphertext += feistel_encrypt_block(block, round_keys)
    except Exception as e:
        print(f"Ошибка при шифровании данных: {e}")
        return
    try:
        with open(output_filename, 'wb') as fout:
            fout.write(ciphertext)
    except Exception as e:
        print(f"Ошибка при записи зашифрованного файла '{output_filename}': {e}")
        return
    print(f"Файл '{input_filename}' успешно зашифрован в '{output_filename}'.")

def decrypt_file(input_filename: str, output_filename: str, key: str):

    try:
        round_keys = derive_round_keys(key)
    except Exception as e:
        print(f"Ошибка генерации ключей: {e}")
        return
    try:
        with open(input_filename, 'rb') as fin:
            ciphertext = fin.read()
    except FileNotFoundError:
        print(f"Ошибка: входной файл '{input_filename}' не найден.")
        return
    except Exception as e:
        print(f"Ошибка при чтении файла '{input_filename}': {e}")
        return
    if len(ciphertext) % BLOCK_SIZE != 0:
        print("Ошибка: Размер зашифрованного файла не кратен размеру блока.")
        return
    plaintext_padded = b""
    try:
        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i:i+BLOCK_SIZE]
            plaintext_padded += feistel_decrypt_block(block, round_keys)
    except Exception as e:
        print(f"Ошибка при расшифровке данных: {e}")
        return
    try:
        plaintext = unpad(plaintext_padded)
    except Exception as e:
        print(f"Ошибка при удалении паддинга: {e}")
        return
    try:
        with open(output_filename, 'wb') as fout:
            fout.write(plaintext)
    except Exception as e:
        print(f"Ошибка при записи расшифрованного файла '{output_filename}': {e}")
        return
    print(f"Файл '{input_filename}' успешно расшифрован в '{output_filename}'.")

def main():
    while True:
        print("\n===== БЛОЧНЫЙ ШИФР =====")
        print("1. Зашифровать файл")
        print("2. Расшифровать файл")
        print("3. Выход")
        choice = input("Выберите опцию (1-3): ").strip()
        if choice == '1':
            infile = input("Введите имя входного файла: ").strip()
            outfile = input("Введите имя выходного файла: ").strip()
            key = input("Введите ключ (строка): ").strip()
            try:
                encrypt_file(infile, outfile, key)
            except Exception as e:
                print(f"Произошла ошибка при шифровании: {e}")
        elif choice == '2':
            infile = input("Введите имя входного файла: ").strip()
            outfile = input("Введите имя выходного файла: ").strip()
            key = input("Введите ключ (строка): ").strip()
            try:
                decrypt_file(infile, outfile, key)
            except Exception as e:
                print(f"Произошла ошибка при расшифровке: {e}")
        elif choice == '3':
            print("Выход...")
            sys.exit(0)
        else:
            print("Неверный выбор. Повторите попытку.")

if __name__ == "__main__":
    main()
