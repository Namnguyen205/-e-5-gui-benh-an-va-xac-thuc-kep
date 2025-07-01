# app/crypto_logic.py
import os
import base64
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512, SHA256
from Crypto.Random import get_random_bytes
from flask import current_app

def pad(data, block_size):
    """Hàm thêm đệm để dữ liệu đủ khối cho AES."""
    padding_len = block_size - len(data) % block_size
    padding = bytes([padding_len]) * padding_len
    return data + padding

def unpad(data, block_size):
    """Hàm loại bỏ đệm sau khi giải mã."""
    padding_len = data[-1]
    if padding_len > block_size or padding_len == 0:
        return data
    return data[:-padding_len]

def seal_package(file_content, file_name, patient_id):
    """
    Giai đoạn 1: Bác sĩ niêm phong gói tin.
    Mã hóa file, ký metadata và trả về một gói tin bảo mật.
    """
    with open(current_app.config['SENDER_PRIVATE_KEY_PATH'], 'rb') as f:
        sender_private_key = RSA.import_key(f.read())
    with open(current_app.config['RECEIVER_PUBLIC_KEY_PATH'], 'rb') as f:
        receiver_public_key = RSA.import_key(f.read())
    
    timestamp = datetime.utcnow().isoformat()
    metadata_str = f"{file_name}|{timestamp}|{patient_id}"
    hash_metadata = SHA512.new(metadata_str.encode('utf-8'))
    signature = pkcs1_15.new(sender_private_key).sign(hash_metadata)
    
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key, hashAlgo=SHA512)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    iv = get_random_bytes(AES.block_size)
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    padded_content = pad(file_content, AES.block_size)
    ciphertext = cipher_aes.encrypt(padded_content)
    
    integrity_hash = SHA512.new(iv + ciphertext).digest()
    
    encrypted_file_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{patient_id}.enc"
    encrypted_file_path = os.path.join(current_app.root_path, '..', 'received_files', encrypted_file_name)
    with open(encrypted_file_path, 'wb') as f:
        f.write(ciphertext)
        
    return {
        "encrypted_file_path": encrypted_file_path,
        "signature_b64": base64.b64encode(signature).decode('utf-8'),
        "encrypted_session_key_b64": base64.b64encode(encrypted_session_key).decode('utf-8'),
        "iv_b64": base64.b64encode(iv).decode('utf-8'),
        "integrity_hash_b64": base64.b64encode(integrity_hash).decode('utf-8'),
        "metadata_str": metadata_str
    }

def unseal_package(record, records_room_password):
    """
    Giai đoạn 2: Nhân viên mở niêm phong gói tin.
    Kiểm tra toàn vẹn, xác thực chữ ký, xác thực mật khẩu và giải mã.
    """
    iv = base64.b64decode(record.iv)
    stored_integrity_hash = base64.b64decode(record.integrity_hash)
    with open(record.encrypted_file_path, 'rb') as f:
        ciphertext = f.read()

    calculated_hash = SHA512.new(iv + ciphertext).digest()
    if calculated_hash != stored_integrity_hash:
        raise ValueError("Lỗi Toàn vẹn (NACK): Dữ liệu có thể đã bị thay đổi.")

    correct_pwd_hash = SHA256.new(current_app.config['RECORDS_ROOM_PASSWORD'].encode('utf-8')).digest()
    submitted_pwd_hash = SHA256.new(records_room_password.encode('utf-8')).digest()
    if correct_pwd_hash != submitted_pwd_hash:
        raise ValueError("Lỗi Xác thực (NACK): Mật khẩu phòng lưu trữ không chính xác.")

    with open(current_app.config['SENDER_PUBLIC_KEY_PATH'], 'rb') as f:
        sender_public_key = RSA.import_key(f.read())
    
    hash_metadata = SHA512.new(record.metadata_str.encode('utf-8'))
    signature = base64.b64decode(record.signature)
    try:
        pkcs1_15.new(sender_public_key).verify(hash_metadata, signature)
    except (ValueError, TypeError):
        raise ValueError("Lỗi Xác thực (NACK): Chữ ký của bác sĩ không hợp lệ.")

    with open(current_app.config['RECEIVER_PRIVATE_KEY_PATH'], 'rb') as f:
        receiver_private_key = RSA.import_key(f.read())
    
    encrypted_session_key = base64.b64decode(record.encrypted_session_key)
    cipher_rsa = PKCS1_OAEP.new(receiver_private_key, hashAlgo=SHA512)
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_padded_data = cipher_aes.decrypt(ciphertext)
    decrypted_data = unpad(decrypted_padded_data, AES.block_size)
    return decrypted_data
