import hashlib
import random
import string
import os
from itertools import cycle

# ソルト候補文字（1~z, 0~9）をあらかじめ高速検索用に定義
SALT_CHARS = (string.ascii_lowercase + string.digits).encode('utf-8')

def generate_base_key(k1: str, k2: str, k3: str) -> bytes:
    """3つのキーから共通のベースハッシュ鍵（バイト列）を高速生成"""
    return hashlib.sha256((k1 + k2 + k3).encode('utf-8')).digest()

def fast_encrypt(plain_text: str, base_key: bytes) -> str:
    """[高速化] 可変長（6〜12文字）暗号化、全体26文字制限対応"""
    text_bytes = plain_text.encode('utf-8')
    encrypted_tokens = []
    
    # 高速ランダムチョイスのためのローカル変数化
    rc = random.choice
    
    for b in text_bytes:
        # 1文字あたりの総長をランダム決定 (6〜12)
        total_length = random.randint(6, 12)
        length_marker = f"{total_length:x}"
        
        # ソルト生成と使い捨てハッシュ計算
        salt_len = total_length - 1 - 2
        salt_bytes = bytes([rc(SALT_CHARS) for _ in range(salt_len)])
        
        # ハッシュ結合
        char_key = hashlib.sha256(base_key + salt_bytes).digest()
        
        # ビット演算(XOR)
        encrypted_byte = b ^ char_key[0]
        
        # トークンを結合
        token = length_marker + salt_bytes.decode('utf-8') + f"{encrypted_byte:02x}"
        encrypted_tokens.append(token)
        
    result = "".join(encrypted_tokens)
    return result

def fast_decrypt(cipher_text: str, base_key: bytes) -> str:
    """[高速化] マーカーを読み解きながら高速に一括スライス復号"""
    decrypted_bytes = bytearray()
    idx = 0
    cipher_len = len(cipher_text)
    
    try:
        # C言語ライブラリの処理速度を活かすため、インデックスをジャンプさせて高速化
        while idx < cipher_len:
            # マーカーから長さを取得
            total_length = int(cipher_text[idx], 16)
            
            # 必要な部分をスライス（一括切り出し）
            salt = cipher_text[idx + 1 : idx + total_length - 2].encode('utf-8')
            hex_code = cipher_text[idx + total_length - 2 : idx + total_length]
            
            # 鍵の復元
            char_key = hashlib.sha256(base_key + salt).digest()
            encrypted_byte = int(hex_code, 16)
            
            # 復号（XOR）してバイト配列に追加
            decrypted_bytes.append(encrypted_byte ^ char_key[0])
            
            idx += total_length
            
        return decrypted_bytes.decode('utf-8')
    except Exception:
        return "【エラー】復号失敗。鍵が違うかデータが破損しています。"

def handle_file_operations(mode: str, base_key: bytes):
    """[高速化] バッファを介さずOSレベルのファイルI/Oで一瞬でロード/保存"""
    file_path = input("対象のファイル名（例: data.txt）を入力してください: ").strip()
    
    if mode == 'C':
        if not os.path.exists(file_path):
            print("エラー: 指定されたファイルが存在しません。")
            return
            
        # 高速ファイルロード（一括読み込み）
        with open(file_path, 'r', encoding='utf-8') as f:
            plain_text = f.read()
            
        print("暗号化処理中...")
        cipher_text = fast_encrypt(plain_text, base_key)
        
        # 全体26文字制限のチェック
        if not (5 <= len(cipher_text) <= 26):
            print(f"【警告】暗号化後の長さ（{len(cipher_text)}文字）が制限（5〜26文字）を超えました。")
            print("※元のテキストをさらに短くする必要があります。")
            return
            
        # 暗号化ファイルの高速保存
        out_path = file_path + ".enc"
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(cipher_text)
        print(f"高速保存完了: {out_path} (暗号文: {cipher_text})")
        
    elif mode == 'D':
        if not os.path.exists(file_path):
            print("エラー: 指定されたファイルが存在しません。")
            return
            
        # 暗号化ファイルの高速ロード
        with open(file_path, 'r', encoding='utf-8') as f:
            cipher_text = f.read().strip()
            
        # 長さの事前バリデーション
        if not (5 <= len(cipher_text) <= 26):
            print(f"【エラー】ファイル内の暗号文が5〜26文字の範囲外です（現在{len(cipher_text)}文字）。")
            return
            
        print("復号処理中...")
        plain_text = fast_decrypt(cipher_text, base_key)
        
        # 復号ファイルの高速保存
        out_path = file_path.replace(".enc", "") + ".dec.txt"
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(plain_text)
        print(f"高速復号完了: {out_path} (復号結果: {plain_text})")

def main():
    print("=== 超高速・多パターン暗号化システム（ファイルロード対応） ===")
    
    key1 = input("1つ目のキーを入力してください: ")
    key2 = input("2つ目のキーを入力してください: ")
    key3 = input("3つ目のキーを入力してください: ")
    
    base_key = generate_base_key(key1, key2, key3)
    
    mode = input("decode or codex? (D/C): ").strip().upper()
    
    if mode in ('C', 'D'):
        handle_file_operations(mode, base_key)
    else:
        print("エラー: 'C' または 'D' を入力してください。")

if __name__ == "__main__":
    main()
