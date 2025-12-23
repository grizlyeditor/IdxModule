import base64
import json
import blackboxprotobuf
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, render_template, request, jsonify
import os

app = Flask(__name__)

# ---------------------------------------------------------
#   CONFIGURATIONS (GLOBAL KEYS)
# ---------------------------------------------------------
REQ_KEY = b'Yg&tc%DEuh6%Zc^8'
REQ_IV = b'6oyZDr22E3ychjM%'

# ---------------------------------------------------------
#   HELPER FUNCTIONS
# ---------------------------------------------------------
def byte_converter(obj):
    """JSON serialization ke liye bytes ko string/hex me badalta hai"""
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except:
            return f"HEX:{obj.hex()}"
    return str(obj)

def aes_decrypt_proto(base64_str):
    try:
        # 1. Base64 Decode
        cipher_bytes = base64.b64decode(base64_str)
        
        # 2. AES Decrypt
        cipher = AES.new(REQ_KEY, AES.MODE_CBC, REQ_IV)
        decrypted_data = unpad(cipher.decrypt(cipher_bytes), AES.block_size)
        
        return decrypted_data
    except Exception as e:
        raise Exception(f"Decryption Error: {e}")

def aes_encrypt_proto(raw_bytes):
    try:
        # 1. AES Encrypt
        cipher = AES.new(REQ_KEY, AES.MODE_CBC, REQ_IV)
        encrypted_bytes = cipher.encrypt(pad(raw_bytes, AES.block_size))
        
        # 2. Base64 Encode
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        raise Exception(f"Encryption Error: {e}")

# ---------------------------------------------------------
#   ROUTES
# ---------------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/decode_response', methods=['POST'])
def decode_response():
    try:
        base64_string = request.json.get('data', '').strip()
        
        if not base64_string:
            return jsonify({'error': 'Empty input!'})
        
        print("Wait... Decoding data...")
        
        # Step 1: Base64 to Binary
        binary_data = base64.b64decode(base64_string)
        
        # Step 2: Protobuf decode
        decoded_data, message_type = blackboxprotobuf.decode_message(binary_data)
        
        # Step 3: Convert to neat JSON string
        json_output = json.dumps(decoded_data, indent=4, default=byte_converter)
        
        return jsonify({
            'success': True,
            'output': json_output,
            'message': '✅ SUCCESS! DATA DECODED'
        })
        
    except Exception as e:
        return jsonify({'error': f'❌ Error: {str(e)}'})

@app.route('/decode_request', methods=['POST'])
def decode_request():
    try:
        enc_input = request.json.get('data', '').strip()
        
        if not enc_input:
            return jsonify({'error': 'Empty input!'})
        
        # Step 1: Decrypt
        decrypted_bytes = aes_decrypt_proto(enc_input)
        
        # Step 2: Protobuf Decode
        msg, typedef = blackboxprotobuf.decode_message(decrypted_bytes)
        
        # Format JSON
        json_output = json.dumps(msg, indent=4, default=byte_converter)
        
        return jsonify({
            'success': True,
            'decrypted_hex': decrypted_bytes.hex(),
            'output': json_output,
            'message': '✅ DECRYPTION SUCCESSFUL'
        })
        
    except Exception as e:
        return jsonify({'error': f'❌ Error: {str(e)}'})

@app.route('/encode_uid', methods=['POST'])
def encode_uid():
    try:
        uid = request.json.get('uid', '')
        
        if not uid:
            return jsonify({'error': 'Empty UID!'})
        
        try:
            uid_int = int(uid)
        except:
            return jsonify({'error': 'Invalid UID! Must be a number.'})
        
        # Protobuf Encoding
        def encode_varint(value):
            out = []
            while True:
                b = value & 0x7F
                value >>= 7
                if value:
                    out.append(b | 0x80)
                else:
                    out.append(b)
                    break
            return bytes(out)
        
        # Encode UID (field 1 → varint)
        field_header = bytes([0x08])  # (1 << 3 | 0)
        proto_bytes = field_header + encode_varint(uid_int)
        
        # Encrypt
        final_b64 = aes_encrypt_proto(proto_bytes)
        
        return jsonify({
            'success': True,
            'payload': final_b64,
            'proto_hex': proto_bytes.hex(),
            'message': f'✅ ENCODED UID: {uid_int}'
        })
        
    except Exception as e:
        return jsonify({'error': f'❌ Error: {str(e)}'})

@app.route('/encode_custom', methods=['POST'])
def encode_custom():
    try:
        hex_input = request.json.get('hex', '').strip().replace(" ", "")
        
        if not hex_input:
            return jsonify({'error': 'Empty hex input!'})
        
        try:
            raw_bytes = bytes.fromhex(hex_input)
        except:
            return jsonify({'error': 'Invalid Hex String!'})
        
        # Encrypt
        final_b64 = aes_encrypt_proto(raw_bytes)
        
        return jsonify({
            'success': True,
            'payload': final_b64,
            'message': '✅ ENCRYPTION SUCCESSFUL'
        })
        
    except Exception as e:
        return jsonify({'error': f'❌ Error: {str(e)}'})

if __name__ == '__main__':
    app.run(debug=True)