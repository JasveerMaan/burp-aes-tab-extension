# Burp Suite Extension: AES Encrypt & Decrypt Tab

This Burp Suite extension adds a custom tab in the HTTP message editor to **decrypt and re-encrypt AES-encrypted request fields** for easier analysis and modification. It is specifically designed for applications that use **AES-CBC with dynamic IV** and SHA-256 derived keys.

## 🔐 Key Features

- Adds a custom tab titled **"SourceData (decrypted)"** in Burp Suite.
- Automatically extracts encrypted fields like `sourceData`, `crudFlag`, `otp`, etc.
- Decrypts AES-encrypted fields using the `secretkey` from the request body.
- Displays decrypted data in a user-friendly editable format.
- Re-encrypts fields on the fly before sending updated requests from Repeater.
- Supports both `application/x-www-form-urlencoded` and `multipart/form-data`.

## 🧠 How It Works (Decryption)

1. The extension monitors HTTP requests sent from Burp tools like Repeater.
2. It detects specific endpoints (e.g. `/verifyLoginOTP`, `/getAccountActivity`) and extracts the `secretkey` field.
3. For each field that is AES-encrypted (`value` in the form `IV:CipherText`):
    - The IV and ciphertext are split.
    - A SHA-256 hash of `secretkey` is derived as the AES key.
    - The ciphertext is decrypted using AES/CBC/PKCS5Padding with the derived key and IV.
    - The plaintext is shown in the custom tab.
