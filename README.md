# SecLink

<img width="1346" height="1420" alt="image" src="https://github.com/user-attachments/assets/c0065f28-72eb-4289-a26a-5030fcbda677" />

---

The One-Time Link Generator is a secure, lightweight web application built with Google Apps Script. It allows you to share sensitive information through single-use, password-protected links. Each link can be opened only once, expires automatically after one hour, and requires the recipient to enter a password before the secret is revealed.

## Features

### One-time access  
Each generated link is valid for a single use. After successful access, the stored data is deleted immediately.

### Password protection  
You define a custom password that the recipient must enter. The application stores only a SHA‑256 hash of the password, never the password itself.

### Custom secret messages  
You can securely share any text-based secret such as credentials, notes, or codes. The secret is stored server-side and never appears in the URL.

### Automatic expiration  
Links expire after one hour. Expired or used entries are removed to maintain security and reduce storage.

### Server-side storage  
All data is stored in Script Properties on the server side. No sensitive information is exposed to the client until the password is verified.

### Optional cleanup  
A cleanup function is included to remove expired or used entries. It can be scheduled using a time-based trigger.

## How It Works

1. You generate a link by providing:
   - A password  
   - A secret message  

2. The system:
   - Generates a unique token  
   - Hashes the password using SHA‑256  
   - Stores the hashed password, secret, expiry timestamp, and usage flag  
   - Returns a one-time URL containing the token  

3. The recipient opens the link and enters the password. If the password is correct and the link is valid:
   - The secret is returned  
   - The stored record is deleted immediately  

If the link is expired, already used, or the password is incorrect, access is denied with a clear error message.

## Use Cases

- Sharing credentials securely  
- Sending private notes that should not persist  
- Delivering one-time codes or sensitive information  
- Avoiding exposure of secrets in email or chat history  

## Security Notes

- Passwords are never stored in plain text.  
- Secrets are deleted after first successful access.  
- Expired links are automatically invalidated.  
- No data is exposed in the URL except the token.  

---
