# SecLink

<img width="1493" height="1206" alt="image" src="https://github.com/user-attachments/assets/d2edbcb6-35a2-4335-884c-5ce6be29788e" />


---

## End-to-End Encrypted Secret Sharing Tool

A secure, zero-knowledge web application built with Google Apps Script and the browser Web Crypto API. It allows users to create self-destructing, one-time secret notes protected either by a client-side password or an auto-generated URL decryption key.

---

## Features

* **End-to-End Encryption (E2EE)**: Messages are encrypted inside the browser using AES-GCM (256-bit) before transmission. The unencrypted text never touches the server.


* **Flexible Security Options**:
* **Password Protected**: Derives AES keys via PBKDF2 (100,000 iterations + SHA-256).


* **Passwordless**: Generates a 256-bit key embedded directly in the URL hash fragment. The key is never sent to Google servers during HTTP requests.




* **One-Time Burn and Expiry**: Payloads self-destruct instantly upon retrieval or auto-expire after 1 hour.


* **Built-in Rate Limiting**: Script locking and windowed rate-limiting prevent abuse (up to 5 links per minute per user).


* **Zero Infrastructure Cost**: Runs completely serverless using Google Apps Script infrastructure.



---

## Technical Stack

* **Frontend**: HTML5, CSS3, JavaScript (Web Crypto API for in-browser encryption)


* **Backend Service**: Google Apps Script (`PropertiesService`, `LockService`, `Session`)


* **Cryptographic Standards**:
* Algorithm: AES-GCM (256-bit)


* Key Derivation: PBKDF2 with 100,000 iterations


* Initialization Vector: 12-byte random array





---

## Setup and Deployment

1. Go to Google Apps Script and create a new project.
2. Replace the contents of `Code.gs` with the provided script.


3. Create an `index.html` file in the project editor and paste the HTML/JS code.


4. Click **Deploy** > **New deployment**.
5. Select **Web app**:
* Set **Execute as** to *Me*.
* Set **Who has access** to *Anyone*.


6. Deploy the project and use the web app URL to share secure notes.
