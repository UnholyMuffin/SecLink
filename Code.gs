// ================================================
// SECURE ONE-TIME LINK GENERATOR - FULL CODE
// ================================================

/**
 * Serves the HTML interface
 */
function doGet(e) {
  return HtmlService.createHtmlOutputFromFile('index')
    .setTitle('🔐 Secure One-Time Link Generator')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

// ================================================
// ENCRYPTION HELPERS
// ================================================

/**
 * Encrypts a message using XOR cipher with SHA-256 derived key
 * @param {string} text - The text to encrypt
 * @param {string} password - The password to derive key from
 * @returns {Object} { encrypted: string, iv: string, salt: string, hmac: string }
 */
function encryptSecret(text, password) {
  if (!text || !password) {
    throw new Error('Text and password required for encryption');
  }
  
  // Generate random salt (16 characters)
  const salt = Utilities.getUuid().replace(/-/g, '').substring(0, 16);
  
  // Generate random IV (16 characters)
  const iv = Utilities.getUuid().replace(/-/g, '').substring(0, 16);
  
  // Derive key using SHA-256 with salt and IV
  const keyMaterial = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    password + salt + iv
  ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
  
  // Use 32 chars as key
  const key = keyMaterial.substring(0, 32);
  
  // Combine key + iv for encryption
  const combinedKey = key + iv;
  
  // Convert to bytes
  const textBytes = Utilities.newBlob(text).getBytes();
  const keyBytes = Utilities.newBlob(combinedKey).getBytes();
  
  // XOR encryption
  const encryptedBytes = [];
  for (let i = 0; i < textBytes.length; i++) {
    const keyByte = keyBytes[i % keyBytes.length];
    encryptedBytes.push(textBytes[i] ^ keyByte);
  }
  
  // Convert to Base64 for storage
  const encryptedBase64 = Utilities.base64Encode(encryptedBytes);
  
  // Add HMAC for integrity check
  const hmac = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    encryptedBase64 + password + salt
  ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
  
  return {
    encrypted: encryptedBase64,
    iv: iv,
    salt: salt,
    hmac: hmac.substring(0, 32)
  };
}

/**
 * Decrypts a message using XOR cipher with SHA-256 derived key
 * @param {string} encryptedBase64 - The encrypted text in Base64
 * @param {string} password - The password to derive key from
 * @param {string} iv - The IV used for encryption
 * @param {string} salt - The salt used for key derivation
 * @param {string} hmac - The HMAC for integrity verification
 * @returns {string} Decrypted text
 */
function decryptSecret(encryptedBase64, password, iv, salt, hmac) {
  if (!encryptedBase64 || !password || !iv || !salt) {
    throw new Error('Missing required parameters for decryption');
  }
  
  try {
    // Verify HMAC first
    const hmacCheck = Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256,
      encryptedBase64 + password + salt
    ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    
    if (hmac && hmac !== hmacCheck.substring(0, 32)) {
      throw new Error('Data integrity check failed');
    }
    
    // Derive key using same method as encryption
    const keyMaterial = Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256,
      password + salt + iv
    ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    
    const key = keyMaterial.substring(0, 32);
    const combinedKey = key + iv;
    
    // Decode from Base64
    const encryptedBytes = Utilities.base64Decode(encryptedBase64);
    const keyBytes = Utilities.newBlob(combinedKey).getBytes();
    
    // XOR decryption (same as encryption)
    const decryptedBytes = [];
    for (let i = 0; i < encryptedBytes.length; i++) {
      const keyByte = keyBytes[i % keyBytes.length];
      decryptedBytes.push(encryptedBytes[i] ^ keyByte);
    }
    
    // Convert to string
    return Utilities.newBlob(decryptedBytes).getDataAsString();
  } catch (e) {
    throw new Error('Decryption failed: ' + e.message);
  }
}

// ================================================
// CORE LINK FUNCTIONS
// ================================================

/**
 * Generates a secure one-time link with encrypted secret
 * @param {string} linkPassword - The password to protect the link
 * @param {string} secretMessage - The secret to encrypt and send
 * @param {boolean} isPasswordless - Whether the link requires a password
 * @returns {Object} { link: string, token: string, expiry: number }
 */
function generateLink(linkPassword, secretMessage, isPasswordless) {
  // Input validation
  if (!secretMessage || secretMessage.trim() === '') {
    throw new Error('Secret message cannot be empty');
  }
  
  const token = Utilities.getUuid();
  const now = new Date().getTime();
  const expiry = now + 60 * 60 * 1000; // 1 hour
  
  let data = {
    expiry: expiry,
    used: false,
    passwordless: isPasswordless || false,
    attempts: 0 // Track failed attempts
  };
  
  try {
    // Handle passwordless vs password-protected
    if (isPasswordless || !linkPassword || linkPassword.trim() === '') {
      // Generate random key for passwordless access
      const randomKey = Utilities.getUuid().replace(/-/g, '').substring(0, 32);
      const encryptionResult = encryptSecret(secretMessage, randomKey);
      
      data.encryptedSecret = encryptionResult.encrypted;
      data.iv = encryptionResult.iv;
      data.salt = encryptionResult.salt;
      data.hmac = encryptionResult.hmac;
      data.randomKey = randomKey;
      data.hash = null;
    } else {
      // Hash the password for verification
      const passwordHash = Utilities.computeDigest(
        Utilities.DigestAlgorithm.SHA_256, 
        linkPassword
      ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
      
      // Encrypt with the user's password
      const encryptionResult = encryptSecret(secretMessage, linkPassword);
      
      data.encryptedSecret = encryptionResult.encrypted;
      data.iv = encryptionResult.iv;
      data.salt = encryptionResult.salt;
      data.hmac = encryptionResult.hmac;
      data.hash = passwordHash;
      data.randomKey = null;
    }
  } catch (e) {
    throw new Error('Failed to encrypt secret: ' + e.message);
  }
  
  // Save to database
  try {
    PropertiesService.getScriptProperties().setProperty('ot_' + token, JSON.stringify(data));
  } catch (e) {
    throw new Error('Failed to save link: ' + e.message);
  }
  
  // Generate the one-time URL
  const url = ScriptApp.getService().getUrl() + '?v=view&token=' + encodeURIComponent(token);
  
  return { 
    link: url, 
    token: token, 
    expiry: expiry 
  };
}

/**
 * Consumes a one-time link and decrypts the secret
 * @param {string} token - The link token
 * @param {string} enteredPassword - The password entered by the recipient
 * @returns {Object} { success: boolean, secret: string, message: string }
 */
function consumeLink(token, enteredPassword) {
  const props = PropertiesService.getScriptProperties();
  const key = 'ot_' + token;
  const storedJson = props.getProperty(key);
  
  if (!storedJson) {
    return { success: false, message: '❌ Link not found or already used' };
  }
  
  let record;
  try { 
    record = JSON.parse(storedJson); 
  } catch (e) { 
    props.deleteProperty(key);
    return { success: false, message: '❌ Invalid link data' }; 
  }
  
  // Check if already used
  if (record.used === true) { 
    props.deleteProperty(key); 
    return { success: false, message: '❌ This link has already been used' }; 
  }
  
  // Check expiry
  const now = new Date().getTime();
  if (now > record.expiry) { 
    props.deleteProperty(key); 
    return { success: false, message: '❌ Link expired (1 hour lifetime)' }; 
  }
  
  let secret = null;
  
  try {
    // Handle passwordless links
    if (record.passwordless === true) {
      if (!record.randomKey) {
        props.deleteProperty(key);
        return { success: false, message: '❌ Invalid passwordless link configuration' };
      }
      
      // Decrypt using the stored random key
      secret = decryptSecret(
        record.encryptedSecret,
        record.randomKey,
        record.iv,
        record.salt,
        record.hmac
      );
    } else {
      // Password-protected: verify password first
      if (!enteredPassword || enteredPassword.trim() === '') {
        return { success: false, message: '❌ Please enter a password' };
      }
      
      // Verify password hash
      const attemptHash = Utilities.computeDigest(
        Utilities.DigestAlgorithm.SHA_256, 
        enteredPassword
      ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
      
      if (attemptHash !== record.hash) {
        // Track failed attempts
        record.attempts = (record.attempts || 0) + 1;
        
        if (record.attempts >= 5) {
          // Destroy link after 5 failed attempts
          props.deleteProperty(key);
          return { success: false, message: '❌ Too many failed attempts. Link destroyed.' };
        }
        
        props.setProperty(key, JSON.stringify(record));
        return { success: false, message: '❌ Incorrect password' };
      }
      
      // Decrypt using the provided password
      secret = decryptSecret(
        record.encryptedSecret,
        enteredPassword,
        record.iv,
        record.salt,
        record.hmac
      );
    }
  } catch (e) {
    // If decryption fails, destroy the link to prevent further attempts
    props.deleteProperty(key);
    return { 
      success: false, 
      message: '❌ Unable to decrypt secret. Link has been destroyed for security.'
    };
  }
  
  // SUCCESS! Delete immediately and return secret
  props.deleteProperty(key);
  
  return { 
    success: true, 
    secret: secret,
    message: '✅ Link verified! Your secret is below:'
  };
}

// ================================================
// LINK MANAGEMENT FUNCTIONS
// ================================================

/**
 * Checks if a link exists and returns its type
 * @param {string} token - The link token
 * @returns {Object} { exists: boolean, passwordless: boolean }
 */
function checkLinkExists(token) {
  const props = PropertiesService.getScriptProperties();
  const key = 'ot_' + token;
  const storedJson = props.getProperty(key);
  
  if (!storedJson) {
    return { exists: false };
  }
  
  try {
    const record = JSON.parse(storedJson);
    const now = new Date().getTime();
    
    // Check if expired or used
    if (now > record.expiry || record.used === true) {
      props.deleteProperty(key);
      return { exists: false };
    }
    
    return { 
      exists: true,
      passwordless: record.passwordless || false
    };
  } catch (e) {
    props.deleteProperty(key);
    return { exists: false };
  }
}

/**
 * Revokes a link before it expires
 * @param {string} token - The link token
 * @returns {Object} { success: boolean, message: string }
 */
function revokeLink(token) {
  const props = PropertiesService.getScriptProperties();
  const key = 'ot_' + token;
  
  if (props.getProperty(key)) {
    props.deleteProperty(key);
    return { success: true, message: 'Link revoked successfully' };
  }
  
  return { success: false, message: 'Link not found' };
}

// ================================================
// CLEANUP FUNCTION (Run on time trigger)
// ================================================

/**
 * Cleans up expired and used links (run hourly via trigger)
 */
function cleanupExpired() {
  const props = PropertiesService.getScriptProperties();
  const all = props.getProperties();
  const now = new Date().getTime();
  let count = 0;
  
  Object.keys(all).forEach(key => {
    if (key.startsWith('ot_')) {
      try {
        const record = JSON.parse(all[key]);
        if (now > record.expiry || record.used === true) {
          props.deleteProperty(key);
          count++;
        }
      } catch(e) {
        // If data is corrupted, delete it
        props.deleteProperty(key);
        count++;
      }
    }
  });
  
  console.log('Cleaned up ' + count + ' expired/used links');
}

// ================================================
// TEST FUNCTIONS (For debugging)
// ================================================

/**
 * Test function to verify encryption/decryption works
 */
function testEncryption() {
  try {
    const testText = "My Secret Password: 12345";
    const testPassword = "Test123!";
    
    console.log("Testing encryption...");
    const encrypted = encryptSecret(testText, testPassword);
    console.log("✅ Encrypted successfully");
    
    console.log("Testing decryption...");
    const decrypted = decryptSecret(
      encrypted.encrypted, 
      testPassword, 
      encrypted.iv, 
      encrypted.salt,
      encrypted.hmac
    );
    
    if (testText === decrypted) {
      console.log("✅ Test passed! Encryption/Decryption working correctly.");
      return { success: true, message: "Test passed!" };
    } else {
      console.log("❌ Test failed! Decrypted text doesn't match original.");
      return { success: false, message: "Test failed!" };
    }
  } catch (e) {
    console.log("❌ Test error: " + e.message);
    return { success: false, message: "Test error: " + e.message };
  }
}

/**
 * Creates a test link for debugging
 */
function createTestLink() {
  return generateLink("Test123!", "This is a test secret message", false);
}