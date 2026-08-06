// ================================================
// SECURE ONE-TIME LINK GENERATOR - v1.5
// Google Apps Script
// ================================================

function doGet(e) {
  return HtmlService.createHtmlOutputFromFile('index')
    .setTitle('🔐 One-Time Link')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

// ================================================
// ENCRYPTION
// ================================================

function encryptSecret(text, password) {
  if (!text || !password) {
    throw new Error('Text and password required');
  }
  
  const salt = Utilities.getUuid().replace(/-/g, '').substring(0, 16);
  const iv = Utilities.getUuid().replace(/-/g, '').substring(0, 16);
  
  const keyMaterial = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    password + salt + iv
  ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
  
  const key = keyMaterial.substring(0, 32);
  const combinedKey = key + iv;
  
  const textBytes = Utilities.newBlob(text).getBytes();
  const keyBytes = Utilities.newBlob(combinedKey).getBytes();
  
  const encryptedBytes = [];
  for (let i = 0; i < textBytes.length; i++) {
    const keyByte = keyBytes[i % keyBytes.length];
    encryptedBytes.push(textBytes[i] ^ keyByte);
  }
  
  const encryptedBase64 = Utilities.base64Encode(encryptedBytes);
  
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

function decryptSecret(encryptedBase64, password, iv, salt, hmac) {
  if (!encryptedBase64 || !password || !iv || !salt) {
    throw new Error('Missing required parameters');
  }
  
  try {
    const hmacCheck = Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256,
      encryptedBase64 + password + salt
    ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    
    if (hmac && hmac !== hmacCheck.substring(0, 32)) {
      throw new Error('Integrity check failed');
    }
    
    const keyMaterial = Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256,
      password + salt + iv
    ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    
    const key = keyMaterial.substring(0, 32);
    const combinedKey = key + iv;
    
    const encryptedBytes = Utilities.base64Decode(encryptedBase64);
    const keyBytes = Utilities.newBlob(combinedKey).getBytes();
    
    const decryptedBytes = [];
    for (let i = 0; i < encryptedBytes.length; i++) {
      const keyByte = keyBytes[i % keyBytes.length];
      decryptedBytes.push(encryptedBytes[i] ^ keyByte);
    }
    
    return Utilities.newBlob(decryptedBytes).getDataAsString();
  } catch (e) {
    throw new Error('Decryption failed');
  }
}

// ================================================
// RATE LIMITING - 5 links per minute
// ================================================

function checkRateLimit() {
  try {
    const userEmail = Session.getActiveUser().getEmail();
    const props = PropertiesService.getScriptProperties();
    const key = 'rate_limit_' + userEmail;
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    const maxLinks = 5;
    
    const storedData = props.getProperty(key);
    let data = { count: 0, timestamp: now, requests: [] };
    
    if (storedData) {
      try {
        data = JSON.parse(storedData);
        if (now - data.timestamp > windowMs) {
          data = { count: 0, timestamp: now, requests: [] };
        }
      } catch(e) {
        data = { count: 0, timestamp: now, requests: [] };
      }
    }
    
    if (data.count >= maxLinks) {
      const oldestRequest = data.requests[0] || data.timestamp;
      const waitTime = Math.ceil((oldestRequest + windowMs - now) / 1000);
      return { 
        allowed: false, 
        message: '❌ Please wait ' + waitTime + ' seconds' 
      };
    }
    
    data.count++;
    data.timestamp = now;
    data.requests.push(now);
    data.requests = data.requests.filter(time => now - time < windowMs);
    
    props.setProperty(key, JSON.stringify(data));
    
    return { 
      allowed: true, 
      remaining: maxLinks - data.count,
      limit: maxLinks
    };
  } catch (e) {
    console.log('Rate limit check failed: ' + e.message);
    return { allowed: true };
  }
}

function getRateLimitStatus() {
  try {
    const userEmail = Session.getActiveUser().getEmail();
    const props = PropertiesService.getScriptProperties();
    const key = 'rate_limit_' + userEmail;
    const now = Date.now();
    const windowMs = 60000;
    const maxLinks = 5;
    
    const storedData = props.getProperty(key);
    if (!storedData) {
      return { remaining: maxLinks, limit: maxLinks };
    }
    
    try {
      const data = JSON.parse(storedData);
      if (now - data.timestamp > windowMs) {
        return { remaining: maxLinks, limit: maxLinks };
      }
      return { 
        remaining: Math.max(0, maxLinks - data.count), 
        limit: maxLinks 
      };
    } catch(e) {
      return { remaining: maxLinks, limit: maxLinks };
    }
  } catch(e) {
    return { remaining: 5, limit: 5 };
  }
}

// ================================================
// CORE FUNCTIONS
// ================================================

function generateLink(linkPassword, secretMessage, isPasswordless) {
  const rateLimit = checkRateLimit();
  if (!rateLimit.allowed) {
    throw new Error(rateLimit.message);
  }
  
  if (!secretMessage || secretMessage.trim() === '') {
    throw new Error('Secret message cannot be empty');
  }
  
  const token = Utilities.getUuid();
  const now = new Date().getTime();
  const expiry = now + 60 * 60 * 1000;
  
  let data = {
    expiry: expiry,
    used: false,
    passwordless: isPasswordless || false,
    attempts: 0
  };
  
  try {
    if (isPasswordless || !linkPassword || linkPassword.trim() === '') {
      const randomKey = Utilities.getUuid().replace(/-/g, '').substring(0, 32);
      const encryptionResult = encryptSecret(secretMessage, randomKey);
      
      data.encryptedSecret = encryptionResult.encrypted;
      data.iv = encryptionResult.iv;
      data.salt = encryptionResult.salt;
      data.hmac = encryptionResult.hmac;
      data.randomKey = randomKey;
      data.hash = null;
    } else {
      const passwordHash = Utilities.computeDigest(
        Utilities.DigestAlgorithm.SHA_256, 
        linkPassword
      ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
      
      const encryptionResult = encryptSecret(secretMessage, linkPassword);
      
      data.encryptedSecret = encryptionResult.encrypted;
      data.iv = encryptionResult.iv;
      data.salt = encryptionResult.salt;
      data.hmac = encryptionResult.hmac;
      data.hash = passwordHash;
      data.randomKey = null;
    }
  } catch (e) {
    throw new Error('Failed to encrypt: ' + e.message);
  }
  
  try {
    PropertiesService.getScriptProperties().setProperty('ot_' + token, JSON.stringify(data));
  } catch (e) {
    throw new Error('Failed to save link');
  }
  
  const url = ScriptApp.getService().getUrl() + '?v=view&token=' + encodeURIComponent(token);
  
  return { 
    link: url, 
    token: token, 
    expiry: expiry,
    rateLimit: {
      remaining: rateLimit.remaining || 5,
      limit: 5
    }
  };
}

function consumeLink(token, enteredPassword) {
  const props = PropertiesService.getScriptProperties();
  const key = 'ot_' + token;
  const storedJson = props.getProperty(key);
  
  if (!storedJson) {
    return { success: false, message: '❌ Not found' };
  }
  
  let record;
  try { 
    record = JSON.parse(storedJson); 
  } catch (e) { 
    props.deleteProperty(key);
    return { success: false, message: '❌ Invalid' }; 
  }
  
  if (record.used === true) { 
    props.deleteProperty(key); 
    return { success: false, message: '❌ Already used' }; 
  }
  
  const now = new Date().getTime();
  if (now > record.expiry) { 
    props.deleteProperty(key); 
    return { success: false, message: '❌ Expired' }; 
  }
  
  let secret = null;
  
  try {
    if (record.passwordless === true) {
      if (!record.randomKey) {
        props.deleteProperty(key);
        return { success: false, message: '❌ Invalid' };
      }
      
      secret = decryptSecret(
        record.encryptedSecret,
        record.randomKey,
        record.iv,
        record.salt,
        record.hmac
      );
    } else {
      if (!enteredPassword || enteredPassword.trim() === '') {
        return { success: false, message: '❌ Enter password' };
      }
      
      const attemptHash = Utilities.computeDigest(
        Utilities.DigestAlgorithm.SHA_256, 
        enteredPassword
      ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
      
      if (attemptHash !== record.hash) {
        record.attempts = (record.attempts || 0) + 1;
        
        if (record.attempts >= 5) {
          props.deleteProperty(key);
          return { success: false, message: '❌ Too many attempts' };
        }
        
        props.setProperty(key, JSON.stringify(record));
        return { success: false, message: '❌ Wrong password' };
      }
      
      secret = decryptSecret(
        record.encryptedSecret,
        enteredPassword,
        record.iv,
        record.salt,
        record.hmac
      );
    }
  } catch (e) {
    props.deleteProperty(key);
    return { 
      success: false, 
      message: '❌ Failed to decrypt'
    };
  }
  
  props.deleteProperty(key);
  
  return { 
    success: true, 
    secret: secret,
    message: '✅ Success'
  };
}

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
        props.deleteProperty(key);
        count++;
      }
    }
  });
  
  return count;
}