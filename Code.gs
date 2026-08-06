// ================================================
// SECURE ONE-TIME LINK GENERATOR - v2.0 (E2EE)
// Google Apps Script - End-to-End Encrypted
// ================================================

function doGet(e) {
  // Enforce secure framing (default mode denies embedding in unauthorized frames)
  return HtmlService.createHtmlOutputFromFile('index')
    .setTitle('🔐 One-Time Link')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

// ================================================
// RATE LIMITING & LOCKING
// ================================================

function checkRateLimit() {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) {
    return { allowed: false, message: '❌ System busy, please try again.' };
  }

  try {
    // Session.getTemporaryActiveUserKey() handles unauthenticated/anonymous users safely
    const userKey = Session.getTemporaryActiveUserKey() || 'anon_user';
    const props = PropertiesService.getScriptProperties();
    const key = 'rl_' + userKey;
    const now = Date.now();
    const windowMs = 60000; // 1 minute window
    const maxLinks = 5;

    const storedData = props.getProperty(key);
    let data = { count: 0, timestamp: now, requests: [] };

    if (storedData) {
      try {
        data = JSON.parse(storedData);
        if (now - data.timestamp > windowMs) {
          data = { count: 0, timestamp: now, requests: [] };
        }
      } catch (e) {
        data = { count: 0, timestamp: now, requests: [] };
      }
    }

    data.requests = data.requests.filter(time => now - time < windowMs);

    if (data.requests.length >= maxLinks) {
      const oldestRequest = data.requests[0] || data.timestamp;
      const waitTime = Math.ceil((oldestRequest + windowMs - now) / 1000);
      return {
        allowed: false,
        message: '❌ Limit exceeded. Please wait ' + Math.max(1, waitTime) + ' seconds.'
      };
    }

    data.count = data.requests.length + 1;
    data.timestamp = now;
    data.requests.push(now);

    props.setProperty(key, JSON.stringify(data));

    return {
      allowed: true,
      remaining: maxLinks - data.count,
      limit: maxLinks
    };
  } catch (e) {
    console.error('Rate limit error: ' + e.message);
    return { allowed: true, remaining: 5, limit: 5 };
  } finally {
    lock.releaseLock();
  }
}

function getRateLimitStatus() {
  try {
    const userKey = Session.getTemporaryActiveUserKey() || 'anon_user';
    const props = PropertiesService.getScriptProperties();
    const storedData = props.getProperty('rl_' + userKey);
    const maxLinks = 5;

    if (!storedData) return { remaining: maxLinks, limit: maxLinks };

    const data = JSON.parse(storedData);
    const now = Date.now();
    const activeRequests = (data.requests || []).filter(time => now - time < 60000);

    return {
      remaining: Math.max(0, maxLinks - activeRequests.length),
      limit: maxLinks
    };
  } catch (e) {
    return { remaining: 5, limit: 5 };
  }
}

// ================================================
// STORAGE & PAYLOAD HANDLING
// ================================================

function saveSecretPayload(encryptedData) {
  const rateLimit = checkRateLimit();
  if (!rateLimit.allowed) {
    throw new Error(rateLimit.message);
  }

  if (!encryptedData || !encryptedData.ciphertext || !encryptedData.iv) {
    throw new Error('Invalid secret payload');
  }

  const token = Utilities.getUuid();
  const now = Date.now();
  const expiry = now + (60 * 60 * 1000); // 1 hour TTL

  const record = {
    ciphertext: encryptedData.ciphertext,
    iv: encryptedData.iv,
    salt: encryptedData.salt || null,
    passwordless: !!encryptedData.passwordless,
    expiry: expiry
  };

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) {
    throw new Error('Server busy, storage lock timeout');
  }

  try {
    PropertiesService.getScriptProperties().setProperty('ot_' + token, JSON.stringify(record));
  } catch (e) {
    throw new Error('Storage limit exceeded or failed to save secret');
  } finally {
    lock.releaseLock();
  }

  const baseUrl = ScriptApp.getService().getUrl();
  const url = baseUrl + '?v=view&token=' + encodeURIComponent(token);

  return {
    url: url,
    token: token,
    expiry: expiry,
    rateLimit: rateLimit
  };
}

function fetchSecretPayload(token) {
  if (!token) return { success: false, message: '❌ Invalid token' };

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) {
    return { success: false, message: '❌ Server busy' };
  }

  const props = PropertiesService.getScriptProperties();
  const key = 'ot_' + token;

  try {
    const storedJson = props.getProperty(key);
    if (!storedJson) {
      return { success: false, message: '❌ Secret not found or already consumed' };
    }

    let record;
    try {
      record = JSON.parse(storedJson);
    } catch (e) {
      props.deleteProperty(key);
      return { success: false, message: '❌ Corrupted payload' };
    }

    // Immediately burn payload upon retrieval (One-Time Access)
    props.deleteProperty(key);

    if (Date.now() > record.expiry) {
      return { success: false, message: '❌ Link expired' };
    }

    return {
      success: true,
      ciphertext: record.ciphertext,
      iv: record.iv,
      salt: record.salt,
      passwordless: record.passwordless
    };
  } finally {
    lock.releaseLock();
  }
}

function checkLinkExists(token) {
  if (!token) return { exists: false };

  const props = PropertiesService.getScriptProperties();
  const storedJson = props.getProperty('ot_' + token);

  if (!storedJson) return { exists: false };

  try {
    const record = JSON.parse(storedJson);
    if (Date.now() > record.expiry) {
      return { exists: false };
    }
    return {
      exists: true,
      passwordless: record.passwordless
    };
  } catch (e) {
    return { exists: false };
  }
}

function cleanupExpired() {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return 0;

  let count = 0;
  try {
    const props = PropertiesService.getScriptProperties();
    const all = props.getProperties();
    const now = Date.now();

    Object.keys(all).forEach(key => {
      if (key.startsWith('ot_')) {
        try {
          const record = JSON.parse(all[key]);
          if (now > record.expiry) {
            props.deleteProperty(key);
            count++;
          }
        } catch (e) {
          props.deleteProperty(key);
          count++;
        }
      }
    });
  } finally {
    lock.releaseLock();
  }
  return count;
}