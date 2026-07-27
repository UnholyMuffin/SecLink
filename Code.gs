// ================================================
// ONE-TIME LINK GENERATOR - WITH CUSTOM SECRETS & PASSWORDLESS OPTION
// ================================================

function doGet(e) {
  return HtmlService.createHtmlOutputFromFile('index')
    .setTitle('🔐 One-Time Link Generator')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

// GENERATE LINK with optional password
function generateLink(linkPassword, secretMessage, isPasswordless) {
  const token = Utilities.getUuid();
  const now = new Date().getTime();
  const expiry = now + 60 * 60 * 1000; // 1 hour
  
  let data = {
    secret: secretMessage,
    expiry: expiry,
    used: false,
    passwordless: isPasswordless || false
  };
  
  // Only hash password if not passwordless
  if (!isPasswordless && linkPassword && linkPassword.trim() !== '') {
    const passwordHash = Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256, 
      linkPassword
    ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    data.hash = passwordHash;
  } else {
    // For passwordless, store a flag and no hash
    data.hash = null;
  }
  
  // Save to database
  PropertiesService.getScriptProperties().setProperty('ot_' + token, JSON.stringify(data));
  
  // Generate the one-time URL
  const url = ScriptApp.getService().getUrl() + '?v=view&token=' + encodeURIComponent(token);
  
  return { 
    link: url, 
    token: token, 
    expiry: expiry 
  };
}

// CONSUME one-time link
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
  
  // Handle passwordless links
  if (record.passwordless === true) {
    // SUCCESS! No password needed
    props.deleteProperty(key);
    return { 
      success: true, 
      secret: record.secret,
      message: '✅ Link verified! Your secret is below:'
    };
  }
  
  // Verify password for password-protected links
  if (!enteredPassword || enteredPassword.trim() === '') {
    return { success: false, message: '❌ Please enter a password' };
  }
  
  const attemptHash = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256, 
    enteredPassword
  ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
  
  if (attemptHash !== record.hash) {
    return { success: false, message: '❌ Incorrect password' };
  }
  
  // SUCCESS! Delete immediately and return secret
  props.deleteProperty(key);
  
  return { 
    success: true, 
    secret: record.secret,
    message: '✅ Link verified! Your secret is below:'
  };
}

// Check if link exists and get its type (for recipient view)
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
    return { exists: false };
  }
}

// Clean up expired links (optional - run on time trigger)
function cleanupExpired() {
  const props = PropertiesService.getScriptProperties();
  const all = props.getProperties();
  const now = new Date().getTime();
  
  Object.keys(all).forEach(key => {
    if (key.startsWith('ot_')) {
      try {
        const record = JSON.parse(all[key]);
        if (now > record.expiry || record.used === true) {
          props.deleteProperty(key);
        }
      } catch(e) {}
    }
  });
}