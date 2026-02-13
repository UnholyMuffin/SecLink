// ================================================
// ONE-TIME LINK GENERATOR - WITH CUSTOM SECRETS
// ================================================

function doGet(e) {
  return HtmlService.createHtmlOutputFromFile('index')
    .setTitle('🔐 One-Time Link Generator')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

// GENERATE LINK with custom password AND custom secret
function generateLink(linkPassword, secretMessage) {
  const token = Utilities.getUuid();
  const now = new Date().getTime();
  const expiry = now + 60 * 60 * 1000; // 1 hour
  
  // Hash the link password (what recipient needs to enter)
  const passwordHash = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256, 
    linkPassword
  ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
  
  // Store everything
  const data = {
    hash: passwordHash,
    secret: secretMessage,     // YOUR CUSTOM MESSAGE HERE
    expiry: expiry,
    used: false
  };
  
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
  
  // Verify password
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