const crypto = require("crypto");
const { TableClient } = require("@azure/data-tables");
const querystring = require("querystring");

/**
 * Generates a secure authentication token for form submission with expiration
 * Uses HMAC-SHA256 with server-side secret (PEPPER) for cryptographic security
 * @param {string} id - User ID
 * @param {string} lastName - User's last name
 * @param {string} pid - Project ID
 * @returns {Object} Token data including base64 token, salt, timestamps, and expiration info
 */
function generateSecureToken(id, lastName, pid) {
  // Generate cryptographically secure random salt
  const salt = crypto.randomBytes(16).toString('hex');
  const issuedAt = Date.now();
  const expiresAt = issuedAt + (15 * 60 * 1000); // 15 minutes from now
  const expiresIn = 15 * 60 * 1000; // 15 minutes in milliseconds
  
  // Create payload with expiration data
  const payload = `${id}:${lastName}:${pid}:${salt}:${issuedAt}:${expiresAt}`;
  
  // Create HMAC signature using server secret (PEPPER)
  // This prevents token forgery as attackers don't have the PEPPER
  const hmac = crypto.createHmac("sha256", process.env.PEPPER)
    .update(payload)
    .digest("hex");
  
  // Encode token components as base64 for safe transport
  // Format: hmac:salt:issuedAt:expiresAt
  const tokenPayload = `${hmac}:${salt}:${issuedAt}:${expiresAt}`;
  const token = Buffer.from(tokenPayload).toString("base64");
  
  return { 
    token, 
    salt, 
    issuedAt, 
    expiresAt, 
    expiresIn,
    // Helper for easy expiration checking
    isExpired: () => Date.now() > expiresAt
  };
}

/**
 * Verifies a token's authenticity and expiration status
 * @param {string} token - Base64 encoded token to verify
 * @param {string} id - Expected user ID
 * @param {string} lastName - Expected user's last name
 * @param {string} pid - Expected project ID
 * @returns {Object} Verification result with success flag and details
 */
function verifySecureToken(token, id, lastName, pid) {
  try {
    // Decode the token
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const [hmac, salt, issuedAt, expiresAt] = decoded.split(':');
    
    if (!hmac || !salt || !issuedAt || !expiresAt) {
      return { valid: false, error: "Invalid token format" };
    }
    
    // Check if token is expired
    const now = Date.now();
    const expirationTime = parseInt(expiresAt);
    if (now > expirationTime) {
      return { valid: false, error: "Token expired", expiredAt: new Date(expirationTime) };
    }
    
    // Recreate the expected HMAC signature
    const payload = `${id}:${lastName}:${pid}:${salt}:${issuedAt}:${expiresAt}`;
    const expectedHmac = crypto.createHmac("sha256", process.env.PEPPER)
      .update(payload)
      .digest("hex");
    
    // Use crypto.timingSafeEqual to prevent timing attacks
    const hmacBuffer = Buffer.from(hmac, 'hex');
    const expectedHmacBuffer = Buffer.from(expectedHmac, 'hex');
    
    if (hmacBuffer.length !== expectedHmacBuffer.length || 
        !crypto.timingSafeEqual(hmacBuffer, expectedHmacBuffer)) {
      return { valid: false, error: "Invalid token signature" };
    }
    
    return { 
      valid: true, 
      issuedAt: new Date(parseInt(issuedAt)),
      expiresAt: new Date(expirationTime),
      remainingTime: expirationTime - now
    };
    
  } catch (error) {
    return { valid: false, error: "Token verification failed", details: error.message };
  }
}

/**
 * Validates environment configuration required for secure operation
 * @param {Object} context - Azure Function context for logging
 * @returns {Object} Validation result with success flag and error message
 */
function validateEnvironment(context) {
  if (!process.env.PEPPER) {
    context.log.error("🚨 PEPPER environment variable not configured - tokens cannot be generated securely");
    return { valid: false, error: "Server configuration error" };
  }
  
  if (!process.env.AZURE_STORAGE_CONNECTION_STRING) {
    context.log.error("🚨 AZURE_STORAGE_CONNECTION_STRING not configured");
    return { valid: false, error: "Storage configuration error" };
  }
  
  return { valid: true };
}

module.exports = async function (context, req) {
  // Validate environment configuration first
  const envValidation = validateEnvironment(context);
  if (!envValidation.valid) {
    context.res = {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
      },
      body: { error: envValidation.error }
    };
    return;
  }

  context.log("🔐 Token generation request received");

  // Define allowed origins
  const allowedOrigins = [
    "http://localhost:8000",
    "https://newatticus.local",
    "https://www.mighty-geeks.com",
    "https://mighty-geeks.com"
  ];
  
  // Get the origin from the request
  const origin = req.headers.origin;
  const allowedOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    context.res = {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": allowedOrigin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "86400"
      }
    };
    return;
  }

  context.log("=== Incoming Request Body ===");
  context.log(req.body);

  // Parse form-encoded body if needed
  let body = req.body;
  if (typeof body === "string") {
    body = querystring.parse(body);
  }

  const { id, lastName, redirectBaseUrl, pid } = body;

  if (!id || !lastName || !redirectBaseUrl || !pid) {
    context.log("❌ Missing one or more required fields:");
    context.log(`id: ${id}, lastName: ${lastName}, redirectBaseUrl: ${redirectBaseUrl}, pid: ${pid}`);
    context.res = {
      status: 400,
      headers: {
        "Access-Control-Allow-Origin": allowedOrigin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
      },
      body: "Missing id, lastName, redirectBaseUrl, or pid"
    };
    return;
  }

  const tableClient = TableClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING,
    "Claimants"
  );

  // Add TableClient for FormTableJSON
  const formTableClient = TableClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING,
    "FormTableJSON"
  );

  try {
    context.log(`🔍 Looking up entity for RowKey: '${id}' in Claimants`);
    const entity = await tableClient.getEntity("auth", id); // Empty PartitionKey for single partition tables

    // Check last_name property (case-insensitive)
    if (!entity.last_name || entity.last_name.toLowerCase() !== lastName.toLowerCase()) {
      context.log(`❌ last_name mismatch. Expected: ${entity.last_name}, Provided: ${lastName}`);
      throw new Error("Unauthorized: last_name mismatch");
    }

    // Fetch form JSON from FormTableJSON where PartitionKey == pid (ignore RowKey)
    let projectFormJson = null;
    try {
      let found = false;
      for await (const formEntity of formTableClient.listEntities({ queryOptions: { filter: `PartitionKey eq '${pid}'` } })) {
        projectFormJson = formEntity.JSON || null;
        context.log("✅ Form JSON found for pid:", pid, "RowKey:", formEntity.rowKey);
        // Test if projectFormJson is valid JSON (if it's a string)
        if (typeof projectFormJson === 'string') {
          try {
            const parsed = JSON.parse(projectFormJson);
            context.log('[DEBUG] projectFormJson is valid JSON.');
          } catch (jsonErr) {
            context.log('[ERROR] projectFormJson is NOT valid JSON:', jsonErr.message);
            context.log('[ERROR] Offending JSON string:', projectFormJson);
          }
        } else {
          context.log('[DEBUG] projectFormJson is already an object/array.');
        }
        found = true;
        break;
      }
      if (!found) {
        context.log("⚠️ Form JSON not found for pid:", pid);
      }
    } catch (e) {
      context.log("⚠️ Error during FormTableJSON lookup for pid:", pid, e.message || e);
    }

    // Generate secure authentication token for this validated user
    const tokenData = generateSecureToken(id, lastName, pid);
    context.log(`🔑 Secure token generated for user ${id}`);
    context.log(`🕒 Token expires at: ${new Date(tokenData.expiresAt).toISOString()}`);
    context.log(`⏱️ Token valid for: ${Math.round(tokenData.expiresIn / 1000 / 60)} minutes`);

    // Removed debug log of response body as requested
    context.res = {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": allowedOrigin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
      },
      body: {
        projectFormJson: projectFormJson,
        projectId: pid,
        redirectUrl: redirectBaseUrl,
        id: id, // Return the user ID for form submission
        lastName: lastName,
        // Add secure token data for authenticated form submission
        authToken: tokenData.token,
        tokenSalt: tokenData.salt,
        tokenIssuedAt: tokenData.issuedAt,
        tokenExpiresAt: tokenData.expiresAt,
        tokenExpiresIn: tokenData.expiresIn, // milliseconds until expiration
        // Helper for frontend to check expiration
        tokenValidUntil: new Date(tokenData.expiresAt).toISOString()
      }
    };
  } catch (err) {
    context.log("💥 Error during lookup or validation:", err.message);
    context.res = {
      status: 401,
      headers: {
        "Access-Control-Allow-Origin": allowedOrigin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
      },
      body: "Invalid ID or last_name"
    };
  }
};