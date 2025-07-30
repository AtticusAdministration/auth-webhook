const crypto = require("crypto");
const { TableClient } = require("@azure/data-tables");

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
    context.log.error("🚨 PEPPER environment variable not configured - tokens cannot be verified");
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
        "Access-Control-Allow-Headers": "Content-Type, ocp-apim-subscription-key, Authorization, x-ms-client-request-id, Accept, Origin, X-Requested-With"
      },
      body: { error: envValidation.error }
    };
    return;
  }

  context.log("📝 Form submission request received");

  // Define allowed origins (same as generateToken)
  const allowedOrigins = [
    "http://localhost:7072",
    "https://newatticus.local",
    "https://www.mighty-geeks.com",
    "https://mighty-geeks.com"
  ];
  
  // Get the origin from the request
  const origin = req.headers.origin;
  const allowedOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

  // Enhanced CORS headers with additional allowed headers
  const corsHeaders = {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, ocp-apim-subscription-key, Authorization, x-ms-client-request-id, Accept, Origin, X-Requested-With",
    "Access-Control-Max-Age": "86400"
  };

  // CORS preflight handler
  if (req.method === "OPTIONS") {
    context.log("✅ CORS preflight handled");
    context.res = {
      status: 200,
      headers: corsHeaders
    };
    return;
  }

  context.log("=== Incoming Form Submission ===");
  context.log("Request body structure:", Object.keys(req.body || {}));
  context.log("Full request body:", JSON.stringify(req.body, null, 2));

  const { authToken, tokenSalt, projectId, id, lastName, ...otherFields } = req.body || {};

  // Validate required fields for new token format
  if (!authToken || !projectId) {
    context.log("❌ Missing required fields for token authentication:");
    context.log(`authToken: ${!!authToken}, projectId: ${projectId}`);
    context.res = {
      status: 400,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      },
      body: { error: "Missing authToken or projectId" }
    };
    return;
  }

  // Extract user credentials - check multiple possible sources
  // Note: id might be empty string, so check for truthy values
  const userId = (id && id.trim()) || (otherFields.id && otherFields.id.trim());
  const userLastName = (lastName && lastName.trim()) || (otherFields.lastName && otherFields.lastName.trim());

  context.log(`🔍 Extracted credentials: userId='${userId}', userLastName='${userLastName}'`);

  if (!userId || !userLastName) {
    context.log("❌ Missing user credentials:");
    context.log(`userId: '${userId}', userLastName: '${userLastName}'`);
    context.log("Available fields:", Object.keys(req.body || {}));
    context.res = {
      status: 400,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      },
      body: { 
        error: "Missing user credentials (id and lastName)",
        debug: {
          userId: userId,
          userLastName: userLastName,
          availableFields: Object.keys(req.body || {})
        }
      }
    };
    return;
  }

  // Reconstruct formData from the payload (includes all fields for storage)
  const formData = {
    id: userId,
    lastName: userLastName,
    ...otherFields
  };

  // Verify the authentication token
  context.log(`🔐 Verifying token for user ${userId}, project ${projectId}`);
  const tokenVerification = verifySecureToken(authToken, userId, userLastName, projectId);
  
  if (!tokenVerification.valid) {
    context.log(`❌ Token verification failed: ${tokenVerification.error}`);
    if (tokenVerification.expiredAt) {
      context.log(`🕒 Token expired at: ${tokenVerification.expiredAt.toISOString()}`);
    }
    context.res = {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      },
      body: { 
        error: "Authentication failed", 
        reason: tokenVerification.error,
        ...(tokenVerification.expiredAt && { expiredAt: tokenVerification.expiredAt.toISOString() })
      }
    };
    return;
  }

  context.log(`✅ Token verified successfully for user ${userId}`);
  context.log(`🕒 Token remaining time: ${Math.round(tokenVerification.remainingTime / 1000 / 60)} minutes`);

  // Connect to the Claimants table for user validation and data storage
  const tableClient = TableClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING,
    "Claimants"
  );

  try {
    context.log(`🔍 Looking up user entity for RowKey: '${userId}' in Claimants`);
    const entity = await tableClient.getEntity("auth", userId);
    
    // Double-check lastName matches (defense in depth)
    if (!entity.last_name || entity.last_name.toLowerCase() !== userLastName.toLowerCase()) {
      context.log(`❌ lastName mismatch in table. Expected: ${entity.last_name}, Provided: ${userLastName}`);
      throw new Error("User validation failed");
    }

    context.log(`✅ User validated: ${userId} (${userLastName})`);
    
    // Store the form data as JSON in the entity
    entity.JSON = JSON.stringify(formData);
    entity.submittedAt = new Date().toISOString();
    entity.projectId = projectId;
    
    context.log("💾 Updating entity with form data");
    await tableClient.updateEntity(entity, "Merge");
    
    context.log("✅ Form data saved successfully");

    // Determine redirect URL (you may want to customize this based on projectId)
    const redirectUrl = `${allowedOrigin}/thank-you?pid=${projectId}`;

    context.res = {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      },
      body: { 
        success: true, 
        message: "Form submitted successfully",
        redirectUrl: redirectUrl,
        submittedAt: entity.submittedAt
      }
    };

  } catch (err) {
    context.log("💥 Error during form processing:", err.message);
    const isUserNotFound = err.statusCode === 404 || err.message.includes("not found");
    
    context.res = {
      status: isUserNotFound ? 404 : 500,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      },
      body: { 
        error: isUserNotFound ? "User not found" : "Form processing failed",
        details: err.message
      }
    };
  }
};