const crypto = require("crypto");
const { TableClient } = require("@azure/data-tables");
const { BlobServiceClient } = require("@azure/storage-blob");
const PDFDocument = require('pdfkit');

/**
 * Generates PDF from form template and submission data using PDFKit
 * @param {Object|string} projectFormJson - Form template with steps structure
 * @param {Object} submissionData - User submitted form data
 * @returns {Buffer} PDF buffer
 */
async function generatePdfFromData(projectFormJson, submissionData) {
  return new Promise((resolve, reject) => {
    try {
      let formStructure;
      
      // Parse projectFormJson if it's a string
      try {
        formStructure = typeof projectFormJson === 'string' 
          ? JSON.parse(projectFormJson) 
          : projectFormJson;
      } catch (error) {
        formStructure = { steps: [] };
      }

      const doc = new PDFDocument({ margin: 50 });
      const buffers = [];
      
      // Collect PDF data
      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => {
        const pdfBuffer = Buffer.concat(buffers);
        resolve(pdfBuffer);
      });
      doc.on('error', reject);

      // Header - Extract title from form structure or use default
      const formTitle = formStructure.title || 'Form Submission';
      doc.fontSize(18)
         .fillColor('#4a90e2')
         .font('Helvetica-Bold')
         .text(formTitle, 50, 50, { align: 'center' });
      
      doc.moveDown();
      
      // Submission info
      doc.fontSize(11)
         .fillColor('#666666')
         .text(`Submitted by: ${submissionData.firstName || ''} ${submissionData.middleInitial || ''} ${submissionData.lastName || ''}`.replace(/\s+/g, ' '), { align: 'center' })
         .text(`Submission ID: ${submissionData.submissionId || 'N/A'}`, { align: 'center' })
         .text(`Date: ${new Date().toLocaleDateString()}`, { align: 'center' });
      
      doc.moveDown(1.5);
      
      // Draw a line
      doc.strokeColor('#4a90e2')
         .lineWidth(2)
         .moveTo(50, doc.y)
         .lineTo(545, doc.y)
         .stroke();
      
      doc.moveDown();

      // Process form structure dynamically
      if (formStructure.steps && Array.isArray(formStructure.steps)) {
        formStructure.steps.forEach((step, index) => {
          addStepToPdf(doc, step, submissionData, index + 1);
        });
      } else if (formStructure.fields && Array.isArray(formStructure.fields)) {
        // Handle field-based forms
        formStructure.fields.forEach(field => {
          const value = submissionData[field.name] || submissionData[field.id] || 'Not provided';
          addFormField(doc, field.label || field.name || 'Field', value, field.required);
        });
      } else {
        // Fallback: iterate through submission data
        Object.entries(submissionData).forEach(([key, value]) => {
          if (key !== 'submissionId' && key !== 'projectId') {
            addFormField(doc, formatFieldName(key), value);
          }
        });
      }

      // Footer
      doc.fontSize(10)
         .fillColor('#666666')
         .text('This document was automatically generated from form submission data.', 50, doc.page.height - 100)
         .text(`Project ID: ${submissionData.projectId || 'Unknown'}`, 50, doc.page.height - 85);

      doc.end();
      
    } catch (error) {
      reject(error);
    }
  });
}

/**
 * Adds a form step to the PDF document
 * @param {PDFDocument} doc - PDFKit document instance
 * @param {Object} step - Step object from form structure
 * @param {Object} submissionData - User submitted data
 * @param {number} stepNumber - Step number for display
 */
function addStepToPdf(doc, step, submissionData, stepNumber) {
  // Check if we need a new page
  if (doc.y > doc.page.height - 150) {
    doc.addPage();
  }

  // Step title
  doc.fontSize(14)
     .fillColor('#4a90e2')
     .font('Helvetica-Bold')
     .text(`${stepNumber}. ${step.title}`, 50, doc.y);
  
  doc.moveDown(0.5);

  // Step instruction
  if (step.instruction) {
    doc.fontSize(11)
       .fillColor('#666666')
       .font('Helvetica-Oblique')
       .text(step.instruction, 50, doc.y, { width: 495 });
    
    doc.moveDown(0.5);
  }

  // Add HTML content as text (for informational steps)
  if (step.html) {
    // Clean HTML content for display
    const cleanText = step.html
      .replace(/<[^>]*>/g, ' ')  // Remove HTML tags
      .replace(/&nbsp;/g, ' ')   // Replace &nbsp; with space
      .replace(/\s+/g, ' ')      // Collapse multiple spaces
      .trim();
    
    if (cleanText && cleanText.length > 0) {
      doc.fontSize(10)
         .fillColor('#333333')
         .font('Helvetica')
         .text(cleanText, 60, doc.y, { width: 485 });
      
      doc.moveDown(0.5);
    }

    // Extract and add form fields if present
    const fieldMatches = step.html.match(/name=['"]([^'"]+)['"]/g);
    if (fieldMatches) {
      fieldMatches.forEach(match => {
        const fieldName = match.match(/name=['"]([^'"]+)['"]/)[1];
        const value = submissionData[fieldName];
        if (value !== undefined) {
          addFormField(doc, formatFieldName(fieldName), value);
        }
      });
    }
  }

  doc.moveDown(1);
}

/**
 * Adds a form field to the PDF document
 * @param {PDFDocument} doc - PDFKit document instance
 * @param {string} label - Field label
 * @param {any} value - Field value
 * @param {boolean} required - Whether field is required
 * @param {string} type - Field type (boolean, etc.)
 */
function addFormField(doc, label, value, required = false, type = 'text') {
  // Check if we need a new page
  if (doc.y > doc.page.height - 80) {
    doc.addPage();
  }
  
  const startY = doc.y;
  const fieldHeight = 25;
  
  // Field background
  doc.rect(45, startY - 3, 505, fieldHeight)
     .fillColor('#f9f9f9')
     .fill()
     .strokeColor('#e0e0e0')
     .lineWidth(0.5)
     .stroke();
  
  // Required indicator
  const requiredText = required ? ' *' : '';
  
  // Field label
  doc.fontSize(10)
     .fillColor('#4a90e2')
     .font('Helvetica-Bold')
     .text(label + requiredText + ':', 55, startY + 3);
  
  // Field value
  let displayValue = formatFieldValue(value, type);
  
  doc.fontSize(10)
     .fillColor('#333333')
     .font('Helvetica')
     .text(displayValue, 200, startY + 3, { width: 340 });
  
  doc.y = startY + fieldHeight + 2;
}

/**
 * Formats field names for display
 * @param {string} fieldName - Raw field name
 * @returns {string} Formatted field name
 */
function formatFieldName(fieldName) {
  return fieldName
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, str => str.toUpperCase())
    .trim();
}

/**
 * Formats field values for display
 * @param {any} value - Field value
 * @param {string} type - Field type
 * @returns {string} Formatted value
 */
function formatFieldValue(value, type = 'text') {
  if (value === null || value === undefined || value === '') {
    return 'Not provided';
  }
  
  if (type === 'boolean' || typeof value === 'boolean') {
    return value ? 'Yes' : 'No';
  }
  
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  
  return String(value);
}

/**
 * Uploads PDF to Azure Blob Storage
 * @param {Buffer} pdfBuffer - PDF content as buffer
 * @param {string} fileName - Name for the PDF file
 * @param {string} containerName - Azure Blob container name
 * @returns {string} Public URL of the uploaded PDF
 */
async function uploadPdfToBlob(pdfBuffer, fileName, containerName = 'submissions') {
  const blobServiceClient = BlobServiceClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING
  );
  
  const containerClient = blobServiceClient.getContainerClient(containerName);
  
  // Create container if it doesn't exist
  try {
    await containerClient.createIfNotExists({
      access: 'blob' // Public read access for PDFs
    });
  } catch (error) {
    // Container might already exist, continue
  }
  
  const blobClient = containerClient.getBlockBlobClient(fileName);
  
  await blobClient.upload(pdfBuffer, pdfBuffer.length, {
    blobHTTPHeaders: {
      blobContentType: 'application/pdf'
    }
  });
  
  return blobClient.url;
}

/**
 * Verifies a token's authenticity and expiration status with enhanced validation
 * @param {string} token - Base64 encoded token to verify
 * @param {string} providedSalt - Salt provided from request
 * @param {string} providedExpiresAt - Expiration timestamp from request
 * @param {string} providedValidUntil - Valid until timestamp from request
 * @param {string} id - Expected user ID
 * @param {string} lastName - Expected user's last name
 * @param {string} pid - Expected project ID
 * @returns {Object} Verification result with success flag and details
 */
function verifyEnhancedToken(token, providedSalt, providedExpiresAt, providedValidUntil, id, lastName, pid) {
  try {
    // Decode the token
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const [hmac, tokenSalt, issuedAt, expiresAt] = decoded.split(':');
    
    if (!hmac || !tokenSalt || !issuedAt || !expiresAt) {
      return { valid: false, error: "Invalid token format" };
    }

    // Validate salt consistency
    if (tokenSalt !== providedSalt) {
      return { valid: false, error: "Token salt mismatch" };
    }

    // Validate expiration timestamp consistency
    if (expiresAt !== providedExpiresAt) {
      return { valid: false, error: "Token expiration timestamp mismatch" };
    }

    // Parse timestamps - handle both numeric timestamps and ISO strings
    const now = Date.now();
    const tokenExpirationTime = parseInt(expiresAt);
    
    // Handle tokenValidUntil - could be timestamp number or ISO string
    let providedValidUntilTime;
    if (typeof providedValidUntil === 'string' && providedValidUntil.includes('T')) {
      // ISO string format
      providedValidUntilTime = new Date(providedValidUntil).getTime();
    } else {
      // Timestamp number
      providedValidUntilTime = parseInt(providedValidUntil);
    }

    // Check if token is expired (using token's internal expiration)
    if (now > tokenExpirationTime) {
      return { 
        valid: false, 
        error: "Token expired", 
        expiredAt: new Date(tokenExpirationTime),
        expiredSince: now - tokenExpirationTime
      };
    }

    // Check if token is still within valid until time
    if (now > providedValidUntilTime) {
      return { 
        valid: false, 
        error: "Token validity period exceeded", 
        validUntil: new Date(providedValidUntilTime)
      };
    }
    
    // Recreate the expected HMAC signature using provided salt
    const payload = `${id}:${lastName}:${pid}:${providedSalt}:${issuedAt}:${expiresAt}`;
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
    
    // Calculate remaining time correctly - find the shorter valid period
    const tokenRemainingTime = tokenExpirationTime - now;
    const validUntilRemainingTime = providedValidUntilTime - now;
    
    // Both times should be positive (future) since we already checked expiration above
    // Take the minimum of the two remaining times to get the actual valid period
    const actualRemainingTime = Math.min(tokenRemainingTime, validUntilRemainingTime);
    
    return { 
      valid: true, 
      issuedAt: new Date(parseInt(issuedAt)),
      expiresAt: new Date(tokenExpirationTime),
      validUntil: new Date(providedValidUntilTime),
      remainingTime: actualRemainingTime,
      salt: tokenSalt
    };
    
  } catch (error) {
    return { valid: false, error: "Token verification failed", details: error.message };
  }
}

/**
 * Legacy token verification function (kept for backward compatibility)
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

  const { 
    authToken, 
    tokenSalt, 
    tokenExpiresAt, 
    tokenValidUntil, 
    projectId, 
    id, 
    lastName, 
    ...otherFields 
  } = req.body || {};

  // Validate required fields for enhanced token authentication
  if (!authToken || !tokenSalt || !tokenExpiresAt || !tokenValidUntil || !projectId) {
    context.log("❌ Missing required authentication fields:");
    context.log(`authToken: ${!!authToken}`);
    context.log(`tokenSalt: ${!!tokenSalt}`);
    context.log(`tokenExpiresAt: ${!!tokenExpiresAt}`);
    context.log(`tokenValidUntil: ${!!tokenValidUntil}`);
    context.log(`projectId: ${!!projectId}`);
    
    context.res = {
      status: 400,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      },
      body: { 
        error: "Missing required authentication fields",
        required: ["authToken", "tokenSalt", "tokenExpiresAt", "tokenValidUntil", "projectId"],
        provided: Object.keys(req.body || {}).filter(key => 
          ["authToken", "tokenSalt", "tokenExpiresAt", "tokenValidUntil", "projectId"].includes(key)
        )
      }
    };
    return;
  }

  // Log authentication data for debugging
  context.log("🔐 Authentication fields received:");
  context.log(`  • authToken: ${authToken ? authToken.substring(0, 20) + '...' : 'missing'}`);
  context.log(`  • tokenSalt: ${tokenSalt ? tokenSalt.substring(0, 10) + '...' : 'missing'}`);
  context.log(`  • tokenExpiresAt: ${tokenExpiresAt}`);
  context.log(`  • tokenValidUntil: ${tokenValidUntil}`);
  context.log(`  • projectId: ${projectId}`);

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

  // Verify the authentication token with enhanced validation
  context.log(`🔐 Verifying enhanced token for user ${userId}, project ${projectId}`);
  context.log(`🕒 Token expires at: ${new Date(parseInt(tokenExpiresAt)).toISOString()}`);
  
  // Handle tokenValidUntil - could be timestamp number or ISO string
  const validUntilTimestamp = typeof tokenValidUntil === 'string' && tokenValidUntil.includes('T')
    ? new Date(tokenValidUntil).getTime()
    : parseInt(tokenValidUntil);
    
  context.log(`🕒 Token valid until: ${new Date(validUntilTimestamp).toISOString()}`);
  
  const tokenVerification = verifyEnhancedToken(
    authToken, 
    tokenSalt, 
    tokenExpiresAt, 
    tokenValidUntil, 
    userId, 
    userLastName, 
    projectId
  );
  
  if (!tokenVerification.valid) {
    context.log(`❌ Enhanced token verification failed: ${tokenVerification.error}`);
    if (tokenVerification.expiredAt) {
      context.log(`🕒 Token expired at: ${tokenVerification.expiredAt.toISOString()}`);
    }
    if (tokenVerification.validUntil) {
      context.log(`🕒 Token was valid until: ${tokenVerification.validUntil.toISOString()}`);
    }
    if (tokenVerification.expiredSince) {
      context.log(`🕒 Token expired ${Math.round(tokenVerification.expiredSince / 1000)} seconds ago`);
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
        ...(tokenVerification.expiredAt && { expiredAt: tokenVerification.expiredAt.toISOString() }),
        ...(tokenVerification.validUntil && { validUntil: tokenVerification.validUntil.toISOString() })
      }
    };
    return;
  }

  context.log(`✅ Enhanced token verified successfully for user ${userId}`);
  context.log(`🔐 Token salt validated: ${tokenVerification.salt.substring(0, 10)}...`);
  context.log(`🕒 Token remaining time: ${Math.round(tokenVerification.remainingTime / 1000 / 60)} minutes`);
  context.log(`🕒 Token expires: ${tokenVerification.expiresAt.toISOString()}`);
  context.log(`🕒 Token valid until: ${tokenVerification.validUntil.toISOString()}`);

  // Connect to the Claimants table for user validation
  const claimantsTableClient = TableClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING,
    "Claimants"
  );

  // Connect to the Submissions table for storing form data
  const submissionsTableClient = TableClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING,
    "Submissions"
  );

  try {
    context.log(`🔍 Looking up user entity for RowKey: '${userId}' in Claimants`);
    const entity = await claimantsTableClient.getEntity("auth", userId);
    
    // Double-check lastName matches (defense in depth)
    if (!entity.last_name || entity.last_name.toLowerCase() !== userLastName.toLowerCase()) {
      context.log(`❌ lastName mismatch in table. Expected: ${entity.last_name}, Provided: ${userLastName}`);
      throw new Error("User validation failed");
    }

    context.log(`✅ User validated: ${userId} (${userLastName})`);
    
    // Generate a unique RowKey for the submission
    const submissionId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const submittedAt = new Date().toISOString();
    
    // Get the project form JSON for PDF generation
    const formTableClient = TableClient.fromConnectionString(
      process.env.AZURE_STORAGE_CONNECTION_STRING,
      "FormTableJSON"
    );
    
    let projectFormJson = null;
    try {
      for await (const formEntity of formTableClient.listEntities({ 
        queryOptions: { filter: `PartitionKey eq '${projectId}'` } 
      })) {
        projectFormJson = formEntity.JSON || null;
        context.log("✅ Form JSON found for PDF generation");
        break;
      }
    } catch (e) {
      context.log("⚠️ Error fetching form JSON for PDF:", e.message);
    }

    // Generate PDF using PDFKit
    context.log("📄 Starting PDF generation with PDFKit...");
    const pdfBuffer = await generatePdfFromData(projectFormJson, { ...formData, submissionId, projectId });
    
    // Upload PDF to Azure Blob Storage
    const pdfFileName = `submission-${projectId}-${submissionId}.pdf`;
    const pdfUrl = await uploadPdfToBlob(pdfBuffer, pdfFileName);
    
    context.log("✅ PDF generated and uploaded successfully");
    context.log(`🔗 PDF URL: ${pdfUrl}`);

    // Include PDF URL in the form data for storage
    const formDataWithPdf = {
      ...formData,
      pdfUrl: pdfUrl
    };
    
    // Create submission entity for the Submissions table
    const submissionEntity = {
      partitionKey: "submissions",
      rowKey: submissionId,
      timestamp: submittedAt,
      claimant_id: userId,
      project_id: projectId,
      submission_json: JSON.stringify(formDataWithPdf)
    };
    
    context.log("💾 Creating new submission entity in Submissions table");
    await submissionsTableClient.createEntity(submissionEntity);
    
    context.log("✅ Form data saved successfully to Submissions table");

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
        submittedAt: submittedAt,
        submissionId: submissionId,
        pdfUrl: pdfUrl
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