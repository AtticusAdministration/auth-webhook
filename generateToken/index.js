const crypto = require("crypto");
const { TableClient } = require("@azure/data-tables");
const querystring = require("querystring");

module.exports = async function (context, req) {
  // Define allowed origins
  const allowedOrigins = [
    "http://localhost:8000",
    "https://newatticus.local",
    "https://www.mighty-geeks.com"
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
        redirectUrl: redirectBaseUrl
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