const crypto = require("crypto");
const { TableClient } = require("@azure/data-tables");
const querystring = require("querystring");

module.exports = async function (context, req) {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    context.res = {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "https://newatticus.local",
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

  const { id, lastName, redirectBaseUrl } = body;

  if (!id || !lastName || !redirectBaseUrl) {
    context.log("❌ Missing one or more required fields:");
    context.log(`id: ${id}, lastName: ${lastName}, redirectBaseUrl: ${redirectBaseUrl}`);
    context.res = {
      status: 400,
      headers: {
        "Access-Control-Allow-Origin": "https://newatticus.local",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
      },
      body: "Missing id, lastName, or redirectBaseUrl"
    };
    return;
  }

  const tableClient = TableClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING,
    "AuthTable"
  );

  try {
    context.log(`🔍 Looking up entity for PartitionKey: 'auth', RowKey: '${id}'`);
    const entity = await tableClient.getEntity("auth", id);

    // Fetch ProjectFormJSON entity (PartitionKey: 'ProjectFormJSON', RowKey: id)
    let projectFormJsonEntity;
    try {
      projectFormJsonEntity = await tableClient.getEntity("ProjectFormJSON", id);
      context.log("✅ ProjectFormJSON entity found for id:", id);
    } catch (e) {
      context.log("⚠️ ProjectFormJSON entity not found for id:", id);
      projectFormJsonEntity = null;
    }

    context.log("✅ Entity retrieved:", {
      id: entity.rowKey,
      lastName: entity.lastName,
      hasProjectFormJson: !!projectFormJsonEntity,
      projectFormJsonSize: projectFormJsonEntity && projectFormJsonEntity.JSON
        ? Buffer.byteLength(projectFormJsonEntity.JSON, 'utf8')
        : 0
    });

    if (entity.lastName.toLowerCase() !== lastName.toLowerCase()) {
      context.log(`❌ Last name mismatch. Expected: ${entity.lastName}, Provided: ${lastName}`);
      throw new Error("Unauthorized: lastName mismatch");
    }

    const salt = crypto.randomBytes(8).toString("hex");
    const payload = `${id}:${lastName}:${salt}`;
    const hmac = crypto.createHmac("sha256", process.env.PEPPER)
      .update(payload)
      .digest("hex");

    const token = Buffer.from(`${hmac}:${salt}`).toString("base64");
    const redirectUrl = `${redirectBaseUrl}?id=${id}&lastName=${lastName}&salt=${salt}&token=${encodeURIComponent(token)}`;
    context.log(`🚀 Redirecting to: ${redirectUrl}`);

    // Fetch ProjectFormJSON column from the main entity (PartitionKey: 'auth', RowKey: id)
    const projectFormJson = entity.ProjectFormJSON || null;
    context.log("✅ ProjectFormJSON column found in entity:", !!projectFormJson, projectFormJson ? `size: ${Buffer.byteLength(projectFormJson, 'utf8')}` : '');

    context.res = {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "https://newatticus.local",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
      },
      body: {
        projectFormJson: projectFormJson,
        projectId: id,
        redirectUrl
      }
    };

  } catch (err) {
    context.log("💥 Error during lookup or validation:", err.message);
    context.res = {
      status: 401,
      headers: {
        "Access-Control-Allow-Origin": "https://newatticus.local",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
      },
      body: "Invalid ID or lastName"
    };
  }
};