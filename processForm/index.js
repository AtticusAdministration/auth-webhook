const crypto = require("crypto");
const { TableClient } = require("@azure/data-tables");

function verifyToken(id, lastName, salt, tokenB64) {
  const [hmacFromToken, saltFromToken] = Buffer.from(tokenB64, "base64").toString().split(":");
  const expected = crypto.createHmac("sha256", process.env.PEPPER)
    .update(`${id}:${lastName}:${saltFromToken}`)
    .digest("hex");
  return hmacFromToken === expected;
}

module.exports = async function (context, req) {
  // CORS preflight handler
  if (req.method === "OPTIONS") {
    context.res = {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "https://newatticus.local",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, ocp-apim-subscription-key"
      }
    };
    return;
  }

  const { id, lastName, salt, token, pid, ...formData } = req.body || {};

  if (!id || !lastName || !salt || !token || !pid) {
    context.res = {
      status: 400,
      body: "Missing id, lastName, salt, token, or pid",
      headers: {
        "Access-Control-Allow-Origin": "https://newatticus.local",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, ocp-apim-subscription-key"
      }
    };
    return;
  }

  if (!verifyToken(id, lastName, salt, token)) {
    context.res = {
      status: 401,
      body: "Token verification failed",
      headers: {
        "Access-Control-Allow-Origin": "https://newatticus.local",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, ocp-apim-subscription-key"
      }
    };
    return;
  }

  const claimantTableClient = TableClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING,
    "ClaimantTable"
  );

  // Log connection string (account name only), table name, and request body for debugging
  const connStr = process.env.AZURE_STORAGE_CONNECTION_STRING || '';
  const accountNameMatch = connStr.match(/AccountName=([^;]+)/);
  const accountName = accountNameMatch ? accountNameMatch[1] : 'unknown';
  context.log("[DEBUG] Using storage account:", accountName);
  context.log("[DEBUG] Using table:", "ClaimantTable");
  context.log("[DEBUG] Request body:", req.body);

  try {
    // Prepare data for ClaimantTable (exclude id and pid)
    const claimantData = { ...req.body };
    delete claimantData.id;
    delete claimantData.pid;

    context.log("Attempting to insert into ClaimantTable", {
      partitionKey: "claimant",
      rowKey: "[random]",
      JSON: JSON.stringify(claimantData),
      pid: pid
    });

    // Insert new record into ClaimantTable
    await claimantTableClient.createEntity({
      partitionKey: "claimant",
      rowKey: crypto.randomUUID(),
      JSON: JSON.stringify(claimantData),
      pid: pid
    });

    context.log("Successfully inserted into ClaimantTable");

    const redirectUrl = `https://newatticus.local/thank-you`;

    context.res = {
      status: 302,
      headers: {
        Location: redirectUrl,
        "Access-Control-Allow-Origin": "https://newatticus.local",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, ocp-apim-subscription-key"
      }
    };

  } catch (err) {
    context.log("Error inserting into ClaimantTable", err);
    context.res = {
      status: err.statusCode === 404 ? 404 : 500,
      body: err.message,
      headers: {
        "Access-Control-Allow-Origin": "https://newatticus.local",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, ocp-apim-subscription-key"
      }
    };
  }
};