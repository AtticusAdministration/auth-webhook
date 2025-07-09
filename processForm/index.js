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

  const { id, lastName, salt, token, ...formData } = req.body || {};

  if (!id || !lastName || !salt || !token) {
    context.res = {
      status: 400,
      body: "Missing id, lastName, salt, or token",
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

  const tableClient = TableClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING,
    "AuthTable"
  );

  try {
    const entity = await tableClient.getEntity("auth", id);
    if (entity.lastName.toLowerCase() !== lastName.toLowerCase()) {
      throw new Error("LastName mismatch");
    }

    entity.JSON = JSON.stringify(formData);
    await tableClient.updateEntity(entity, "Merge");

    const redirectId = Buffer.from(id).toString("base64");
    const redirectKey = Buffer.from(lastName).toString("base64");
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