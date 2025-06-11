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
  const { id, lastName, salt, token, ...formData } = req.body || {};

  if (!id || !lastName || !salt || !token) {
    context.res = { status: 400, body: "Missing id, lastName, salt, or token" };
    return;
  }

  if (!verifyToken(id, lastName, salt, token)) {
    context.res = { status: 401, body: "Token verification failed" };
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

    const redirectId = Buffer.from(id).toString("base64");
    const redirectKey = Buffer.from(lastName).toString("base64");
    const redirectUrl = `https://newatticus.local/gpt-test/?id=${redirectId}&key=${redirectKey}`;

    context.res = {
      status: 302,
      headers: {
        Location: redirectUrl
      }
    };

  } catch (err) {
    context.res = {
      status: err.statusCode === 404 ? 404 : 500,
      body: err.message
    };
  }
};