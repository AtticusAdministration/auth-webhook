const crypto = require("crypto");
const { TableClient } = require("@azure/data-tables");

module.exports = async function (context, req) {
  context.log("=== Incoming Request Body ===");
  context.log(req.body);

  const { id, lastName, redirectBaseUrl } = req.body || {};

  if (!id || !lastName || !redirectBaseUrl) {
    context.log("❌ Missing one or more required fields:");
    context.log(`id: ${id}, lastName: ${lastName}, redirectBaseUrl: ${redirectBaseUrl}`);

    context.res = {
      status: 400,
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
    context.log("✅ Entity retrieved:", entity);

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
    const redirectUrl = `${redirectBaseUrl}?idSalted=${id}${salt}&lastNameSalted=${lastName}${salt}&token=${encodeURIComponent(token)}`;

    context.log(`🚀 Redirecting to: ${redirectUrl}`);

    context.res = {
      status: 302,
      headers: {
        Location: redirectUrl
      }
    };

  } catch (err) {
    context.log("💥 Error during lookup or validation:", err.message);
    context.res = {
      status: 401,
      body: "Invalid ID or lastName"
    };
  }
};