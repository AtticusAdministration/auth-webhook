const { TableClient } = require("@azure/data-tables");

function toBase64(str) {
  return Buffer.from(str, 'utf-8').toString('base64');
}

module.exports = async function (context, req) {
  const id = req.query.id || req.body?.id;
  const lastName = req.query.lastName || req.body?.lastName;

  if (!id || !lastName) {
    context.res = {
      status: 400,
      body: "Missing 'id' or 'lastName'"
    };
    return;
  }

  const tableClient = TableClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING,
    "AuthTable"
  );

  try {
    const entity = await tableClient.getEntity("auth", id);

    if (entity.lastName.toLowerCase() === lastName.toLowerCase()) {
      const redirectUrl = `https://newatticus.local/gpt-test/?id=${toBase64(id)}&key=${toBase64(lastName)}`;
      context.res = {
        status: 302,
        headers: { Location: redirectUrl }
      };
    } else {
      context.res = { status: 401, body: "Unauthorized: lastName mismatch" };
    }
  } catch (err) {
    context.res = {
      status: err.statusCode === 404 ? 404 : 500,
      body: err.statusCode === 404 ? "Entity not found" : `Server error: ${err.message}`
    };
  }
};