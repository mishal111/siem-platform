// Runs only when the isolated deployment volume is first initialized.
const fs = require("fs");
db.getSiblingDB("siem").createUser({
    user: "siem_app",
    pwd: fs.readFileSync("/run/secrets/mongo_app_password", "utf8").trim(),
    roles: [{role: "readWrite", db: "siem"}]
});
