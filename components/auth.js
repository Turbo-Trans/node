const jwt = require("jsonwebtoken");
const con = require("./db");

module.exports = async function (req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ message: "Token eksik" });

  const token = authHeader.split(" ")[1];
  if (!token)
    return res.status(401).json({ message: "Yanlis format" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
    const [rows] = await con.promise().query(
      "SELECT sessionToken FROM user WHERE userID = ?",
      [decoded.userID]
    );

    if (!rows[0] || rows[0].sessionToken !== decoded.sessionToken) {
      return res.status(401).json({
        message: "Bu hesaba baska bir yerden giris yapildi."
      });
    }

    req.user = decoded;
    if (req.skipEmailAuth) {
      return next();
    }

    const [authcheck] = await con.promise().query(
      "SELECT auth FROM user WHERE userID = ?",
      [decoded.userID]
    );

    if (!authcheck[0] || authcheck[0].auth != 1) {
      return res.status(401).json({
        message: "Lutfen Epostanizi onaylayin!"
      });
    }

    next();
  } catch (err) {
    return res.status(401).json({ message: "Gecersiz token" });
  }
};
