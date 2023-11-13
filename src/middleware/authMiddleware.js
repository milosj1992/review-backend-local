// middleware/authMiddleware.js
const jwt = require("jsonwebtoken");
const jwtConfig = require("../config/jwtConfig");

function verifyToken(req, res, next) {
  const authorizationHeader = req.headers.authorization;

  if (!authorizationHeader) {
    return res.status(401).json({ statusCode: 401, error: "Authentication failed: No token provided" });
  }

  const token = authorizationHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ statusCode: 401, error: "Authentication failed: Token format is invalid" });
  }

  jwt.verify(token, jwtConfig.jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ statusCode: 401, error: "Authentication failed: Token is invalid" });
    }

    req.userData = decoded;
    next();
  });
}

module.exports = {
  verifyToken,
};
