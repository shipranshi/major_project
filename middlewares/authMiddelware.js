const JWT = require("jsonwebtoken");

module.exports = async (req, res, next) => {
  try {
    // Check if Authorization header exists
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send({
        success: false,
        message: "Unauthorized: Missing or invalid token",
      });
    }

    // Extract token from Authorization header
    const token = authHeader.split(" ")[1];
    
    // Verify JWT token
    JWT.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).send({
          success: false,
          message: "Unauthorized: Failed to authenticate token",
        });
      } else {
        // Attach decoded user ID to request object for later use
        req.body.userId = decoded.userId;
        next(); // Proceed to the next middleware or route handler
      }
    });
  } catch (error) {
    console.error("Auth Middleware Error:", error);
    return res.status(500).send({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};
