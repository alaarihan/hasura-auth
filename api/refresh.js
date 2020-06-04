const { verify } = require("jsonwebtoken");
const cookie = require('cookie')
const refreshToken = async (req, res) => {
  if(!req.headers.cookie){
    throw res.status(401).json({ message: "You have to login!" });
  }
  const refresh_token = req.cookies.refresh_token;
  if (!refresh_token) {
    throw res.status(401).json({ message: "You have to login!" });
  }

  let refreshTokenData;
  try {
    refreshTokenData = verify(refresh_token, process.env.JWT_KEY);
  } catch (e) {
    throw res.status(401).send({ message: `Invalid token!` });
  }

  if (!refreshTokenData || !refreshTokenData.userId) {
    throw res.status(401).send({ message: `Invalid refresh token!` });
  }
  const user = await getUser({ id: { _eq: userId } });
  if (!user) {
    throw res.status(401).send({ message: `The refresh token user is not valid anymore!` });
  }
  const userToken = loginUserResponse(user);

  return res.json({
    jwt_token: userToken.jwt_token,
    jwt_expires_in: userToken.jwt_expires_in,
  });
};

module.exports = refreshToken;
