const { compare } = require("bcrypt");
const { getUser, loginUserResponse } = require("./lib/common");

const login = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(403).send('Forbidden!');
  }
  const { email, password } = req.body.input;

  const user = await getUser({ email: { _eq: email } });
  if (!user) {
    throw res
      .status(401)
      .send({ message: `No account found for this email: ${email}` });
  }

  const passwordValid = await compare(password, user.password);
  if (!passwordValid) {
    throw res.status(401).send({ message: "Invalid email or password!" });
  }

  const userToken = loginUserResponse(user);

  if (userToken && userToken.refresh_token) {
    res.cookie("refresh_token", userToken.refresh_token, {
      httpOnly: true,
      maxAge: 43200 * 60 * 1000,
    });
  }
  // success
  return res.json({
    jwt_token: userToken.jwt_token,
    jwt_expires_in: userToken.jwt_expires_in,
  });
};

module.exports = login;
