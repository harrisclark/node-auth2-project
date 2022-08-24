const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model')

router.post("/register", validateRoleName, (req, res, next) => {
  try {
    const hash = bcrypt.hashSync(req.body.password, 10);

    Users.add({ username: req.body.username, password: hash, role_name: req.role_name })
      .then(result => {
        //console.log(result)
        res.status(201).json(result)
      })
  } catch(err) {
    next(err)
  }
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  try{
    const { password } = req.body;
    // console.log(req.user)
    // console.log(username, password)

    if (bcrypt.compareSync(password, req.user.password)) {
      const token = generateJwt(req.user)
      res.json({ message: `${req.user.username} is back!`, token })
    } else {
      next({ status: 401, message: "Invalid credentials" })
    }


  } catch(err) {
    next(err)
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function generateJwt(user) {
  const payload = {
    subject: user.user_id,
    role_name: user.role_name,
    username: user.username,
  }
  const config = { expiresIn: '1d'}

  return jwt.sign(payload, JWT_SECRET, config)
}

module.exports = router;
