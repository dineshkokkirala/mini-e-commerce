const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const auth = require("../middleware/auth");


// @route    GET api/auth
// @desc     Get logged in user
// @access   Private
router.get("/api/auth", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// @route    POST api/register
// @desc    Auth user & get token
// @access   Private - only can access this route
router.post("/api/register",auth,async (req, res) => {
    const { name, email, password } = req.body;

    try {
      let admin = await User.findById(req.user.id)
      //console.log(admin)
      if(admin.isAdmin===true){

        let user = await User.findOne({ email: email });
  
        if (user) {
          return res.status(400).json({ msg: "User already exists" });
        }
  
        user = new User({
          name: name,
          email: email,
          password: password,
        });
  
        const salt = await bcrypt.genSalt(10);
  
        user.password = await bcrypt.hash(password, salt);
  
        await user.save();
  
        const payload = {
          user: {
            id: user.id,
          },
        };
  
        jwt.sign(
          payload,
          config.get("jwtSecret"),
          {
            expiresIn: 360000,
          },
          (err, token) => {
            if (err) throw err;
            res.json({ token });
          }
        );
      }else{
          return res.status(401).json({ msg: "Not Authorised, only admin can add user" });  
      }

    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server Error");
    }
    
}
    
  
);

module.exports = router;