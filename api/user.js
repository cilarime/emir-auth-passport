const express = require("express");
const userRouter = express.Router();
const passport = require("passport");
const passportConfig = require("../passport");
const jwt = require("jsonwebtoken");
const User = require("../models/User");


//development env vars
require("dotenv").config();


//funktion som skapar våran json web token även kallad cookie!!
const signToken = (userId) => {
  return jwt.sign(
    {
      iss: "emirAlic",
      sub: userId,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: 60 * 60 * 24,
    }
  );
};


//spara ny användare till DB
userRouter.post("/register", (req, res) => {
  const { username, password } = req.body;
  User.findOne({ username }, (err, user) => {
    if (err) {
      res
        .status(500)
        .json({ msg: { msgBody: "An error occured", msgError: true } });
    }
    if (user) {
      res
        .status(400)
        .json({ msg: { msgBody: "Username allready taken", msgError: true } });
    } else {
      const newUser = new User({ username, password });
      newUser.save((err) => {
        if (err) {
          res
            .status(500)
            .json({ msg: { msgBody: "An error occured", msgError: true } });
        } else {
          res.status(201).json({
            msg: { msgBody: "Account successfully created", msgError: false },
          });
        }
      });
    }
  });
});


//kör lokal strategy middleware alltså passport.js filen och cookie till jwt som är skapad genom våran signToken() funktion
userRouter.post(
  "/login",
  passport.authenticate("local", { session: false }),
  (req, res) => {
    if (req.isAuthenticated()) {
      const { _id, username } = req.user;

      //sätter en konstant hållandes jwt returnerad från våran signedToken funktion
      const token = signToken(_id);

      //sätter en cookie i webbläsaren med namnet "access-token" innehållandes vår jwt genom vår konstant ovan!!
      res.cookie("access-token", token, { httpOnly: true, sameSite: true });
      res.status(200).json({
        isAuthenticated: true,
        user: { _id, username },
        msg: { msgBody: "Successfully logged in", msgError: false },
      });
    }
  }
);

//kör våran jwt strategy middleware som är passport.js fil för att se om en jwt är lagrad i webbläsaren
userRouter.get(
  "/authenticated",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    const { _id, username } = req.user;
    res.status(200).json({
      isAuthenticated: true,
      user: { _id, username },
    });
  }
);

//kör en jwt strategy middleware som är våran passport.js fil för att se om en cookie (jwt) lagrad i vår webbläsare sedan rensar cookie så användare inte längre är auth.
userRouter.get(
  "/logout",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.clearCookie("access-token");
    res
      .status(200)
      .json({ msg: { msgBody: "Successfully logged out", msgError: true } });
  }
);

module.exports = userRouter;