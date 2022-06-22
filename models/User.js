const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const UserSchema = mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
});


//middleware som körs före varje mongodb save call via mongoose
UserSchema.pre("save", function (next) {
  if (!this.isModified("password")) next();
  bcrypt.hash(this.password, 10, (err, passwordHashed) => {
    if (err) return next(err);
    this.password = passwordHashed;
    next();
  });
});


//får ett call passport local strategy för att jämnföra password skickas in från client med lösenord på användare i DB
UserSchema.methods.comparePassword = function (password, cb) {
  bcrypt.compare(password, this.password, (err, isMatch) => {
    if (err) {
      return cb(err);
    } else {
      if (!isMatch) return cb(null, isMatch);
      return cb(null, this);
    }
  });
};

module.exports = mongoose.model("User", UserSchema);
