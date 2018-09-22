var mongoose= require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt-nodejs');

var UserSchema = new Schema({
    user_firstname: {
        type: String,
    } ,
    user_lastname: {
        type: String,
    } ,
    username: {
          type: String,
          required: true
      },
    password: {
          type: String,
          required: true
      } ,
      user_email: {
          type: String,
          required: true
      },
      user_role: {
          type: String,
          required: true
      },
   
      user_registered: { type: Date, default: Date.now },
});

UserSchema.pre('save', function (next) {
    var user = this;
    if (this.isModified('password') || this.isNew) {
        bcrypt.genSalt(10, function (err, salt) {
            if (err) {
                return next(err);
            }
            bcrypt.hash(user.password, salt, null, function (err, hash) {
                if (err) {
                    return next(err);
                }
                user.password = hash;
                next();
            });
        });
    } else {
        return next();
    }
});

UserSchema.methods.comparePassword = function (passw, cb){

    bcrypt.compare(passw, this.password, function (err, isMatch) 
    {
        if (err)
         {
            return cb(err);
          }
      return  cb(null, isMatch);
    });
};
module.exports = mongoose.model('User', UserSchema);
