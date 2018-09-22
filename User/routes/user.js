var express = require('express');
var router = express.Router();
var User= require('../models/User');
var validator = require("email-validator");
var bcrypt = require('bcrypt-nodejs');
var jwt = require('jsonwebtoken');
var passport = require('passport');
var mysql = require('mysql');

//User Value Update
router.put('/update/:id', function(req, res, next) {
    User.findByIdAndUpdate(req.params.id, req.body, function (err, post) {
      if (err) return next(err);
      res.json({success: true, msg: 'Successful user updated.'});
    });
  });


//User Register
router.post('/create', function(req, res) {
  if (!req.body.username || !req.body.password || !req.body.user_email || !req.body.user_role) {
     res.json({success: false, msg: 'Please pass username,password,email and user role .'});
    } else {
      var newUser = new User({
        username: req.body.username,
        password: req.body.password,
        user_email: req.body.user_email,
        user_firstname: req.body.user_firstname,
        user_lastname: req.body.user_lastname,
        user_role: req.body.user_role,
      });
      var emailvalidator = validator.validate(req.body.user_email);
      if(!emailvalidator) {
      return res.json({success: false, msg: 'Please insert a valid email.'});
      }
      User.findOne({
        username: req.body.username
      }, function(err, user) {
        if (user) {
          return res.json({success: false, msg: 'Username already exists.'});
        }
        newUser.save(function(err) {
          if (err) {
            return res.json({success: false, msg: 'Username already exists.'});
          }
          res.json({success: true, msg: 'Successful created new user.'});      
        });
      });    
    }
  });

//User SignIN
router.post('/signin', function(req, res) {
  User.findOne({
    username: req.body.username
  }, function(err, user) {
    if (err) throw err;

    if (!user) {
      res.status(401).send({success: false, msg: 'Authentication failed. User not found.'});
    } else {
      // check if password matches
      user.comparePassword(req.body.password, function (err, isMatch) {
        if (isMatch && !err) {
          // if user is found and password is right create a token
          var token = jwt.sign(user.toJSON(), "SHH");
          // return the information including token as JSON
          res.json({success: true,UserData:user, token: 'JWT ' + token});
        } else {
          res.status(401).send({success: false, msg: 'Authentication failed. Wrong password.'});
        }
      });
    }
  });
});

//Logout
router.post('/logout', passport.authenticate('jwt', { session: false}), function(req, res) {
    var token = getToken(req.headers);
    if (token) {
      res.status(200).send({ auth: false, token: null });
    } else {
      return res.status(403).send({success: false, msg: 'Unauthorized.'});
    }
  });


//user Change Password
router.put("/change_psw/:id",function(req,res){
	//var password = req.body.password;
	//console.log(req.body.password)
  //console.log(req.body);
	bcrypt.genSalt(10, function (err, salt) 
	{
            if (err) 
            {
                return next(err);
            }
            bcrypt.hash(req.body.password, salt, null, function (err, hash) 
            {
                if (err) 
                {
                    return next(err);
                }else{
                	req.body.password = hash
                		User.findByIdAndUpdate(req.params.id, {
                			password:req.body.password
                		},function(err,post){
                			if (err) return next(err);
                	      res.json({success: true, msg: 'Successful password updated.'});
                		});
                }
            });
     });
	
});

getToken = function (headers) {
    if (headers && headers.authorization) {
      var parted = headers.authorization.split(' ');
      if (parted.length === 2) {
        return parted[1];
      } else {
        return null;
      }
    } else {
      return null;
    }
  };

  getUserRole = function (headers) {
    if (headers && headers.role) {
      return headers.role;
  };
};

//MySql

module.exports = router;