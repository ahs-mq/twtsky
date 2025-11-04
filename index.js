const express = require('express');
const cors = require('cors')
const dotenv = require('dotenv');
const path = require('path');
const jwt = require('jsonwebtoken')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt;
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const fs = require('fs');
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads')
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, uniqueSuffix)
  }
})
const upload = multer({ storage: storage })
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
dotenv.config();
const app = express()
const prisma = new PrismaClient()
app.use(express.json())
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(cors())


const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET
};

passport.use(new JwtStrategy(jwtOptions, async (jwt_payload, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: jwt_payload.id } });
    if (user) return done(null, user);
    return done(null, false);
  } catch (err) {
    return done(err, false);
  }
}));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:8000/auth/google/callback" 
  },
  async function(accessToken, refreshToken, profile, done) {
    const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;

    if (!email) {
        return done(new Error("Google did not provide a valid email."), false);
    }
    
    try {
        // 1. Check for an existing user by email
        let user = await prisma.user.findUnique({
            where: { email: email }
        });

        if (user) {
            // SCENARIO: User found (Login/Existing Local User)
            console.log(`User found: ${user.email}. Logging in.`);
            return done(null, user);
        } else {
            const baseName = profile.displayName ? profile.displayName.toLowerCase().replace(/\s/g, '') : 'user';
            let usernameCandidate = `${baseName}${Math.floor(Math.random() * 99999)}`;
            let finalUsername;

            for (let i = 0; i < 5; i++) {
                const existingUsername = await prisma.user.findUnique({
                    where: { username: usernameCandidate }
                });
                
                if (!existingUsername) {
                    finalUsername = usernameCandidate;
                    break;
                }
                usernameCandidate = `${baseName}${Math.floor(Math.random() * 99999)}`;
            }

            if (!finalUsername) {
                 return done(new Error("Could not generate a unique username."), false);
            }

            // 3. Create the new user
            const newUser = await prisma.user.create({
                data: {
                    email: email,
                    username: finalUsername
                }
            });
            console.log(`New user created: ${newUser.email}`);
            return done(null, newUser);
        }
    } catch (err) {
        console.error("Passport Google Strategy Error:", err);
        return done(err, false);
    }
  }
));

app.post("/signup", [
    body("email").trim().isEmail().notEmpty.withMessage("Invalid email address format."),
    body("password").isLength({min: 6}).notEmpty.withMessage("Password must be at least 6 characters long."),
    body('cpassword').custom((value,{req})=>{
        if (value !== req.body.password){
            throw new Error("Password Mismatch")
        }
        return true
    })
] ,async (req,res)=>{

     const errors = validationResult(req);

    if (!errors.isEmpty()) {
        console.error("Validation failed:", errors.array());
        return res.status(400).json({ 
            success: false, 
            message: "Validation failed.",
            errors: errors.array()
        });
    }
    const { username, email, password } = req.body

    try {

        const hashed = await bcrypt.hash(password, 10)
        const newUser = await prisma.user.create({data:{
            email: email ,
            username: username,
            passwordHash: hashed
        }})

    }catch(err){
        console.log("Error", err)
        res.status(500).json({message: "Internal server error during registration." })

    }
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { 
    session: false, 
    failureRedirect: '/login' 
  }),
  function(req, res) {
    const user = req.user

    const payload = {
        id: user.id,
        email: user.email
    }

    const token = jwt.sign(payload, process.env.JWT_SECRET, {expiresIn : "1d"})
    return res.json({token})
  });

app.post("/lologin", async (req,res, next)=>{
    passport.authenticate("local", {session : false}, (err, user, info)=>{
        if (err || !user){
            return res.status(401).json({message: "Login Failed"})
        }
        const payload = {
            id: user.id,
            email: user.email
        }
        const token = jwt.sign(payload, process.env.JWT_SECRET, {expiresIn : "1d"})
        res.json({token})
    })(req,res,next)
})

function isAuth(req, res, next){
    if (req.isAuthenticated()){
        return next()
    }
    res.redirect('/login')

}