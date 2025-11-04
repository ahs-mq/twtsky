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
const aviFilter = (req, file,cb)=>{
    if ((file.mimetype === "image/jpeg" || file.mimetype === "image/png") && file.size <= 256000 ){
        cb(null, true)
    } else {
       cb(new Error("Wrong file type or size bigger than 256kb"), false)
    }
}
const photoFilter = (req, file, cb) => {
  if (
    (file.mimetype === "image/jpeg" || file.mimetype === "image/png") &&
    file.size <= 3 * 1024 * 1024 // 3 MB
  ) {
    cb(null, true);
  } else {
    cb(new Error("Wrong file type or size bigger than 3MB"), false);
  }
};
const aviUpload = multer({dest: "./uploads/avi", fileFilter:aviFilter})
const photoUpload = multer({dest: "./uploads/photo", fileFilter:photoFilter})
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
const { fileLoader } = require('ejs');
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

app.post("/local-login", async (req,res, next)=>{
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

const jwtMiddleware = passport.authenticate('jwt', { session: false });

app.get("/posts/all", jwtMiddleware, async (req, res, next)=>{
    try {
        const allPosts = await prisma.tweet.findMany()
        res.status(200).json({allPosts})
    }catch(err){
        console.log(err)
        return res.status(400).json({message: `Error ${err}`})
    }
})

app.get("/posts/timeline", jwtMiddleware, async (req, res, next) => {
    const currentUserId = req.user.id;

    try {
        // Find all users the current user is following
        const followedUsers = await prisma.follow.findMany({
            where: {
                followerId: currentUserId,
            },
            select: {
                followingId: true, // Only select the ID of the person being followed
            },
        });

        // Extract the IDs into a flat array
        const followedIds = followedUsers.map(follow => follow.followingId);
        
        //Combine the current user's ID with the followed users ID, use spread
        const timelineIds = [currentUserId, ...followedIds];

        //Fetch all Tweets where the authorId is in the timelineIds list
        const timelinePosts = await prisma.tweet.findMany({
            where: {
                authorId: {
                    in: timelineIds, // Uses the 'in' operator to match any ID in the array
                },
            },
            orderBy: {
                createdAt: 'desc', // Sort by newest first
            },
            // Include the author data so the frontend can display the username/display name
            include: {
                author: {
                    select: {
                        username: true,
                        displayName: true,
                    },
                },
                _count: {
                    likes: true
                },
            },
            take: 50, //Limit the number of posts for performance
        });

        res.status(200).json({ timelinePosts });
    } catch (err) {
        console.error("Timeline Error:", err);
        return res.status(500).json({ message: "Failed to load timeline posts." }); 
    }
});

app.post("/new-post", jwtMiddleware, photoUpload.single("photo"), async (req,res)=>{
    try{
        const newPost = await prisma.tweet.create({data:{
            authorId: req.user.id,
            content: req.body.text,
            photoURL: req.file ? req.file.path : null
        }})
        res.status(200).json({newPost})
    }catch(err){
        console.error("Post Error:", err);
        return res.status(500).json({ message: "Unable to post" });

    }
})

app.post("/new-reply", jwtMiddleware, photoUpload.single("photo"), async (req,res)=>{
    try{
        const newPost = await prisma.tweet.create({data:{
            authorId: req.user.id,
            content: req.body.text,
            photoURL: req.file.path,
            parentId: req.body.parent
        }})
        res.status(200).json({newPost})
    }catch(err){
        console.error("Post Error:", err);
        return res.status(500).json({ message: "Unable to post" });

    }
})

app.post("/modify", jwtMiddleware, aviUpload.single("avi"), async (req, res) => {
    //Ensure at least one field is being updated
    if (!req.body.name && !req.body.username && !req.body.bio && !req.file) {
         return res.status(400).json({ message: "No fields provided for update." });
    }

   //Prepare the update data dynamically (to avoid updating fields with null/undefined if not sent)
    const updateData = {};
    if (req.body.name) updateData.displayName = req.body.name;
    if (req.body.username) updateData.username = req.body.username;
    if (req.body.bio) updateData.bio = req.body.bio;
    if (req.file) updateData.avatar = req.file.path;

    try {
        const mod = await prisma.user.update({
            where: {
                id: req.user.id
            },
            data: updateData
        });

        
        res.status(200).json({ 
            message: "Profile updated successfully!",
            user: mod
        });

    } catch (err) {
        console.error("Post Error:", err);
        
        if (err.code === 'P2002') {
            return res.status(409).json({ message: "That username is already taken. Please choose another." });
        }
        
        return res.status(500).json({ message: "Unable to update profile due to a server error." });
    }
});


