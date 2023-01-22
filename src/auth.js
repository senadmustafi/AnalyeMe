import dotenv from "dotenv";
dotenv.config()
import connection from './connection.js';
import mongo from 'mongodb';
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { use } from 'bcrypt/promises';

(async () =>{
let db = await connection();
await db.collection('users').createIndex({email:1}, {unique:true});
})();

export default{
    async registerUser(userData){
        let db = await connection();

        let doc = {
            email: userData.email,
            //username: userData.username,
            password: await bcrypt.hash(userData.password, 8),

        };
        try{
            await db.collection('users').insertOne(doc)
            if(result && result.insertId){
                return result.insertId;
            };
        }
        catch(e){
            if (e.code == 11000){
                throw new Error("User already exist");
            };
        };
    },

    async authenticateUser(email, password){
        let db = await connection();
        let user = await db.collection("users").findOne({email: email});

        if(user && user.password && (await bcrypt.compare(password, user.password))){
            delete user.password;
            let token = jwt.sign(user, process.env.JWT_SEC, {algorithm: "HS512", expiresIn: "1 week"});
            return{token, email:user.email};

        }else{
            throw new Error("Cannot auth");
        };
    },

    verify(req,res, next){
        try{
        let authirization = req.headers.authorization.split(" ");
        let type = authirization[0];
        let token = authirization[1];
      
        if (type !== "Bearer"){
          return res.status(401).send();
        } else{
          req.jwt = jwt.verify(token, process.env.JWT_SEC);
          return next();
        }
    }
    catch(e){
        return res.status(401).send();
    }
    }




}