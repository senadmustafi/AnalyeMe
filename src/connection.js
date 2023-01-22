import dotenv from "dotenv";
dotenv.config()
import { MongoClient, ServerApiVersion } from 'mongodb';
const uri = process.env.DB_PASW;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true, serverApi: ServerApiVersion.v1 });

let db = null
export default () =>{
    return new Promise((resolve, reject) =>{

    /*    if(db && client.isConnected()){
            resolve(db)
        
        }*/

        client.connect(err => {
            if(err){
                reject("Error" + err)
            }
            else{
                console.log("Connected to DB")
                db = client.db("test1")
                resolve(db)


            }
          });
    })

}