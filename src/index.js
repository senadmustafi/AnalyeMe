import express from "express";
import bodyParser from "body-parser";
import connection from './connection.js';
import mongo from 'mongodb';
import auth from "./auth.js";
import { use } from "bcrypt/promises";
import res from "express/lib/response";
import nodePortScanner from 'node-port-scanner';
import Wappalyzer from 'wappalyzer';
import axios from 'axios';
import dns  from 'dns';
import fs from 'fs';
import EventEmitter from "events";
import cors from "cors";


const app = express()
const port = 3000
app.use(cors())
app.use(bodyParser.json())



app.get('/', (req, res) => {
  res.send("heellooo")

})


//JWT Test
app.get('/secret', [auth.verify], (req, res) => {
  res.json({ message: req.jwt.email });

})



// Login 
app.post('/auth', async (req, res) => {
  let user = req.body;

  try {
    let result = await auth.authenticateUser(user.email, user.password);
    res.json({ result: result });
  }
  catch (e) {
    res.status(401).json({ error: e.message });
  }


})


// Create account / Register
app.post('/users', async (req, res) => {
  let user = req.body;

  let id;
  try {
    id = await auth.registerUser(user);
  }
  catch (e) {
    res.status(500).json({ error: e.message })
  }

  res.json({ id });

})



//Scan wordPress admins
app.post('/scan-wp-users', async (req, res) => {
  try{
  let domain = req.body;
  const ourdata = await axios.get(domain.domain + "wp-json/wp/v2/users" );
  const filtererddata = ourdata.data;
  let lista = []
  filtererddata.forEach(author => {
    lista.push(author.name); 
})

res.json(lista);
  }
  catch(e){
    return res.json("Data is not available on this wp site")
  }

})



//dir

app.post('/dir', async (req, res) => {
  let domain = req.body;
  var array = fs.readFileSync('assets/dir.txt', 'utf8').replace(/\r\n/g,'\n').split('\n');

class MyEmitter extends EventEmitter {}
const myEmitter = new MyEmitter();
 
res.writeHead(200, {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*"
});
array.forEach((item, index) => {
  setTimeout(async() => {
      try {
          const { status } = await axios.get(domain.dns+"/"+item);
          if (status === 200) {
              myEmitter.emit("data", status, item);

          }
      } catch (error) {
          console.error(`Error Occured: ${error}`);
          console.log(domain.dns);

      }
  }, 500 * index);
});

myEmitter.on("data", (status, item) => {
  res.write(JSON.stringify({ item, status }));
  //console.log(JSON.stringify({ item, status }));
});
});


// Get from MongoDB history about user analyzes
app.get('/history/webstatus', [auth.verify], async (req, res) => {
  let db = await connection();

  try {
    let cur = await db.collection("shodan_data").find()
    let curArray = await cur.toArray()
    const filteredArray = curArray.filter(obj => obj.your_email === req.jwt.email)
    return res.json(filteredArray)


  }
  catch (e) {
    console.log(e);
  }
})


//Search for open Port
app.post('/openport', async (req, res) => {
  let ipData = req.body;
  let ip = JSON.stringify(ipData.ip).replace(/[\"\\]/g, "");
  let port = parseInt(ipData.ports)




  try {
    const portScanOnIp = await nodePortScanner(ip, [port]);
    console.log(portScanOnIp)
    return res.json(portScanOnIp.ports);


  }
  catch (e) {

  }
})


// Looking for my Public IPv4
app.get('/my-ip', async (req, res) => {
  try {
    var ip = require('what-is-my-ip-address');
    const my_ip = req.headers["x-forwarded-for"] || await ip.v4(ip);
    return res.json({ip:my_ip})



  }
  catch (e) {
    console.log(e)
  }
})

//DNS LOOK UP

app.post('/dnslookup',   (req, res) => {
  let DNS = req.body
  let stringdns = JSON.stringify(DNS.DNS).replace(/"/g, "");
  console.log(stringdns)
  try{
      dns.lookup(stringdns, function (err, address) {
          if (err) {
              console.log(err);
              res.status(500).json({ error: err });
          } else {
              res.json({ address });
          }
      });
 

  }
  catch(e){
    console.log(e);
  }
})



//Wapalyzer

app.post('/webtech', async (req, res) => {
  let domain = req.body;
  try {
    const url = domain.domain;

    const options = {
      debug: false,
      delay: 500,
      headers: {},
      maxDepth: 3,
      maxUrls: 10,
      maxWait: 14000,
      recursive: true,
      probe: true,
      userAgent: 'Wappalyzer',
      htmlMaxCols: 2000,
      htmlMaxRows: 2000,
      noScripts: false,
    };

    const wappalyzer = new Wappalyzer(options)

    try {
      await wappalyzer.init()

      // Optionally set additional request headers
      const headers = {}

      const site = await wappalyzer.open(url, headers)

      // Optionally capture and output errors
      site.on('error', console.error)

      const results = await site.analyze()

      return res.json(results);
      
    } catch (error) {
      console.error(error)
    }

    await wappalyzer.destroy()



  }
  catch (e) {
    console.log(e)
  }
})

// Analyez website status
app.post('/webstatus', [auth.verify], async (req, res) => {
  let db = await connection();
  var { ip } = req.body
  console.log(ip)


  // Make request
  try {
    const shodan_get_data = await axios.get(`https://api.shodan.io/shodan/host/${ip}?key=` + process.env.SHODAN_KEY);
    let shodan_data = (shodan_get_data.data)


    let shodan_pass_data = {
      your_email: req.jwt.email,
      date: Date(),
      country_name: shodan_data.country_name,
      city: shodan_data.city,
      ip: ip,
      ports: shodan_data.ports,
      os: shodan_data.os,
      isp: shodan_data.isp,
      vulns: shodan_data.vulns,

    }

    await db.collection('shodan_data').insertOne(shodan_pass_data)

    return res.json({ shodan_pass_data })
  }
  catch (e) {
    return res.json({ error: "Task failed" })
  }



})


app.listen(port, () => console.log(`Port ${port}`))