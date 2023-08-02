/////////////////////////
//       IMPORTS       //
/////////////////////////

import fs from "fs"
import express from "express"
import bodyParser from "body-parser"
import JSONdb from "simple-json-db"
import { v4 as uuidv4 } from 'uuid';
import cryptorjs from 'cryptorjs'


/////////////////////////
//      CONSTANTS      //
/////////////////////////

const app = express()
const port = 3000
const KEY = process.env['KEY']
const REGISTERKEY = process.env['RKEY']

const ISDEBUG = true

const users = new JSONdb("./users/data.json")
const tokens = new JSONdb("./users/tokens.json")

const crypto = new cryptorjs(KEY);
function generateToken() {
  return uuidv4()
}
function encryptData(data) {
  return crypto.encode(data)
}
function decryptData(data) {
  return crypto.decode(data)
}

class userManagmentUtilities {
  constructor(){}
  getUserIDfromToken(token) {
    return tokens.get(token)
  }
  getUserPrivateDataFromID(ID) {
    return users.get(ID)
  }
  setupPublicUserStuff(username, ID) {
    var folderName = `users/publicData/${username}`
    var tmpUserData = {
      username: (username),
      createdDate: (new Date()).toString()
    }
    var defaultProfile = {
      theme: {
        BG1:           "#1f1722",
        BG2:           "#40354a",
        HeaderBG:      "#302836",
        Accent:        "#9944ff",
        Text:          "#ffffff",
        TextSecondary: "#c9bebe"
      },
      headerImage: null,
      links: []
    }
    if (!fs.existsSync(folderName)) {
      fs.mkdirSync(folderName);
    }
    fs.appendFile(`${folderName}/data.json`, (JSON.stringify(tmpUserData)), function (err) {
      if (err) throw err;
    });
    if (!fs.existsSync(`${folderName}/posts`)) {
      fs.mkdirSync(`${folderName}/posts`);
    }
    fs.appendFile(`${folderName}/profile.json`, (JSON.stringify(defaultProfile)), function (err) {
      if (err) throw err;
    });
    return folderName
  }
} 
const userUtils = new userManagmentUtilities()


/////////////////////////
//      MAIN CODE      //
/////////////////////////

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))

app.use(express.static('public'))
app.use("/raw/userData/public", express.static('users/publicData'))

app.get('/', (req, res) => {
  res.sendfile('./public/index.html')
})

app.post('/api/getUserInfo/token', (req, res) => {
  // Sync with the databases
  users.sync()
  tokens.sync()
  // Get request data
  const postData = req.body;
  var encryptedData = {}
  for (const key in postData) {
    if (Object.hasOwnProperty.call(postData, key)) {
      const element = postData[key];
      encryptedData[key] = encryptData(element)
    }
  }
  // Check if request provided a token
  if (postData["token"]) {
    if (Object.values(tokens.JSON()).includes(postData["token"])) {
      res.status(200) // OK
      res.send(JSON.stringify({
        user: JSON.stringify(
          userUtils.getUserPrivateDataFromID(
            userUtils.getUserIDfromToken(postData["token"])
          )
        ),
        error: null,
        debug: ISDEBUG ? {
          postData: postData,
          encryptedData: encryptedData
        } : null
      }));
    } else {
      res.status(400) // Bad Request
      res.send(JSON.stringify({
        errorcode: 103,
        error: "Invalid token"
      }));
    }
  } else {
    res.status(400) // Bad Request
    res.send(`Invalid Data: ${JSON.stringify(postData)}`);
  }
});

app.post('/api/login', (req, res) => {
  // Sync with the databases
  users.sync()
  tokens.sync()
  // Get request data
  const postData = req.body;
  var encryptedData = {}
  for (const key in postData) {
    if (Object.hasOwnProperty.call(postData, key)) {
      const element = postData[key];
      encryptedData[key] = encryptData(element)
    }
  }

  // Check if request provided a username and a password
  if (postData["username"], postData["password"]) {
    // Chack if the username and password is correct
    if (users.get(encryptedData.username)["password"] == encryptedData.password) {
      let userToken = encryptData(generateToken())
      res.status(200) // OK
      res.send(JSON.stringify({
        token: userToken,
        error: null,
        debug: ISDEBUG ? {
          postData: postData,
          encryptedData: encryptedData
        } : null
      }));
      tokens.set(encryptedData.username, userToken)
    } else {
      res.status(400) // Bad Request
      res.send(JSON.stringify({
        errorcode: 101,
        error: "Invalid password or username"
      }));
    }
  } else {
    res.status(400) // Bad Request
    res.send(`Invalid Data: ${JSON.stringify(postData)}`);
  }
})

app.post('/api/register', (req, res) => {
  // Sync with the databases
  users.sync()
  tokens.sync()
  // Get request data
  const postData = req.body;
  var encryptedData = {}
  for (const key in postData) {
    if (Object.hasOwnProperty.call(postData, key)) {
      const element = postData[key];
      encryptedData[key] = encryptData(element)
    }
  }

  // Check if request provided a username and a password
  if (postData["key"] == REGISTERKEY) {
    if (postData["username"], postData["password"]) {
      // Chack if the username is'nt already used
      if (!users.has(encryptedData.username)) {
        let userToken = encryptData(generateToken())
        res.status(200) // OK
        res.send(JSON.stringify({
          token: userToken,
          error: null,
          debug: ISDEBUG ? {
            postData: postData,
            encryptedData: encryptedData
          } : null
        }));
        users.set(encryptedData.username, {
          username: encryptedData.username,
          password: encryptedData.password,
        })
        tokens.set(encryptedData.username, userToken)
        userUtils.setupPublicUserStuff(postData.username, encryptedData.username)
      } else {
        res.status(400) // Bad Request
        res.send(JSON.stringify({
          errorcode: 102,
          error: "Username already used"
        }));
      }
    } else {
      res.status(400) // Bad Request
      res.send(`Invalid Data: ${JSON.stringify(postData)}`);
    }
  } else {
    res.status(400) // Bad Request
    res.send(`Invalid REGISTER KEY`);
  }
})

app.listen(port, () => {
  console.log(`app listening on port ${port}`)
})