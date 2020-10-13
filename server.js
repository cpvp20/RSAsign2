const https = require('https'); 
const express = require('express');
const app = express();
const formidable = require('formidable'); 
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const router = express.Router();
const bodyParser = require('body-parser');
const expressSession = require('express-session')({
  secret: 'secret',
  resave: false,
  saveUninitialized: false
});
const mongoose = require('mongoose');
const passport = require('passport');

const User = require('./models/user');
const Log = require('./models/log');
const { use } = require('passport');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

let privateKey, publicKey;

//DATABASE CONNECTION
const db_uri = `mongodb+srv://iteso:ccpprwfc@cluster0.ykikd.mongodb.net/ITESO?retryWrites=true&w=majority`
mongoose.connect(db_uri,
  { useNewUrlParser: true, useUnifiedTopology: true }, (err) => {
    if(err) console.log('Connection Failed', err);
    else console.log('Connected to DB succesfully');
  }
);

app.use(expressSession);
app.use(express.static(path.join(__dirname, 'public')));
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

async function registerLogin(user){
  const new_log = new Log({timestamp: new Date(), user_id: user._id, username: user.username});
  await new_log.save();
  console.log("Login saved");
}

async function getLastLogin(user){
  const logs = await Log.find({user_id: user._id}).sort('-timestamp');
  return logs.length > 1 ? logs : null;
}

router.post('/login',
  passport.authenticate('local', {failureRedirect: '/login'}),
  function(req, res){
    if(req.isAuthenticated()){
      registerLogin(req.user);
      res.redirect('/verify_2fa');
    }else{
      console.log("error logging in");
      res.redirect('/login');
    }
  }
);

router.post('/registerP2',
  passport.authenticate('local', {failureRedirect: '/login'}),
  function(req, res){
    if(req.isAuthenticated()){
      registerLogin(req.user);
      return res.redirect('/generate_2fa');
    }else{
      console.log("error logging in after registering");
      res.redirect('/register');
    }
  }
);

app.get('/lastLogin', isLoggedIn, async function(req, res){
  const log = await getLastLogin(req.user);
  res.json({log: log});
})

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/login');
})

router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/html/login.html'));
})

router.get('/registerP2', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/html/registerP2.html'));
})

router.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/html/register.html'));
})

router.get('/', isLoggedIn, async (req, res) => {
  res.sendFile(path.join(__dirname, 'public/html/index.html'));
})

router.get('/logs', isLoggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, '/public/html/logs.html'));
})

router.get('/edit', isLoggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, '/public/html/edit.html'));
})

router.post('/edit', async (req, res) => {
  if(req.body.user.oldPass && req.body.user.newPass)
    await req.user.changePassword(req.body.user.oldPass, req.body.user.newPass).catch(error => res.send('Could not update password: incorrect old password'));
  if(req.body.user.username && req.body.user.username != req.user.username){
    User.findById(req.user._id, (err, doc) => {
      if(err)
        return res.send('Something went wrong, try again later.')
      doc.username = req.body.user.username;
      doc.save();
    })
  }
  return res.send('Profile updated');
})

router.get('/user', isLoggedIn, (req, res) => {
  res.json(req.user);
  res.end()
})

router.get('/generate_2fa', isLoggedIn, async (req, res) => {
  let user_id = req.user._id;
  let secret = speakeasy.generateSecret({name: 'Seguridad Caro'})

  await User.findOneAndUpdate({_id: user_id}, {secret_2fa: secret.base32}, function(err, result){
    if(err) console.log(err);
  }).catch((err) => console.log(err));
  // Get the data URL of the authenticator URL
  qrcode.toDataURL(secret.otpauth_url, function(err, data_url) {
    // Display this data URL to the user in an <img> tag
    res.write('<h1>Scan this QR Code</h1>');
    res.write('<img src="' + data_url + '">');
    res.write('<form action="verify_2fa" method="get">');
    res.write('<input type="submit" value="Verify 2FA">');
    res.write('</form>')
    res.end()
  });
})

router.get('/verify_2fa', isLoggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/html/verify_2fa.html'))
})

router.post('/verify_2fa', isLoggedIn, async (req, res) =>{
  let verified = speakeasy.totp.verify({ secret: req.user.secret_2fa,
    encoding: 'base32',
    token: req.body.userToken });

  if(verified){
    console.log("verified successfully");
    return res.redirect('/');
  }else{
    console.log("NOT verified successfully");
    return res.redirect('/verify_2fa');
  }
})

function isLoggedIn(req, res, next){
  if(req.isAuthenticated()) return next();
  res.redirect('/login');
}


//UPLOAD
router.post('/fileupload', (req, res) => {
  console.log('File uploaded successfully!') ;
  let form = new formidable.IncomingForm() ;
  form.parse(req, function(err, fields, files) {
      let oldpath = files.filetoupload.path;
      let newpath = `${__dirname}/uploadedFiles/${files.filetoupload.name}`;
      fs.rename(oldpath, newpath, function(){
          res.redirect('/');
          res.end();
          });
      });
})
////

let keys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding:{
      type:'spki',
      format: 'pem'
  },
  privateKeyEncoding:{
      type: 'pkcs8',
      format: 'pem',
      cipher:'aes-256-cbc',
      passphrase:''
  }
});

privateKey = keys.privateKey;
publicKey = keys.publicKey;

let files = getFiles();
for ( file of files ) {
      const sign = crypto.createSign('SHA256');
      let data = fs.readFileSync(`${__dirname}/uploadedFiles/${file}`, "utf8");
      encrypteAndDecyrpt(data); 
}


function encrypteAndDecyrpt(plaintext){ 
// Encrypting msg with privateEncrypt method 
encryptedcmsg = crypto.privateEncrypt(privateKey, Buffer.from(plaintext, 'utf8')).toString('base64'); 
console.log("Encrypted with private key: " + encryptedcmsg); 
fs.writeFile(`${__dirname}/encryptedFiles/${file}`,encryptedcmsg,()=>{});

// Decrypting msg with publicDecrypt method 
decryptedmsg = crypto.publicDecrypt(publicKey, Buffer.from(encryptedcmsg, 'base64')); 
console.log("Decrypted with public key: " + decryptedmsg.toString()); 
fs.writeFile(`${__dirname}/decryptedFiles/${file}`,decryptedmsg.toString(),()=>{});
} 


//SIGN
router.post('/sign',(req,res)=>{
  
  let keys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding:{
          type:'spki',
          format: 'pem'
      },
      privateKeyEncoding:{
          type: 'pkcs8',
          format: 'pem',
          cipher:'aes-256-cbc',
          passphrase:''
      }
  });

  privateKey = keys.privateKey;
  publicKey = keys.publicKey;

  let files = getFiles();
  for ( file of files ) {
      const sign = crypto.createSign('SHA256');
      let data = fs.readFileSync(`${__dirname}/uploadedFiles/${file}`, "utf8");
      encrypteAndDecyrpt(data); 
      sign.update(data);
      sign.end();
      const signature = sign.sign(privateKey,'hex');
      fs.writeFile(`${__dirname}/signedFiles/${file}`,signature,()=>{});
  }
  res.redirect('/');
});

//VERIFY
router.post('/verify',(req,res)=>{
  let files = getFiles();
  for (file of files) {
      let data = fs.readFileSync(`${__dirname}/uploadedFiles/${file}`);
      const verify = crypto.createVerify('SHA256');
      verify.update(data);
      verify.end();
      const signature = fs.readFileSync(`${__dirname}/signedFiles/${file}`).toString();
      let result = verify.verify(publicKey, signature,'hex');
      console.log(file,result);
      if(!result){
          res.write(`Attention: Verification failed for ${file}`, function(){res.end()});
          return;
      }
  }
  res.write('Verification passed for all files. Files are secure and integrity is preserved.');
  res.end();
});

//UPLOAD FILES
router.get('/files', (req, res) => {
  let files = getFiles();
  res.json({'files': files})
});

function getFiles(){
  
  let files=[];//new array 
  fs.readdirSync(`${__dirname}/uploadedFiles`).forEach(file => {
      files.push(file);//array function push
  });
  return files;
}

router.post('/register', function(req, res) {
  newUser = new User({username: req.body.username});
  User.register(newUser, req.body.password, function(err, user) {
    if(err){
      console.log("error in register", err);
      res.redirect('/register');
    }else{
      console.log("registered successfully");
      res.redirect('/registerP2');
    }
  });
});
  
app.use('/',router);

//certification
const options = {key:fs.readFileSync('server.key'), cert:fs.readFileSync('server.cert')};

//create server in port 3000
https.createServer(options,app).listen(3000,()=>{console.log('Server running at https://127.0.0.1:3000/')});





