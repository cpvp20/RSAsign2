const https = require('https');
const express = require('express')
const app = express();
const formidable = require('formidable')//for forms
const fs = require('fs');
const crypto = require('crypto');//CRYPTO LIBRARY
const path = require('path');
const router = express.Router();

app.use(express.static(path.join(__dirname,'public')));

let privateKey, publicKey;//RSA

router.get('/', (req, res) => {
    res.redirect('index.html');
});

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
            format: 'pem'
        }
    });

    privateKey = keys.privateKey;
    publicKey = keys.publicKey;
    
    let files = getFiles();
    for ( file of files ) {
        const sign = crypto.createSign('SHA256');
        let data = fs.readFileSync(`${__dirname}/uploadedFiles/${file}`);
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
    return files ;
}
    
app.use('/',router);

//certification
const options = {key:fs.readFileSync('server.key'), cert:fs.readFileSync('server.cert')};

//create server in port 3000
https.createServer(options,app).listen(3000,()=>{console.log('Server running at https://127.0.0.1:3000/')});






