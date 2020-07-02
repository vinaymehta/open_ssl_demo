var pAPI = ""
var sAPI = ""
var sRSA = ""

function create_csr(){

  var pki = forge.pki;
  keys = pki.rsa.generateKeyPair(parseInt($("#no_of_bits").val()));
  var publicKey = keys.publicKey
  var privateKey = keys.privateKey

  var csr = pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{
    name: 'commonName',
    value: pAPI
  }, {
    name: 'countryName',
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'California'
  }, {
    name: 'localityName',
    value: 'San Diego'
  }, {
    name: 'organizationName',
    value: 'Ubiq Security, Inc'
  }, {
    shortName: 'OU',
    value: 'Ubiq Platform'
  }]);

  csr.sign(keys.privateKey);

  var verified = csr.verify();

  if(verified == true){
    var pem = forge.pki.certificationRequestToPem(csr);
    $(".full-page-loader").addClass("hidden");
    $("#csr").text(pem)

    var rsaPrivateKey = pki.privateKeyToAsn1(privateKey);
    var privateKeyInfo = pki.wrapRsaPrivateKey(rsaPrivateKey);

    var encryptedPrivateKeyInfo = pki.encryptPrivateKeyInfo(
      privateKeyInfo, sRSA, {
        algorithm: 'aes256',
      }
    )

    var pem = pki.encryptedPrivateKeyToPem(encryptedPrivateKeyInfo);

    $("#private-key").text(pem)

  }

}

$(function(){

  pAPI = forge.util.encode64(forge.random.getBytesSync(18))

  $("#uuid").text(pAPI)

  sAPI = forge.util.encode64(forge.random.getBytesSync(33))

  sRSA = forge.util.encode64(forge.random.getBytesSync(33))

  $("#sAPI").text(sAPI)

  $("#sRSA").text(sRSA)


  $("#generate-csr").click(function(){
    $(".full-page-loader").removeClass("hidden");
    setTimeout(function(){ create_csr(); }, 800);
  })

})
