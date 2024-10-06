if (Process.platform === 'windows') {
    console.log('Running on Windows platform');

    var certVerify = Module.findExportByName('crypt32.dll', 'CertVerifyCertificateChainPolicy');
    if (certVerify !== null) {
        Interceptor.attach(certVerify, {
            onEnter: function (args) {
                console.log('Entering CertVerifyCertificateChainPolicy');
            },
            onLeave: function (retval) {
                console.log('Original return value:', retval);
                retval.replace(0); // Replace the return value to indicate success (0)
                console.log('Modified return value:', retval);
            }
        });
    } else {
        console.log('CertVerifyCertificateChainPolicy not found');
    }
} else {
    console.log('This script is intended for Windows platform.');
}
