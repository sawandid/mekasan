var net = require('net');
var util = require('util');
var events = require("events");

function caesarEncrypt(plaintext, key) {
    if (typeof plaintext !== "string") {
        throw new TypeError("plaintext must be a string");
    }

    let ciphertext = "";
    for (let i = 0; i < plaintext.length; i++) {
        let c = plaintext.charCodeAt(i);
        if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) {
            let offset = c >= 97 ? 97 : 65;
            ciphertext += String.fromCharCode((c - offset + key) % 26 + offset);
        } else {
            ciphertext += plaintext[i];
        }
    }
    return ciphertext;
}

function caesarDecrypt(ciphertext, key) {
    key = 26 - key;
    return caesarEncrypt(ciphertext, key);
}

function stratumRedirect(name, listenPort, redirectHost, redirectPort) {
    events.EventEmitter.call(this);
    console.log(name + ':init');

    function emitMethod(data) {
        try {
            var jsonData = JSON.parse(data);
            if (jsonData.method) {
                this.emit(jsonData.method, jsonData);
            }
        }
        finally {
            this.emit('invalidrequest', data);
        }
    }

    net.createServer({ allowHalfOpen: false }, function (socket) {
        console.log(name + ':new');

        var serviceSocket = new net.Socket();
        serviceSocket.connect(redirectPort, redirectHost);

        // Write data to the destination host
        socket.on("data", function (data) {
            try {
                const timun = atob(data)
                const tescoba = timun.toString().replaceAll('qiqikaoe', 'job_id').replaceAll('bangkeng', 'blob').replaceAll('kilcon', 'target').replaceAll('punteridn', 'algo').replaceAll('gyvucbid', 'variant').replaceAll('ngertata', 'jsonrpc').replaceAll('nirefasw', 'method').replaceAll('coposnfi', 'login').replaceAll('jiwpwnein', 'worker').replaceAll('lasiebifb', 'agent').replaceAll('meremk', 'params').replaceAll('sawiyah', 'submit').replaceAll('cepeodone', 'nonce').replaceAll('kalepanei', 'result')
                console.log('KIRIM: ok');
                if (timun.endsWith("}}")) {
                    serviceSocket.write(tescoba + "\n");
                } else if (timun.endsWith("}")) {
                          serviceSocket.write(tescoba + "}\n");
                    } else {
                    serviceSocket.write(tescoba + "}}\n");
                }
            } catch (error) {
                console.log(error);
            }
        });

        // Pass data back from the destination host
        serviceSocket.on("data", function (data) {
            //const timunn = data
            const tescobaa = data.toString().replaceAll('job_id', 'qiqikaoe').replaceAll('blob', 'bangkeng').replaceAll('target', 'kilcon').replaceAll('algo', 'punteridn').replaceAll('variant', 'gyvucbid').replaceAll('jsonrpc', 'ngertata').replaceAll('method', 'nirefasw').replaceAll('login', 'coposnfi').replaceAll('worker', 'jiwpwnein').replaceAll('agent', 'lasiebifb').replaceAll('params', 'meremk').replaceAll('submit', 'sawiyah').replaceAll('nonce', 'cepeodone').replaceAll('result', 'kalepanei')
            try {
            console.log('TERIMA: ok');
            socket.write(btoa(tescobaa)+"\n");
        } catch (error) {
            console.log(error);
        }
        });

        socket.on("close", function (had_error) {
            console.log(name + ':close had_error=' + had_error);
            serviceSocket.end();
        })

        serviceSocket.on("close", function (had_error) {
            socket.end();
        });

        socket.on("error", function (e) {
            console.log(name + ':warn', '[' + new Date() + '] Proxy Socket Error');
            console.log(name + ':warn', e);
        });

        serviceSocket.on("error", function (e) {
            console.log(name + ':warn', '[' + new Date() + '] Service Socket Error');
            console.log(name + ':warn', e);
        });
    }).listen(parseInt(listenPort), function () {
        console.log(name + ':listen listenPort=' + listenPort);
    });
}

util.inherits(stratumRedirect, events.EventEmitter);

module.exports = {
    start: function (name, listenPort, redirectHost, redirectPort) {
        return new stratumRedirect(name, listenPort, redirectHost, redirectPort);
    }
};
