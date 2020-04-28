
function bytelist_js_to_java(bytelist) {
    return Java.array('byte', bytelist)
    // var base64Str = base64Encode(bytelist)
    // var androidBase64 = Java.use('android.util.Base64')
    // var bytesInJava = androidBase64.decode(base64Str, 0)
    // return bytesInJava;
}

function bytelist_java_to_js(bytelist) {
    var jsonString = Java.use('org.json.JSONArray').$new(bytelist).toString();
    return JSON.parse(jsonString);
}


function decrypt(byteListInJs) {
    return Promise(function (resolve, reject) {
        try {
            Java.perform(function () {
                try {
                    var objCompanion = Java.use('com.stardust.autojs.engine.encryption.ScriptEncryption').class.getField("Companion").get(null)
                    objCompanion = Java.cast(objCompanion, Java.use('com.stardust.autojs.engine.encryption.ScriptEncryption$Companion'))
                    var byteListInJava = bytelist_js_to_java(byteListInJs)
                    var byteListRtnInJava = objCompanion.decrypt(byteListInJava, 8, byteListInJs.length)
                    var byteListRtnInJS = bytelist_java_to_js(byteListRtnInJava)
                    resolve(byteListRtnInJS);
                } catch (e) {
                    reject(e)
                }
            })
        } catch (e) {
            reject(e)
        }
    });
}



function encrypt(byteListInJs) {
    return Promise(function (resolve, reject) {
        try {
            Java.perform(function () {
                try {
                    var objCompanion = Java.use('com.stardust.autojs.engine.encryption.ScriptEncryption').class.getField("Companion").get(null)
                    objCompanion = Java.cast(objCompanion, Java.use('com.stardust.autojs.engine.encryption.ScriptEncryption$Companion'))
                    var byteListInJava = bytelist_js_to_java(byteListInJs)
                    var byteListRtnInJava = objCompanion.encrypt(byteListInJava)
                    var byteListRtnInJS = bytelist_java_to_js(byteListRtnInJava)
                    resolve(byteListRtnInJS);
                } catch (e) {
                    reject(e)
                }
            })
        } catch (e) {
            reject(e)
        }
    });
}


rpc.exports = {
    "decrypt": decrypt,
    "encrypt": encrypt,
}