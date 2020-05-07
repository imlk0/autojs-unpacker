
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


function get_project_path() {
    return Promise(function (resolve, reject) {
        try {
            Java.perform(function () {
                try {
                    var got = false;
                    Java.choose('android.app.ContextImpl', {
                        onMatch: function (instance) {
                            if (!got) {
                                got = true;
                                var filesDir = Java.cast(instance, Java.use('android.app.ContextImpl')).getFilesDir().getAbsolutePath();
                                resolve(filesDir);
                            }
                            return "stop";
                        },
                        onComplete: function () {
                            if(!got){
                                console.log("bug, unable to found any 'android.app.ContextImpl' instance!!!")
                                reject();
                            }
                        }
                    })
                } catch (e) {
                    reject(e)
                }
            })
        } catch (e) {
            reject(e)
        }
    });
}


function write_file(full_path, data) {
    var f = new File(full_path, 'w')
    f.write(data)
    f.close()
}


rpc.exports = {
    "decrypt": decrypt,
    "encrypt": encrypt,
    "getprojectpath": get_project_path,
    "writefile": write_file,

}