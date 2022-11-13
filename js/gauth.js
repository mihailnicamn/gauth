
((exports) => {
    "use strict";
    //==========
    //DATA STORAGE
    var StorageService = function () {
        var setObject = (key, value) => {
            localStorage.setItem(key, JSON.stringify(value));
        };
        var getObject = (key) => {
            var value = localStorage.getItem(key);
            // if(value) return parsed JSON else undefined
            return value && JSON.parse(value);
        };
        var isSupported = () => {
            return typeof (Storage) !== "undefined";
        };
        var hasJsonStructure = (str) => {
            if (typeof str !== 'string') return false;
            try {
                const result = JSON.parse(str);
                const type = Object.prototype.toString.call(result);
                return type === '[object Object]'
                    || type === '[object Array]';
            } catch (err) {
                return false;
            }
        };
        var validate = (data) => {
            if (!Array.isArray(data)) return false;
            if (data.length < 1) return false;
            return data.map((entry) => {
                return (entry.hasOwnProperty('name') && entry.hasOwnProperty('secret'))
            }).every(element => element === true);
        }
        // exposed functions
        return {
            isSupported: isSupported,
            getObject: getObject,
            setObject: setObject,
            hasJsonStructure: hasJsonStructure,
            validate: validate
        };
    };
    exports.StorageService = StorageService;
    //==========
    //==========
    //CRYPTOGRAPHY
    var CryptoService = () => {
        var encrypt = (data, password) => {
            var data_string = JSON.stringify(data)
            var encrypted = CryptoJS.AES.encrypt(data_string, password)
            return encrypted.toString()
        }
        var decrypt = (data, password) => {
            var decrypted = CryptoJS.AES.decrypt(data, password);
            var data_ = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
            return data_
        }
        var setWindowPassword = (password) => {
            window.password_ = password
        }
        var getWindowPassword = () => {
            return window.password_
        }
        var isPasswordSet = () => {
            return window.hasOwnProperty('password_')
        }
        var removePassword = () => {
            delete window.password_
        }
        var setBroserSafu = (isit) => {
            window.isitsafu = isit
        }
        var isBrowserSafu = () => {
            if(window.isitsafu === undefined) return false
            return window.isitsafu
        }
        return {
            encrypt: encrypt,
            decrypt: decrypt,
            setWindowPassword: setWindowPassword,
            getWindowPassword: getWindowPassword,
            isPasswordSet: isPasswordSet,
            removePassword: removePassword,
            setBroserSafu: setBroserSafu,
            isBrowserSafu: isBrowserSafu
        }
    }
    //==========
    //KEY UTILITIES
    var KeyUtilities = function (jsSHA) {

        var dec2hex = (s) => {
            return (s < 15.5 ? '0' : '') + Math.round(s).toString(16);
        };

        var hex2dec = (s) => {
            return parseInt(s, 16);
        };

        var base32tohex = (base32) => {
            var base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var bits = "";
            var hex = "";

            for (var i = 0; i < base32.length; i++) {
                var val = base32chars.indexOf(base32.charAt(i).toUpperCase());
                bits += leftpad(val.toString(2), 5, '0');
            }

            for (i = 0; i + 4 <= bits.length; i += 4) {
                var chunk = bits.substr(i, 4);
                hex = hex + parseInt(chunk, 2).toString(16);
            }

            return hex;
        };

        var leftpad = (str, len, pad) => {
            if (len + 1 >= str.length) {
                str = new Array(len + 1 - str.length).join(pad) + str;
            }
            return str;
        };

        var generate = (secret, epoch) => {
            var key = base32tohex(secret);

            // HMAC generator requires secret key to have even number of nibbles
            if (key.length % 2 !== 0) {
                key += '0';
            }

            // If no time is given, set time as now
            if (typeof epoch === 'undefined') {
                epoch = Math.round(new Date().getTime() / 1000.0);
            }
            var time = leftpad(dec2hex(Math.floor(epoch / 30)), 16, '0');

            // external library for SHA functionality
            var hmacObj = new jsSHA(time, "HEX");
            var hmac = hmacObj.getHMAC(key, "HEX", "SHA-1", "HEX");

            var offset = 0;
            if (hmac !== 'KEY MUST BE IN BYTE INCREMENTS') {
                offset = hex2dec(hmac.substring(hmac.length - 1));
            }

            var otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec('7fffffff')) % 1000000 + '';
            return Array(7 - otp.length).join('0') + otp;
        };

        // exposed functions
        return {
            generate: generate
        };
    };
    exports.KeyUtilities = KeyUtilities;
    //==========
    //==========
    //KEY CONTROLLER
    var KeysController = function () {
        var storageService = null,
            keyUtilities = null,
            editingEnabled = false;

        var fixURL = () => {
            let url = window.location.href;
            if(url.includes("#")){
            url = url.split('#')[0]
            window.location = url
        }
        }
        fixURL()
        var init = () => {
            storageService = new StorageService();
            keyUtilities = new KeyUtilities(jsSHA);

            // if accounts is null or not an array, set it to an empty array
            if (!storageService.isSupported()) {
                alert('Your browser does not support local storage. Please use a modern browser.');
                return;
            }
            if (!storageService.hasJsonStructure(localStorage.getItem('accounts'))|| storageService.getObject('accounts') == null) {
                storageService.setObject('accounts', {
                    data: [],
                    encryped: false
                });
            }
            // Check if local storage is supported
            if (storageService.isSupported()) {
                if(CryptoService().isPasswordSet()){
                    alert(CryptoService().isPasswordSet())
                updateKeys();
                setInterval(timerTick, 1000);
                }else{
                    if(storageService.getObject('accounts').encrypted){
                    verifyPassword_ui();
                    $('[aria-owns="unlock-keys"]').click()
                    }else{
                        updateKeys();
                        setInterval(timerTick, 1000);
                    }
                }
            } else {
                // No support for localStorage
                $('#updatingIn').text("x");
                $('#accountsHeader').text("No Storage support");
            }

            // Bind to keypress event for the input
            $('#addKeyButton').click(() => {
                var name = $('#keyAccount').val();
                var secret = $('#keySecret').val();
                // remove spaces from secret
                secret = secret.replace(/ /g, '');
                if (secret !== '') {
                    addAccount(name, secret);
                    clearAddFields();
                    $.mobile.navigate('#main');

                } else {
                    $('#keySecret').focus();
                }
            });

            $('#addKeyCancel').click(() => {
                clearAddFields();
            });

            var clearAddFields = () => {
                $('#keyAccount').val('');
                $('#keySecret').val('');
            };
            $('#edit').click(() => { toggleEdit(); });
            $('#delete-keys-button').click(() => cleanupAccounts());

            $("#import-keys-button").click(() => loadImported());
            const file = document.getElementById("keys_upload_input")
            file.addEventListener('change', importAccounts, false);

            $('#export-keys-button').click(() => exportAccounts());
            function flipChanged(e) {
                var id = this.id,
                    value = this.value;
                var enabled = value == 'on' ? true : value == 'off' ? false : null
                window.save_encrypted = enabled;
                if (enabled) {
                    $('#encryption_password').attr("style", "display:inline;text-align:center;")
                } else {
                    $('#encryption_password').attr("style", "display:none;text-align:center;")
                }
            }
            $('#encryption-slider').on("change", flipChanged)

            $("#unlock-keys-button").click(() => {
                verifyPassword_logic()});
        };
        var closeDialog = () => {
            let url = window.location.href;
            url = url.replaceAll('&ui-state=dialog', '')
            window.location = url
        }
        var updateKeys = () => {
            verifyPassword_ui();
            var accountList = $('#accounts');
            // Remove all except the first line
            accountList.find("li:gt(0)").remove();
            $.each(getSafeData(), function (index, account) {
                var key = keyUtilities.generate(account.secret);

                // Construct HTML
                var account_name_elem = '<span>' + account.name + '</span>'
                if (editingEnabled) account_name_elem = '<input type="text" class="account_name_input" id="account_name_' + index + '" value="' + account.name + '" placeholder="Key Name">'
                var accName = $('<p>').html(account_name_elem).html();  // print as-is
                var detLink = $('<span class="secret"><h3>' + key + '</h3>' + accName + '</span>');
                var accElem = $('<li data-icon="false">').append(detLink);
                if (editingEnabled) {
                    var delLink = $('<p class="ui-li-aside"><a class="ui-btn-icon-notext ui-icon-delete" href="#"></a></p>');
                    delLink.click(() => {
                        deleteAccount(index);
                    });
                    accElem.append(delLink);
                }
                // Add HTML element
                accountList.append(accElem);
            });
            accountList.listview().listview('refresh');

        };
        var toggleEdit = () => {
            editingEnabled = !editingEnabled;
            if (editingEnabled) {
                $('#edit').text('Save')
                $('#addButton').show();
            } else {
                saveAccounts();
                $('#edit').text('Edit')
                $('#addButton').hide();
            }
            updateKeys();
        };
        var saveAccounts = () => {
            let accounts = getSafeData();
            $(".account_name_input").each((i, elem) => {
                accounts[i].name = $(elem).val()
            })
            setSafeData(accounts)
            updateKeys();
        }
        //-----DATA WRAPPERS-------------
        var getSafeData = () => {
            try {
                var local_data = storageService.getObject('accounts');
                if (local_data.encrypted) {
                    //verify if password is correct
                    var local_decrypted_data = CryptoService().decrypt(local_data.data, CryptoService().getWindowPassword())
                    if (local_decrypted_data) {
                        return local_decrypted_data
                    }
                } else {
                    return local_data.data
                }
            } catch (e) {
                console.log(e)
                return [{
                    encrypted: false,
                    data: []
                }]
            }


        }
        var addSafeData = (data) => {
            try {
                var local_data = storageService.getObject('accounts')
                if (local_data.encrypted) {
                    var local_encrypted_data_ = CryptoService().encrypt(data, CryptoService().getWindowPassword())
                    storageService.setObject('accounts', { data: local_encrypted_data_, encrypted: true })
                } else {
                    local_data.data.push(data)
                    storageService.setObject('accounts', local_data)
                }
            } catch (e) {
                alert(e)
            }
        }
        var setSafeData = (data_) => {
            try {
                var local_data = storageService.getObject('accounts')
                if (local_data.encrypted) {
                    var local_encrypted_data = CryptoService().encrypt(data_, CryptoService().getWindowPassword())
                    storageService.setObject('accounts', { data: local_encrypted_data, encrypted: true })
                } else {
                    storageService.setObject('accounts', { data: data_, encrypted: false })
                }
            } catch (e) {
                console.log(e)
            }
        }
        //-----DATA WRAPPERS-------------

        //-----ACCOUNT FUNCTIONS-------------
        var cleanupAccounts = () => {
            storageService.setObject('accounts', { data: [], encrypted: false })
            window.location.reload()
        }
        var addAccount = function (name, secret) {
            if (secret === '') {
                // Bailout
                return false;
            }

            // Construct JSON object
            var account = {
                'name': name,
                'secret': secret
            };

            // Persist new object
            var accounts = getSafeData();
            if (!accounts) {
                // if undefined create a new array
                accounts = [];
            }
            accounts.push(account);
            setSafeData(accounts)

            updateKeys();
            toggleEdit();

            return true;
        };
        var deleteAccount = function (index) {
            // Remove object by index
            var accounts = getSafeData();
            accounts.splice(index, 1);
            setSafeData(accounts)
            updateKeys();
        };
        var exportAccounts = () => {
            console.log("saving keys")
            var accounts = JSON.stringify(getSafeData());
            if (window.save_encrypted) {
                let password_input = $("#encryption_password_input")
                let password = password_input.val();
                if (password.length < 1) return alert("Please write a password")
                var data_string = JSON.stringify(accounts)
                var encrypted = CryptoJS.AES.encrypt(data_string, password)
                let tosavedata = {
                    "encrypted": true,
                    "data": encrypted.toString()
                }
                var blob = new Blob([JSON.stringify(tosavedata)], { type: 'text/plain;charset=utf-8' });
                saveAs(blob, 'gauth-encrypted-data.json');
                closeDialog()
            } else {

                let tosavedata = JSON.stringify({
                    encrypted: false,
                    data: accounts
                })
                var blob = new Blob([tosavedata], { type: 'text/plain;charset=utf-8' });
                saveAs(blob, 'gauth-data.json');
                closeDialog()
            }
        };
        //-----------------import suite-----------------
        var loadImported = () => {
            let fileData = window.import_fileData;
            const password = $("#encryption_password_upload_input").val()
            if (fileData.hasOwnProperty("encrypted")) {
                if(fileData.encrypted){
                if(!verifyPassword__(fileData.data,password)) return alert("Wrong password")
                var decryptedFileData = JSON.parse(CryptoService().decrypt(fileData.data, password))
                if (decryptedFileData) {
                    if (!storageService.validate(decryptedFileData)) return alert("Invalid data")
                    setSafeData(decryptedFileData)
                    closeDialog();
                    updateKeys();
                    $("#import_keys_").val("");
                    $.mobile.navigate('#main');
                } else {
                    alert("Wrong password or corrupted file")
                }
            }
            if (!fileData.encrypted) {
                var parsedData = JSON.parse(fileData.data)
                if (!storageService.validate(parsedData)) return alert("Invalid data")
                setSafeData(parsedData)
                closeDialog();
                updateKeys();
                $("#import_keys_").val("");
                $.mobile.navigate('#main');
            }
            
            }
            if (!fileData.hasOwnProperty("encrypted")) {
                var parsedData = fileData
                if (!storageService.validate(parsedData)) return alert("Invalid data")
                setSafeData(parsedData)
                closeDialog();
                updateKeys();
                $("#import_keys_").val("");
                $.mobile.navigate('#main');
            }
        }
        var loadImportedAccount = (event) => {
            const fileDataRaw = event.target.result;
            if (!storageService.hasJsonStructure(fileDataRaw)) return alert("Invalid data")
            const fileData = JSON.parse(fileDataRaw)
            if(fileData.hasOwnProperty("encrypted")){
            if (fileData.encrypted) {
                $('#encryption_password_upload').attr("style", "display:inline;text-align:center;")
                $("#keys_upload_message").text("Your Keys are encrypted, please entry your password")
                window.import_fileData = fileData;
            }
            if (!fileData.encrypted) {
                $("#keys_upload_message").text("There are " + JSON.parse(fileData.data).length + " keys that you can load")
                window.import_fileData = fileData;
            }
        }
        if (!fileData.hasOwnProperty("encrypted")) {
            $("#keys_upload_message").text("There are " + fileData.length + " keys that you can load")
            window.import_fileData = fileData;
        }
        }
        var importAccounts = (event) => {
            const file = document.getElementById("keys_upload_input")
            // Stop the form from reloading the page
            event.preventDefault();
            // If there's no file, do nothing
            if (!file.value.length) return;
            // Create a new FileReader() object
            let reader = new FileReader();
            // Setup the callback event to run when the file is read
            reader.onload = (event) => {
                loadImportedAccount(event);
            }
            // Read the file
            reader.readAsText(file.files[0]);
        }
        //-----------------import suite-----------------
        //-----ACCOUNT FUNCTIONS-------------

        //-----BROWSER ENCRYPTION FUNCTIONS-------------
        var encryptBrowser = () => {
            var accounts = storageService.getObject('accounts')
            if (accounts.encrypted) {
                alert("Already encrypted")
                return
            }
            var encrypted_data = CryptoService().encrypt(accounts.data, CryptoService().getWindowPassword()).toString()
            storageService.setObject('accounts', { data: encrypted_data, encrypted: true })
            closeDialog();
            updateKeys();
        }
        var decryptBrowser = (password) => {
            //try the password
            var accounts = storageService.getObject('accounts')
            if (!accounts.encrypted) {
            }
            try{
                var decrypted_data = CryptoService().decrypt(accounts.data, password)
            }catch(e){
                alert("Wrong password")
                return
            }
            var accounts = getSafeData()
            if (!storageService.getObject("accounts").encrypted) {
                alert("Already decrypted")
                return
            }
            storageService.setObject('accounts', { data: accounts, encrypted: false })
            closeDialog();
            verifyPassword_ui();
            updateKeys();
            CryptoService().setWindowPassword(password)
        }
        var changePassword = () => {
            var accounts = storageService.getObject('accounts');
            if (!accounts.encrypted) {
                alert("You need to encrypt your data first")
                return
            }
            var encrypted_data = CryptoService().encrypt(accounts.data, CryptoService().getWindowPassword())
            storageService.setObject('accounts', { data: encrypted_data, encrypted: true })
            closeDialog();
            updateKeys();
        }
        var verifyPassword_ = (password) => {
            let accounts = storageService.getObject('accounts')
            try{
                var decrypted_data = CryptoService().decrypt(accounts.data, password)
                return true
            }
            catch(e){
                alert("Wrong password")
                return false
            }
        }
        var verifyPassword__ = (data,password) => {
            try{
                var decrypted_data = CryptoService().decrypt(data, password)
                return true
            }
            catch(e){
                return false
            }
        }
        var verifyPassword_logic = () => {
            if(storageService.getObject('accounts').encrypted && CryptoService().isPasswordSet()){
                if(verifyPassword_($("#encryption_password_unlock_input").val())){
                decryptBrowser($("#encryption_password_unlock_input").val())
                $("#encryption_password_unlock_input").val("")
                }else{
                $("#encryption_password_unlock_input").val("")
                }
            }else

            if(storageService.getObject('accounts').encrypted && !CryptoService().isPasswordSet()){
                if(verifyPassword_($("#encryption_password_unlock_input").val())){
                CryptoService().setWindowPassword($("#encryption_password_unlock_input").val())
                $("#encryption_password_unlock_input").val("")
                updateKeys();
                closeDialog();
                }else{
                $("#encryption_password_unlock_input").val("")
                }
            }else

            if(!storageService.getObject('accounts').encrypted){
                CryptoService().setWindowPassword($("#encryption_password_unlock_input").val())
                $("#encryption_password_unlock_input").val("")
                encryptBrowser()
            }else{}
        }
        var verifyPassword_ui = () => {

            if(storageService.getObject('accounts').encrypted && CryptoService().isPasswordSet()){
                CryptoService().setBroserSafu(true)
                $('[aria-owns="unlock-keys"]').text("Disable Browser Encryption")
                $("#unlock-keys-title").text("Browser level encryption is enabled")
                $("#unlock-keys-subtitle").text("Please enter your password to disable encryption")
                $("#unlock-keys-button").text("Disable Browser Encryption")
                
            }
            if(storageService.getObject('accounts').encrypted && !CryptoService().isPasswordSet()){
                $('[aria-owns="unlock-keys"]').text("Your data is encrypted")
                $("#unlock-keys-title").text("Browser level encryption is enabled")
                $("#unlock-keys-subtitle").text("Please enter your password to access your data")
                $("#unlock-keys-button").text("Access Encrypted Data")
            }
            if(!storageService.getObject('accounts').encrypted){
                CryptoService().setBroserSafu(false)
                $('[aria-owns="unlock-keys"]').text("Enable Browser Encryption")
                $("#unlock-keys-title").text("Browser level encryption is disabled")
                $("#unlock-keys-subtitle").text("Please enter your password to lock your keys")
                $("#unlock-keys-button").text("Enable Browser Encryption")
            }
        }

        //-----BROWSER ENCRYPTION FUNCTIONS-------------
        //----------------------------------
        var timerTick = () => {
            var epoch = Math.round(new Date().getTime() / 1000.0);
            var countDown = 30 - (epoch % 30);
            if (epoch % 30 === 0) {
                if (!editingEnabled) updateKeys();
            }
            $('#updatingIn').text(countDown);
        };
        return {
            init: init,
            addAccount: addAccount,
            deleteAccount: deleteAccount
        };
    }
    exports.KeysController = KeysController;
    //==========

})(typeof exports === 'undefined' ? this['gauth'] = {} : exports);
