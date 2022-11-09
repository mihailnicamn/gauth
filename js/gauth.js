// A simple authentication application written in HTML
// Copyright (C) 2012 Gerard Braad
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.


(function (exports) {
    "use strict";
    window.save_encrypted = false;
    window.load_keys_encrypted = false;
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
    }
    var StorageService = function () {
        var setObject = function (key, value) {
            localStorage.setItem(key, JSON.stringify(value));
        };

        var getObject = function (key) {
            var value = localStorage.getItem(key);
            // if(value) return parsed JSON else undefined
            return value && JSON.parse(value);
        };

        var isSupported = function () {
            return typeof (Storage) !== "undefined";
        };

        // exposed functions
        return {
            isSupported: isSupported,
            getObject: getObject,
            setObject: setObject
        };
    };
    exports.StorageService = StorageService;

    // Originally based on the JavaScript implementation as provided by Russell Sayers on his Tin Isles blog:
    // http://blog.tinisles.com/2011/10/google-authenticator-one-time-password-algorithm-in-javascript/

    var KeyUtilities = function (jsSHA) {

        var dec2hex = function (s) {
            return (s < 15.5 ? '0' : '') + Math.round(s).toString(16);
        };

        var hex2dec = function (s) {
            return parseInt(s, 16);
        };

        var base32tohex = function (base32) {
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

        var leftpad = function (str, len, pad) {
            if (len + 1 >= str.length) {
                str = new Array(len + 1 - str.length).join(pad) + str;
            }
            return str;
        };

        var generate = function (secret, epoch) {
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

    // ----------------------------------------------------------------------------
    var KeysController = function () {
        var storageService = null,
            keyUtilities = null,
            editingEnabled = false;
        var init = function () {
            storageService = new StorageService();
            keyUtilities = new KeyUtilities(jsSHA);

            // Check if local storage is supported
            if (storageService.isSupported()) {
                if (!storageService.getObject('accounts')) {
                    //addAccount('alice@google.com (demo account)', 'JBSWY3DPEHPK3PXP');
                    storageService.setObject('accounts', []);
                    toggleEdit();
                }

                updateKeys();
                setInterval(timerTick, 1000);
            } else {
                // No support for localStorage
                $('#updatingIn').text("x");
                $('#accountsHeader').text("No Storage support");
            }

            // Bind to keypress event for the input
            $('#addKeyButton').click(function () {
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

            $('#addKeyCancel').click(function () {
                clearAddFields();
            });

            var clearAddFields = function () {
                $('#keyAccount').val('');
                $('#keySecret').val('');
            };

            $('#edit').click(function () { toggleEdit(); });
            $('#delete-keys-button').click(() => cleanupAccounts());

            $("#import-keys-button").click( () => loadImported() );
            const file = document.getElementById("keys_upload_input")
            file.addEventListener('change', importAccounts, false);

            $('#export-keys-button').click(()=> exportAccounts() );
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
        };
        var updateKeys = function () {
            var accountList = $('#accounts');
            // Remove all except the first line
            accountList.find("li:gt(0)").remove();

            $.each(storageService.getObject('accounts'), function (index, account) {
                var key = keyUtilities.generate(account.secret);

                // Construct HTML
                var account_name_elem = '<span>' + account.name + '</span>'
                if (editingEnabled) account_name_elem = '<input type="text" class="account_name_input" id="account_name_' + index + '" value="' + account.name + '" placeholder="Key Name">'
                var accName = $('<p>').html(account_name_elem).html();  // print as-is
                var detLink = $('<span class="secret"><h3>' + key + '</h3>' + accName + '</span>');
                var accElem = $('<li data-icon="false">').append(detLink);
                if (editingEnabled) {
                    var delLink = $('<p class="ui-li-aside"><a class="ui-btn-icon-notext ui-icon-delete" href="#"></a></p>');
                    delLink.click(function () {
                        deleteAccount(index);
                    });
                    accElem.append(delLink);
                }
                // Add HTML element
                accountList.append(accElem);
            });
            accountList.listview().listview('refresh');
        };
        var saveAccounts = () => {
            let accounts = storageService.getObject('accounts');
            $(".account_name_input").each((i, elem) => {
                accounts[i].name = $(elem).val()
            })
            storageService.setObject('accounts', accounts);
            updateKeys();
        }
        var toggleEdit = function () {
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
        var closeDialog = () => {
            let url = window.location.href;
            url = url.replaceAll('&ui-state=dialog','')
            window.location = url
        }
        var exportAccounts = function () {
            console.log("saving keys")
            var accounts = JSON.stringify(storageService.getObject('accounts'));
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
        const validate = (data) => {
            if (!Array.isArray(data)) return false;
            if (data.length < 1) return false;
            return data.map((entry) => {
                return (entry.hasOwnProperty('name') && entry.hasOwnProperty('secret'))
            }).every(element => element === true);
        }
        var loadImported = () => {
            let data = window.import_fileData;
            const password = $("#encryption_password_upload_input").val()
            if(data.encrypted){
                if(password.length<1) return alert("Please enter your password")
                try {
                    var decrypted = CryptoJS.AES.decrypt(data.data, password);
                    var data_ = JSON.parse(JSON.parse(decrypted.toString(CryptoJS.enc.Utf8)));
                    if(!validate(data_)) return alert("Data is not valid")
                    storageService.setObject('accounts', data_);
                    updateKeys();
                    $("#import_keys_").val("")
                    $.mobile.navigate('#main');
                    
                } catch (error) {
                    alert("Wrong Password or File")
                    
                }
            }
            if(!data.encrypted){
            if(!validate(data.data)) return alert("Data is not valid")
            storageService.setObject('accounts', data.data);
            updateKeys();
            $("#import_keys_").val("")
            $.mobile.navigate('#main');
            }
        }
        var loadImportedAccount = (event) =>{
            const fileDataRaw = event.target.result;
            if(!hasJsonStructure(fileDataRaw)) return alert("Not gauth compatible FileType")
            const fileData = JSON.parse(fileDataRaw)
            if(fileData.encrypted){
                $('#encryption_password_upload').attr("style", "display:inline;text-align:center;")
                $("#keys_upload_message").text("Your Keys are encrypted, please entry your password")
                window.import_fileData = fileData;
            }
            if(!fileData.encrypted){
                $("#keys_upload_message").text("There are "+JSON.parse(fileData.data).length+" keys that you can load")
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
        var cleanupAccounts = () => {
            storageService.setObject('accounts', []);
            updateKeys();
            $.mobile.navigate('#main');
            
        }
        var deleteAccount = function (index) {
            // Remove object by index
            var accounts = storageService.getObject('accounts');
            accounts.splice(index, 1);
            storageService.setObject('accounts', accounts);
            updateKeys();
        };
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
            var accounts = storageService.getObject('accounts');
            if (!accounts) {
                // if undefined create a new array
                accounts = [];
            }
            accounts.push(account);
            storageService.setObject('accounts', accounts);

            updateKeys();
            toggleEdit();

            return true;
        };
        var timerTick = function () {
            var epoch = Math.round(new Date().getTime() / 1000.0);
            var countDown = 30 - (epoch % 30);
            if (epoch % 30 === 0) {
                if(!editingEnabled) updateKeys();
            }
            $('#updatingIn').text(countDown);
        };
        return {
            init: init,
            addAccount: addAccount,
            deleteAccount: deleteAccount
        };
    };

    exports.KeysController = KeysController;

})(typeof exports === 'undefined' ? this['gauth'] = {} : exports);
