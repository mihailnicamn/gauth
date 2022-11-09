// Init function
$(document).bind('mobileinit', function(){
    $.mobile.defaultPageTransition = 'none';
    $.mobile.defaultDialogTransition = 'none';
});

$(function() {
    // Initialize external panels
    window.save_encrypted = false;
    window.load_keys_encrypted = false;
    $("body>[data-role='panel']").panel().enhanceWithin();
});