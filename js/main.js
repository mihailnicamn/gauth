// Main function
$(document).on('ready', function() {
    // Use exports from locally defined module
    var keysController = new gauth.KeysController();
    keysController.init();
});