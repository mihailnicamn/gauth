// Main function
$(document).on('pagecreate', '#main', function() {
    // Use exports from locally defined module
    var keysController = new gauth.KeysController();
    keysController.init();
});
$(document).on('pagecreate', '#settings', function() {
    // Use exports from locally defined module
    var keysController = new gauth.KeysController();
    keysController.init();
});
