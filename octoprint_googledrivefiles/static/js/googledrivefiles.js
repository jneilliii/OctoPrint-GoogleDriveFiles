/*
 * View model for OctoPrint-GoogleDriveFiles
 *
 * Author: jneilliii
 * License: AGPLv3
 */
$(function() {
    function GoogledrivefilesViewModel(parameters) {
        var self = this;

        self.settingsViewModel = parameters[0];
        self.cert_saved = ko.observable(false);
        self.cert_authorized = ko.observable(false);
        self.authorizing = ko.observable(false);
        self.cert_file_name = ko.observable('');
        self.cert_file_data = undefined;
        self.auth_code = ko.observable('');
        self.auth_url = ko.observable('#');

        var certFileuploadOptions = {
            dataType: "json",
            maxNumberOfFiles: 1,
            autoUpload: false,
            headers: OctoPrint.getRequestHeaders(),
            add: function(e, data) {
                if (data.files.length === 0) {
                    // no files? ignore
                    return false;
                }

                self.cert_file_name(data.files[0].name);
                self.cert_file_data = data;
            },
            done: function(e, data) {
                self.cert_file_name(undefined);
                self.cert_file_data = undefined;
            }
        };

        $("#googledrivefiles_cert_file").fileupload(certFileuploadOptions);

        self.onBeforeBinding = function() {
            self.cert_saved(self.settingsViewModel.settings.plugins.googledrivefiles.cert_saved());
            self.cert_authorized(self.settingsViewModel.settings.plugins.googledrivefiles.cert_authorized());
        };
        
        self.onDataUpdaterPluginMessage = function(plugin, data) {
            if (plugin != "googledrivefiles" || !data) {
                return;
            }
            console.log(data)
            if (data.hasOwnProperty("authorized")) {
                self.cert_authorized(data.authorized);
                self.auth_url('#');
                self.authorizing(false);
            }
        }

        self.uploadCertFile = function(){
            if (self.cert_file_data === undefined) return;
            self.authorizing(true);
            var input, file, fr;

            if (typeof window.FileReader !== 'function') {
              alert("The file API isn't supported on this browser yet.");
              self.authorizing(false);
              return;
            }

            file = self.cert_file_data.files[0];
            fr = new FileReader();
            fr.onload = receivedText;
            fr.readAsText(file);

            function receivedText(e) {
                let lines = e.target.result;
                var json_data = JSON.parse(lines);
				if (json_data.hasOwnProperty("installed")) {
					json_data["installed"]["redirect_uris"] = ["urn:ietf:wg:oauth:2.0:oob", window.location.origin + '/api/plugin/googledrivefiles'];
				$.ajax({
                    url: API_BASEURL + "plugin/googledrivefiles",
                    type: "POST",
                    dataType: "json",
                    data: JSON.stringify({command: "gen_secret", json_data: json_data}),
                    contentType: "application/json; charset=UTF-8"
                }).done(function(data){
                    if(data.cert_saved){
                        self.cert_saved(true);
                        self.auth_url(data.url);
                        self.authorizing(false);
                    }
                }).fail(function(data){
                    console.log("error uploading cert file");
                    self.authorizing(false);
                });
            }
        };

        self.authorizeCertFile = function(){
            if(self.auth_code() === '') return;
            self.authorizing(true);
            $.ajax({
                url: API_BASEURL + "plugin/googledrivefiles",
                type: "POST",
                dataType: "json",
                data: JSON.stringify({command: "authorize", auth_code: self.auth_code()}),
                contentType: "application/json; charset=UTF-8"
            }).done(function(data){
                if(data.authorized){
                    self.cert_authorized(true);
                    self.authorizing(false);
                }
            }).fail(function(data){
                console.log("error authorizing");
                self.cert_authorized(false);
                self.authorizing(false);
            });
        };

        self.deleteCertFiles = function(){
            self.cert_saved(false);
            self.cert_authorized(false);
        };
    }

    OCTOPRINT_VIEWMODELS.push({
        construct: GoogledrivefilesViewModel,
        dependencies: [ "settingsViewModel" ],
        elements: [ "#settings_plugin_googledrivefiles" ]
    });
});
