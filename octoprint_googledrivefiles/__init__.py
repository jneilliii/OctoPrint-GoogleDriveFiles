# coding=utf-8
from __future__ import absolute_import

import threading

import octoprint.plugin
import flask
import os
from flask_babel import gettext
from octoprint.access.permissions import Permissions, ADMIN_GROUP


class GoogledrivefilesPlugin(octoprint.plugin.SettingsPlugin,
                             octoprint.plugin.AssetPlugin,
                             octoprint.plugin.TemplatePlugin,
                             octoprint.plugin.SimpleApiPlugin,
                             octoprint.plugin.EventHandlerPlugin,
                             ):

    def __init__(self):
        super().__init__()
        self.config = {}
        self.gauth = None
        self.downloading_files = {}
        self.google_files = []
        self.google_files_removed = []
        self.local_files_removed = []
        self.local_files_added = []
        self.syncing = False

    # ~~ SettingsPlugin mixin

    def get_settings_defaults(self):
        return {
            "cert_saved": False,
            "cert_authorized": False,
            "download_folder": "OctoPrint GCode",
        }

    def on_settings_initialized(self):
        self.reload_settings()

    def on_settings_save(self, data):
        octoprint.plugin.SettingsPlugin.on_settings_save(self, data)
        self.reload_settings()

    def reload_settings(self):
        for k, v in self.get_settings_defaults().items():
            if type(v) == str:
                v = self._settings.get([k])
            elif type(v) == int:
                v = self._settings.get_int([k])
            elif type(v) == float:
                v = self._settings.get_float([k])
            elif type(v) == bool:
                v = self._settings.get_boolean([k])

            self.config[k] = v
            self._logger.debug("{}: {}".format(k, v))

    # ~~ SimpleApiPlugin mixin

    def get_api_commands(self):
        return {'gen_secret': ["json_data"], 'authorize': ["auth_code"]}

    def on_api_command(self, command, data):
        import flask
        if not Permissions.PLUGIN_GOOGLEDRIVEFILES_ACCESS.can():
            return flask.make_response("Insufficient rights", 403)

        from pydrive2.auth import GoogleAuth
        config_file = "{}/client_secrets.json".format(self.get_plugin_data_folder())
        credentials_file = "{}/credentials.json".format(self.get_plugin_data_folder())
        if not self.gauth:
            self.gauth = GoogleAuth()

        if command == "gen_secret":
            import json
            # write out our client_secrets.json file
            with open(config_file, "w") as f:
                f.write(json.dumps(data["json_data"]))
            self._settings.set(["cert_saved"], True)
            self._settings.save()

            self.gauth.LoadClientConfigFile(config_file)
            self.gauth.GetFlow()
            self.gauth.flow.params.update({'access_type': 'offline'})
            self.gauth.flow.params.update({'approval_prompt': 'force'})
            auth_url = self.gauth.GetAuthUrl()
            return flask.jsonify(dict(cert_saved=True, url=auth_url))

        if command == "authorize":
            self._logger.info("Attempting to authorize Google App")
            if not self.gauth:
                return flask.jsonify({'authorized': False})
            # Try to load saved client credentials
            self.gauth.Auth(data["auth_code"])
            self.gauth.SaveCredentialsFile(credentials_file)
            self._settings.set(["cert_authorized"], True)
            self._settings.save()
            self.reload_settings()
            sync_worker = threading.Thread(target=self.sync_files, daemon=True)
            sync_worker.start()
            return flask.jsonify({'authorized': True})

    def sync_files(self):
        if self.config['cert_authorized'] and not self.syncing:
            try:
                self.syncing = True
                drive = self._get_drive()
                folder_id = None
                files_removed = False
                files_added = False
                self.google_files = []
                self.google_files_removed = []
                if not self.config["download_folder"] == "":
                    folder_id = self.get_create_remote_folder(drive, self.config["download_folder"])
                google_file_list = drive.ListFile({'q': "trashed=false and '{}' in parents and title contains '.gcode'".format(folder_id or "root")}).GetList()
                local_file_list = self._file_manager.list_files("local", "Google")["local"]
                if len(google_file_list) < len(local_file_list):
                    files_removed = True

                for file in google_file_list:
                    if not self._file_manager.file_exists("local", "Google/{}".format(file["title"])) and not self.downloading_files.get(file["title"], False) or self._file_manager.get_metadata("local", "Google/{}".format(file["title"])) and self._file_manager.get_metadata("local", "Google/{}".format(file["title"])).get("googledrive") != file["modifiedDate"]:
                        if file["title"] not in self.local_files_removed:
                            if file["title"] in self.local_files_added:
                                self._logger.debug("{} was added locally, cleaning up".format(file["title"]))
                                self.local_files_added.remove(file["title"])
                            else:
                                self._logger.debug("{} doesn't exist or updated, downloading".format(file["title"]))
                                self.downloading_files[file["title"]] = file["modifiedDate"]
                                file.GetContentFile("{}/Google/{}".format(self._settings.getBaseFolder("watched"), file["title"]))
                        else:
                            self._logger.debug("{} was deleted locally, cleaning up".format(file["title"]))
                            self.local_files_removed.remove(file["title"])
                    elif self.downloading_files.get(file["title"], False):
                        self._logger.debug("{} already downloading".format(file["title"]))
                    else:
                        self._logger.debug("{} is current".format(file["title"]))
                    if files_removed:
                        self.google_files.append(file["title"])

                if len(self.google_files) > 0:
                    for file in local_file_list:
                        if file not in self.google_files and file not in self.local_files_added:
                            self._logger.debug("{} was removed from Google, deleting locally".format(file))
                            self.google_files_removed.append(file)
                            self._file_manager.remove_file("local", "Google/{}".format(file))
            except Exception as e:
                self._logger.error(e)
                google_file_list = {}

            self.syncing = False

            return google_file_list

    def get_create_remote_folder(self, drive, folder_name):
        folder_list = (drive.ListFile({'q': "mimeType='application/vnd.google-apps.folder' and trashed=false and title='{}'".format(folder_name)}).GetList())

        if not self._file_manager.folder_exists("local", "Google"):
            self._logger.debug("Creating local Google folder in uploads")
            self._file_manager.add_folder("local", "Google")

        if not os.path.exists("{}/Google".format(self._settings.getBaseFolder("watched"))):
            self._logger.debug("Creating local Google folder in watched folder")
            os.makedirs("{}/Google".format(self._settings.getBaseFolder("watched")))

        if len(folder_list) == 1:
            return folder_list[0]["id"]

        file_metadata = {
            "title": folder_name,
            "mimeType": "application/vnd.google-apps.folder"
        }
        file0 = drive.CreateFile(file_metadata)
        file0.Upload()
        return file0["id"]

    # ~~ EventHandlerPlugin mixin

    def on_event(self, event, payload):
        if event == "FileAdded" and payload.get("name", False):
            if payload["name"] in self.downloading_files:
                self._logger.debug("adding metadata to {}".format(payload["name"]))
                self._file_manager.set_additional_metadata("local", payload["path"], "googledrive", self.downloading_files[payload["name"]], overwrite=True)
                self.downloading_files.pop(payload["name"])
            elif payload["path"].startswith("Google/"):
                self._logger.debug("{} added locally, uploading to Google".format(payload["name"]))
                self.local_files_added.append(payload["name"])
                folder_id = None
                drive = self._get_drive()
                if not self.config["download_folder"] == "":
                    folder_id = self.get_create_remote_folder(drive, self.config["download_folder"])
                file_list = drive.ListFile({'q': "title='{}' and trashed=false and '{}' in parents".format(payload["name"], folder_id or "root")}).GetList()
                if len(file_list) == 1:
                    f = file_list[0]
                else:
                    file_metadata = {"title": payload["name"]}
                    if folder_id:
                        file_metadata["parents"] = [{"id": folder_id}]
                    f = drive.CreateFile(file_metadata)
                f.SetContentFile(self._file_manager.path_on_disk("local", payload["path"]))
                f.Upload()
                self._logger.debug("adding metadata to {}".format(payload["name"]))
                self._file_manager.set_additional_metadata("local", payload["path"], "googledrive", f["modifiedDate"], overwrite=True)
                f = None

        if event == "FileRemoved" and payload.get("path", False) and payload["path"].startswith("Google/") and payload["name"] not in self.google_files_removed:
            self._logger.debug("{} file removed locally, deleting from Google".format(payload["name"]))
            self.local_files_removed.append(payload["name"])
            folder_id = None
            drive = self._get_drive()
            if not self.config["download_folder"] == "":
                folder_id = self.get_create_remote_folder(drive, self.config["download_folder"])
            google_file_list = drive.ListFile({'q': "trashed=false and '{}' in parents and title = '{}'".format(folder_id or "root", payload["name"])}).GetList()
            if len(google_file_list) > 0:
                google_file_list[0].Trash()

    def _get_drive(self):
        from pydrive2.auth import GoogleAuth
        from pydrive2.drive import GoogleDrive

        credentials_file = "{}/credentials.json".format(self.get_plugin_data_folder())
        if not self.gauth:
            self.gauth = GoogleAuth()

        self.gauth.LoadCredentialsFile(credentials_file)
        if self.gauth.credentials is None:
            self._logger.error("not authorized")
            self._settings.set(["cert_authorized"], False)
            self._settings.save()
            return flask.jsonify({"error": "not authorized"})
        elif self.gauth.access_token_expired:
            self.gauth.Refresh()
        else:
            self.gauth.Authorize()

        drive = GoogleDrive(self.gauth)
        return drive

    # ~~ AssetPlugin mixin

    def get_assets(self):
        return {
            "js": ["js/googledrivefiles.js"],
        }

    # ~~ TemplatePlugin mixin

    def get_template_vars(self):
        return {"plugin_version": self._plugin_version}

    def update_file_list(self):
        if self.config['cert_authorized'] and flask.request.path.startswith('/api/files') and flask.request.method == 'GET' and not self.syncing:
            self.sync_files()

    # ~~ Server API Before Request Hook

    def hook_octoprint_server_api_before_request(self, *args, **kwargs):
        return [self.update_file_list]

    # ~~ Access Permissions Hook

    def get_additional_permissions(self, *args, **kwargs):
        return [
            {'key': "ACCESS", 'name': "Access Files", 'description': gettext("Allows access to Google Drive files."),
             'roles': ["admin"], 'dangerous': True, 'default_groups': [ADMIN_GROUP]}
        ]

    # ~~ Softwareupdate hook

    def get_update_information(self):
        return {
            "googledrivefiles": {
                "displayName": "Google Drive Files",
                "displayVersion": self._plugin_version,

                # version check: github repository
                "type": "github_release",
                "user": "jneilliii",
                "repo": "OctoPrint-GoogleDriveFiles",
                "current": self._plugin_version,
                "stable_branch": {
                    "name": "Stable",
                    "branch": "master",
                    "comittish": ["master"]
                },
                "prerelease_branches": [
                    {
                        "name": "Release Candidate",
                        "branch": "rc",
                        "comittish": ["rc", "master"]
                    }
                ],

                # update method: pip
                "pip": "https://github.com/jneilliii/OctoPrint-GoogleDriveFiles/archive/{target_version}.zip",
            }
        }


__plugin_name__ = "Google Drive Files"
__plugin_pythoncompat__ = ">=3,<4"  # only python 3


def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = GoogledrivefilesPlugin()

    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.access.permissions": __plugin_implementation__.get_additional_permissions,
        "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information,
        "octoprint.server.api.before_request": __plugin_implementation__.hook_octoprint_server_api_before_request,
    }
