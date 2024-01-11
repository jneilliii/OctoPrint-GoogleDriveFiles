# coding=utf-8
from __future__ import absolute_import

import threading

import octoprint.plugin
import flask
import json
import os
from flask_babel import gettext
from octoprint.access.permissions import Permissions, ADMIN_GROUP
from treelib import Tree, Node


class GoogledrivefilesPlugin(octoprint.plugin.SettingsPlugin,
                             octoprint.plugin.AssetPlugin,
                             octoprint.plugin.TemplatePlugin,
                             octoprint.plugin.SimpleApiPlugin,
                             octoprint.plugin.EventHandlerPlugin,
                             octoprint.plugin.BlueprintPlugin,
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
        self.sync_thread = None

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

    def on_api_get(self, request):
        if not Permissions.PLUGIN_GOOGLEDRIVEFILES_ACCESS.can():
            return flask.make_response("Insufficient rights", 403)
        response = self.on_api_command("authorize", {"auth_code": request.values.get("code")})
        self._plugin_manager.send_plugin_message(self._identifier, json.loads(response.response[0]))
        return flask.make_response("Authorization Success", 200)


    def on_api_command(self, command, data):
        if not Permissions.PLUGIN_GOOGLEDRIVEFILES_ACCESS.can():
            return flask.make_response("Insufficient rights", 403)

        from pydrive2.auth import GoogleAuth
        config_file = "{}/client_secrets.json".format(self.get_plugin_data_folder())
        credentials_file = "{}/credentials.json".format(self.get_plugin_data_folder())
        if not self.gauth:
            self.gauth = GoogleAuth()

        if command == "gen_secret":
            import json
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
            self.sync_thread = threading.Thread(target=self.sync_files, daemon=True)
            self.sync_thread.start()
            return flask.jsonify({'authorized': True})

    def sync_files(self):
        if self.config['cert_authorized']:
            try:
                drive = self._get_drive()
                folder_id = None
                files_removed = False
                files_added = False
                self.google_files = []
                self.google_files_removed = []
                if not self.config["download_folder"] == "":
                    folder_id = self.get_create_remote_folder(drive, self.config["download_folder"])
                tree = Tree()
                tree.create_node("Google", folder_id or "root")
                google_file_list = drive.ListFile({'q': "trashed=false and (title contains '.gcode' or title contains '.bgcode' or mimeType='application/vnd.google-apps.folder')", 'orderBy': 'createdDate'}).GetList()
                for google_file in google_file_list:
                    if len(google_file['parents']) > 0:
                        if tree.get_node(google_file['id']) is None:
                            if tree.get_node(google_file['parents'][0]['id']):
                                tree.create_node(google_file['title'], google_file['id'], parent=google_file['parents'][0]['id'], data=google_file)
                local_file_list = self._flatten_files("Google")

                # flatten our tree into dict of paths with google drive data
                leave_paths = tree.paths_to_leaves()
                google_file_paths = {}
                for leave_path in leave_paths:
                    full_path = ""
                    for folder_identifier in leave_path:
                        full_path += "/{}".format(tree.get_node(folder_identifier).tag)
                    if full_path.lower().endswith(".gcode") or full_path.lower().endswith(".gco") or full_path.lower().endswith(".bgcode"):
                        google_file_paths[full_path[1:]] = tree.get_node(folder_identifier).data

                for file in google_file_paths:
                    if not self.downloading_files.get(file, False):
                        if not self._file_manager.file_exists("local", file) or self._file_manager.get_metadata("local", file).get("googledrive") != google_file_paths[file]["md5Checksum"]:
                            self._logger.debug("{} updated on Google or missing".format(file))
                            self.downloading_files[file] = google_file_paths[file]
                            path_on_disk = "{}/{}".format(self._settings.getBaseFolder("watched"), file)
                            folder_path = os.path.split(path_on_disk)[0]
                            if not os.path.exists(folder_path):
                                os.makedirs(folder_path)
                            google_file_paths[file].GetContentFile(path_on_disk)
                        else:
                            self._logger.debug("{} up to date".format(file))
                    else:
                        self._logger.debug("{} already downloading".format(file))

            except Exception as e:
                self._logger.error(e)
                google_file_list = {}

            files_removed = local_file_list.keys() - google_file_paths.keys()
            if len(files_removed) > 0:
                for file_removed in files_removed:
                    if file_removed not in self.local_files_added:
                        self.google_files_removed.append(file_removed)
                        self._logger.debug("{} removed from Google deleting".format(file_removed))
                        self._file_manager.remove_file("local", file_removed)
                        path_on_disk = os.path.join(self._settings.getBaseFolder("uploads"), file_removed)
                        if not os.path.exists(path_on_disk) and file_removed in local_file_list:
                            local_file_list.pop(file_removed)
                        folder_path = os.path.split(path_on_disk)[0]
                        if os.path.exists(folder_path) and os.listdir(folder_path) == ['.metadata.json']:
                            os.remove(os.path.join(folder_path, ".metadata.json"))
                            self._logger.debug("{} empty deleting".format(folder_path))
                            os.removedirs(folder_path)

            self.sync_thread = None
            return google_file_list

    def _flatten_files(self, folder, filelist={}):
        if type(folder) == str:
            folder = self._file_manager.list_files("local", folder, recursive=True)["local"]
        if folder is not None:
            for fileKey in folder:
                if folder[fileKey].get("type") == "machinecode":
                    filelist[folder[fileKey].get("path")] = folder[fileKey]
                if folder[fileKey]["type"] == "folder" and len(folder[fileKey].get("children", [])) > 0:
                    self._flatten_files(folder[fileKey].get("children"), filelist)
        return filelist

    def get_create_remote_folder(self, drive, folder_name):
        def create_drive_folder_level(filename, parents):
            dirs = drive.ListFile({'q': "'{}' in parents and trashed=false and mimeType='application/vnd.google-apps.folder'".format(parents[-1]['id'])})
            try:
                # this will give me the parent folder, if it exists
                current = [x for x in list(dirs)[0] if x['title'] == filename][0]
            except IndexError:
                current = None
            if not current:
                meta = {'title': filename, 'parents': [{'id': x['id']} for x in [parents[-1]]], 'mimeType': 'application/vnd.google-apps.folder'}
                current = drive.CreateFile(meta)
                current.Upload({'convert': True})
                return current
            return current

        folder_name = folder_name.split('/')
        p = [dict(id='root')]
        for i in range(len(folder_name)):
            p.append(create_drive_folder_level(folder_name[i], p))

        folder_list = p[-1]

        if not self._file_manager.folder_exists("local", "Google"):
            self._logger.debug("Creating local Google folder in uploads")
            self._file_manager.add_folder("local", "Google")

        if not os.path.exists("{}/Google".format(self._settings.getBaseFolder("watched"))):
            self._logger.debug("Creating local Google folder in watched folder")
            os.makedirs("{}/Google".format(self._settings.getBaseFolder("watched")))

        if folder_list.get("id", False):
            return folder_list["id"]

        file_metadata = {
            "title": folder_name,
            "mimeType": "application/vnd.google-apps.folder"
        }
        file0 = drive.CreateFile(file_metadata)
        file0.Upload()
        return file0["id"]

    # ~~ EventHandlerPlugin mixin

    def on_event(self, event, payload):
        if event == "FileAdded" and payload.get("path", False):
            if payload["path"] in self.downloading_files:
                self._logger.debug("adding metadata to {}".format(payload["path"]))
                self._file_manager.set_additional_metadata("local", payload["path"], "googledrive", self.downloading_files[payload["path"]]["md5Checksum"], overwrite=True)
                self.downloading_files.pop(payload["path"])
            elif payload["path"].startswith("Google/"):
                self.local_files_added.append(payload["path"])
                self._logger.debug("{} added locally, uploading to Google".format(payload["name"]))
                folder_id = None
                drive = self._get_drive()
                if not self.config["download_folder"] == "":
                    folder_path = os.path.split(payload["path"])[0].replace("Google", self.config["download_folder"])
                    folder_id = self.get_create_remote_folder(drive, folder_path)
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
                self._logger.debug("adding metadata to {}".format(payload["path"]))
                self._file_manager.set_additional_metadata("local", payload["path"], "googledrive", f["md5Checksum"], overwrite=True)
                self.local_files_added.remove(payload["path"])
                f = None

        elif event == "FileRemoved" and payload.get("path", False) and payload["path"].startswith("Google/") and payload["path"] not in self.google_files_removed:
            self._logger.debug("{} file removed locally, deleting from Google".format(payload["name"]))
            self.local_files_removed.append(payload["path"])
            folder_id = None
            drive = self._get_drive()
            if not self.config["download_folder"] == "":
                folder_path = os.path.split(payload["path"])[0].replace("Google", self.config["download_folder"])
                folder_id = self.get_create_remote_folder(drive, folder_path)
            google_file_list = drive.ListFile({'q': "trashed=false and '{}' in parents and title = '{}'".format(folder_id or "root", payload["name"])}).GetList()
            if len(google_file_list) > 0:
                google_file_list[0].Trash()
            self.local_files_removed.remove(payload["path"])

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
        if self.config['cert_authorized'] and flask.request.path.startswith('/api/files') and flask.request.method == 'GET' and self.sync_thread is None:
            self.sync_thread = threading.Thread(target=self.sync_files, daemon=True)
            self.sync_thread.start()

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
