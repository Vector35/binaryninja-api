# update snippets
#
# Automatically download and update this collection of snippets to your local snippet folder

from zipfile import ZipFile
from tempfile import TemporaryFile
import os

#TODO: Merge remote with local description or hotkey changes (AKA: if filename matches, skip the first two lines, truncate, re-write the rest)

domain = b'https://gist.github.com'
path = b'/psifertex/6fbc7532f536775194edd26290892ef7' # Feel free to adapt to your own setup
archive = path + b'/archive/'
subfolder = 'default'                                 # Change to save the snippets to a different sub-folder
tab2space = False
width = 4

def download(url):
    # Can also use 'CoreDownloadProvider' or 'PythonDownloadProvider' as keys here
    provider = DownloadProvider[Settings().get_string('network.downloadProviderName')].create_instance()
    code, data = provider.get_response(url)
    if code == 0:
        return data
    else:
        raise ConnectionError("Unsuccessful download of %s" % url)

def update_snippets():
    if not interaction.show_message_box('Warning', "Use at your own risk. Do you want to automatically overwrite local snippets from gist?", buttons=MessageBoxButtonSet.YesNoButtonSet):
        return
    snippetPath = os.path.realpath(os.path.join(user_plugin_path(), '..', 'snippets', subfolder))
    if not os.path.isdir(snippetPath):
        os.makedirs(snippetPath)
    url = domain + path
    log_info("Downloading from: %s" % url)
    source = download(url)
    zipPath = [s for s in source.split(b'\"') if s.endswith(b'.zip') and archive in s]
    if len(zipPath) != 2:
        log_error("Update failed.")
        return
    url = domain + zipPath[0]

    log_info("Downloading from: %s" % url)
    zip = download(url)
    with TemporaryFile() as f:
        f.write(zip)
        with ZipFile(f, 'r') as zip:
            for item in zip.infolist():
                if item.filename[-1] == '/':
                    continue
                basename = os.path.basename(item.filename)
                with open(os.path.join(snippetPath, basename), 'wb') as f:
                    if tab2space:
                        f.write(zip.read(item).replace(b'\t', b' ' * width))
                    else:
                        f.write(zip.read(item))
                    log_info("Extracting %s" % item.filename)

update_snippets()
