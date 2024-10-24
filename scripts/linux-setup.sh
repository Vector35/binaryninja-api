#!/bin/bash

# Note is setup script currently does four things:
#
# 1. It creates a binaryninja.desktop file in ${HOME}/.local/share/applications and
#    copies it to the desktop
# 2. It creates a .xml file to add a mime type for .bndb files.
# 3. It adds a binaryninja: url handler.
# 4. Creates .pth python file to add binary ninja to your python path


setvars()
{
	APP="binaryninja"
	APPID="com.vector35.binaryninja"
	NAME="Binary Ninja"
	FILECOMMENT="Binary Ninja Analysis Database"
	APPCOMMENT="Binary Ninja: A Reverse Engineering Platform"
	BNPATH=$(realpath "$(dirname "$(readlink -f "$0")")/..")
	EXEC="${BNPATH}/binaryninja"
	PNG="${BNPATH}/docs/img/logo.png"
	EXT="bndb"
  SHARE="${HOME}/.local/share" #For user only
	DESKTOPFILE="${SHARE}/applications/${APPID}.desktop"
	OLDDESKTOPFILE="${SHARE}/applications/${APP}.desktop"
	MIMEFILE="${SHARE}/mime/packages/application-x-${APP}.xml"
	IMAGEFILE="${SHARE}/pixmaps/application-x-${APP}.png"
}

usage()
{
	echo "Usage: $0 -[ulpdmrsh]
	-u: For uninstall, removes all associations (does NOT remove ${HOME}/.binaryninja)
	-l: Disable creation ${HOME}/.binaryninja/lastrun file
	-p: Disable adding python path .pth file
	-d: Disable adding desktop launcher
	-m: Disable adding mime associations
	-r: Run as root to set system wide preferences (requires sudo permissions)
	-s: Run in headless mode (equivalent to -d -m)
	-h: Display this help
" 1>&2
	exit 1
}

lastrun()
{
	#Contains the last run location, but on systems without a UI this ensures
	#the UI doesn't have to run once for the core to be available.
	if [ -f ${HOME}/.binaryninja/lastrun ]
	then
		echo lastrun already exists, remove to create a new one
	else
		if [ ! -d ${HOME}/.binaryninja ]
		then
			mkdir ${HOME}/.binaryninja
		fi
		echo ${BNPATH} > ${HOME}/.binaryninja/lastrun
	fi
}

pythonpath()
{
	echo Configuring python path
	if [ "$USERINTERACTIVE" == "true" ]
	then
		SILENT=""
	else
		SILENT="-s"
	fi
	if [[ -x "`which python3`" ]]
	then
		python3 -V >/dev/null 2>&1 && python3 "${BNPATH}/scripts/install_api.py" ${SILENT}
	else
		echo "Python3 not found. Not installing BN PTH file."
	fi
}

createdesktopfile()
{
	mkdir -p ${SHARE}/{mime/packages,applications,pixmaps}
	echo Creating .desktop file

	# Desktop File
	read -d '' DESKTOP << EOF
[Desktop Entry]
Name=${NAME}
Exec=${EXEC// /\\\\ } %u
MimeType=application/x-${APP};x-scheme-handler/${APP};
Icon=${PNG// /\\\\s}
Terminal=false
Type=Application
Categories=Utility;
Comment=${APPCOMMENT}
EOF
	read -d '' MIMEAPPS << EOF
[Added Associations]
application/x-executable=${APP}.desktop
application/x-elf=${APP}.desktop
application/x-sharedlib=${APP}.desktop
EOF
	echo "${DESKTOP}" | $SUDO tee ${DESKTOPFILE} >/dev/null
	echo "${MIMEAPPS}" | $SUDO tee -a ${MIMEFILE} >/dev/null
	if [ -f ${OLDDESKTOPFILE} ]
	then
		rm ${OLDDESKTOPFILE}
	fi
	settrusted "${DESKTOPFILE}"
	$SUDO update-desktop-database ${SHARE}/applications
}

settrusted()
{
	$SUDO chmod +x "$1"
	GNOMEVERSION=`gnome-shell --version|awk '{print $3}'`
	MINVERSION=3.36
	# This check is dumb. Thanks Gnome for not only imitating the worst
	# permission models of MacOS and Windows but doing it in a way that isn't
	# even consistent between adjacent LTS versions :facepalm: Note that a
	# reboot or reload of Gnome is required but I'm not going to do it here
	# because the experience is poor.
	if [ $(echo -en "$GNOMEVERSION\n$MINVERSION" | sort -t '.' -k 1,1 -k 2,2 -k 3,3 -g | tail -n1) != $MINVERSION ]
	then
		DBFLAG="true"
	else
		DBFLAG="yes"
	fi
	echo -e "\n\nWARNING: Note that the desktop icon that was created may not be usable until you login again or reboot depending on your GNOME version.\n"
	DBUS_LAUNCH=dbus-launch
	if ! (which dbus-launch > /dev/null); then
		DBUS_LAUNCH=""
	fi
	$SUDO $DBUS_LAUNCH gio set "$1" "metadata::trusted" $DBFLAG
}

createmime()
{
	echo Creating MIME settings
	if [ ! -f ${DESKTOPFILE} -a ! -f ${HOME}/Desktop/${APP}.desktop ]
	then
		createdesktopfile
	fi

	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">
	<mime-type type=\"application/x-${APP}\">
		<comment>${FILECOMMENT}</comment>
		<icon name=\"application-x-${APP}\"/>
		<magic-deleteall/>
		<glob pattern=\"*.${EXT}\"/>
		<glob pattern=\"*.bnpm\"/>
		<glob pattern=\"*.bnta\"/>
		<sub-class-of type=\"application/x-sqlite3\" />
	</mime-type>
</mime-info>"| $SUDO tee ${MIMEFILE} >/dev/null

	#echo Copying icon
	#$SUDO cp "$PNG" "$IMAGEFILE"
	$SUDO cp "${PNG}" "${IMAGEFILE}"
	$SUDO update-mime-database ${SHARE}/mime
}

addtodesktop()
{
	cp "$DESKTOPFILE" "${HOME}/Desktop/${APP}.desktop"
	settrusted "${HOME}/Desktop/${APP}.desktop"
}

uninstall()
{
	rm -i -r "$DESKTOPFILE" "$MIMEFILE" "$IMAGEFILE" "${HOME}/Desktop/${APP}.desktop"
	$SUDO update-mime-database ${SHARE}/mime
	python3 -V >/dev/null 2>&1 && ${SUDO}python3 "${BNPATH}/scripts/install_api.py" -u
	exit 0
}

CREATEDESKTOP=true
CREATEMIME=true
ADDTODESKTOP=true
CREATELASTRUN=true
USERINTERACTIVE=true
PYTHONPATH=true
UNINSTALL=false

while [[ $# -ge 1 ]]
do
	flag="$1"

	case $flag in
		-u)
		UNINSTALL=true
		;;
		-l)
		CREATELASTRUN=false
		;;
		-p)
		PYTHONPATH=false
		;;
		-d)
		ADDTODESKTOP=false
		CREATEDESKTOP=false
		;;
		-m)
		CREATEMIME=false
		;;
		-s)
		ADDTODESKTOP=false
		CREATEMIME=false
		CREATEDESKTOP=false
		USERINTERACTIVE=false
		;;
		-h|*)
		usage
		;;
	esac
	shift
done

setvars

if [ "$UNINSTALL" == "true" ]
then
	uninstall
fi
if [ "$CREATEDESKTOP" == "true" ]
then
	createdesktopfile
fi
if [ "$CREATEMIME" == "true" ]
then
	createmime
fi
if [ "$ADDTODESKTOP" == "true" ]
then
	addtodesktop
fi
if [ "$CREATELASTRUN" == "true" ]
then
	lastrun
fi
if [ "$PYTHONPATH" == "true" ]
then
	pythonpath
fi
