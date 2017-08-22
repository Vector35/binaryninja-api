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
	FILECOMMENT="Binary Ninja Analysis Database"
	APPCOMMENT="Binary Ninja: A Reverse Engineering Platform"
	BNPATH=$(dirname $(readlink -f "$0"))
	EXEC="${BNPATH}/binaryninja"
	PNG="${BNPATH}/docs/images/logo.png"
	EXT="bndb"
	if [ "$ROOT" == "root" ]
	then
		SHARE="/usr/share" #For system
		SUDO="sudo "       #For system
	else
		SHARE="${HOME}/.local/share" #For user only
		SUDO=""                #For user only
	fi
	DESKTOPFILE="${SHARE}/applications/${APP}.desktop"
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
		echo ${BNPATH} > ${HOME}/.binaryninja/lastrun
	fi
}

pythonpath()
{
	echo Configuring python path
	${SUDO}python ${BNPATH}/install_api.py $ROOT
}

createdesktopfile()
{
	mkdir -p ${SHARE}/{mime/packages,applications,pixmaps}
	echo Creating .desktop file

	# Desktop File
	read -d '' DESKTOP << EOF
[Desktop Entry]
Name=${APP}
Exec=${EXEC} %u
MimeType=application/x-${APP};x-scheme-handler/${APP};
Icon=${PNG}
Terminal=false
Type=Application
Categories=Utility;
Comment=${APPCOMMENT}
EOF
	if [ "${ROOT}" == "root" ]
	then
		echo ${DESKTOP} | $SUDO tee ${DESKTOPFILE} >/dev/null
		$SUDO chmod +x ${DESKTOPFILE}
		$SUDO update-desktop-database ${SHARE}/applications
	else
		echo ${DESKTOP} > ${HOME}/Desktop/${APP}.desktop
	fi
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
		<sub-class-of type=\"application/x-sqlite3\" />
	</mime-type>
</mime-info>"| $SUDO tee ${MIMEFILE} >/dev/null

	#echo Copying icon
	#$SUDO cp $PNG $IMAGEFILE
	if [ "${ROOT}" == "root" ]
	then
		$SUDO cp ${PNG} ${IMAGEFILE}
		$SUDO update-mime-database ${SHARE}/mime
	fi

}

addtodesktop()
{
	cp $DESKTOPFILE ${HOME}/Desktop
}

uninstall()
{
	rm -i -r $DESKTOPFILE $MIMEFILE $IMAGEFILE
	if [ "$ROOT" == "root" ]
	then
		$SUDO update-mime-database ${SHARE}/mime
	fi
	exit 0
}



ROOT=user
CREATEDESKTOP=true
CREATEMIME=true
ADDTODESKTOP=true
CREATELASTRUN=true
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
		;;
		-m)
		CREATEMIME=false
		;;
		-r)
		ROOT=root
		;;
		-s)
		ADDTODESKTOP=false
		CREATEMIME=false
		CREATEDESKTOP=false
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
