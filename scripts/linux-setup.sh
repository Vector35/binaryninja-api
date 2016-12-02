#!/bin/bash

# Note is setup script currently does three things:
#
# 1. It creates a binaryninja.desktop file in ~/.local/share/applications and 
#    copies it to the desktop
# 2. It creates a .xml file to add a mime type for .bndb files.
# 3. It adds a binaryninja: url handler.


APP="binaryninja"
FILECOMMENT="Binary Ninja Analysis Database"
APPCOMMENT="Binary Ninja: A Reverse Engineering Platform"
BNPATH=$(dirname $(readlink -f "$0"))
EXEC="${BNPATH}/binaryninja"
PNG="${BNPATH}/docs/images/logo.png"
EXT="bndb"
SHARE=/usr/share #For system
SUDO="sudo"	 #For system
SHARE=~/.local/share #For user only
SUDO=""				 #For user only
DESKTOPFILE=$SHARE/applications/${APP}.desktop
MIMEFILE=$SHARE/mime/packages/application-x-$APP.xml
IMAGEPATH=$SHARE/pixmaps

createdesktopfile()
{
	mkdir -p $SHARE/{mime/packages,applications,pixmaps}
	echo Creating .desktop file 

	# Desktop File
	echo "[Desktop Entry]
Name=$APP
Exec=$EXEC %u
MimeType=application/x-$APP;x-scheme-handler/$APP;
Icon=$PNG
Terminal=false
Type=Application
Categories=Utility;
Comment=$APPCOMMENT
" | $SUDO tee $DESKTOPFILE >/dev/null
	$SUDO chmod +x $DESKTOPFILE

	$SUDO update-desktop-database $SHARE/applications
}

createmime() 
{
	echo Creating MIME settings
	if [ ! -f $DESKTOPFILE ]
	then
		createdesktopfile
	fi

	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">
	<mime-type type=\"application/x-$APP\">
		<comment>$FILECOMMENT</comment>
		<icon name=\"application-x-$APP\"/>
		<magic-deleteall/>
		<glob pattern=\"*.$EXT\"/>
		<sub-class-of type=\"application/x-sqlite3\" />
	</mime-type>
</mime-info>"| $SUDO tee $MIMEFILE >/dev/null

	#echo Copying icon
	#$SUDO cp $PNG $IMAGEPATH/$APP.png
	#$SUDO cp $PNG $IMAGEPATH/application-x-$APP.png

	$SUDO update-mime-database $SHARE/mime
}

addtodesktop()
{
	cp $DESKTOPFILE ~/Desktop
}

#TODO: Make these optional...
createdesktopfile
createmime
addtodesktop
