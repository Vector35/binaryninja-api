@echo off
set PYTHON=poetry run python

if "%1" == "help" (
    echo Please use `make <target>` where <target> is one of
    echo   clean    to clean the folders
    echo   html     to make standalone HTML files
    echo   docset   to make a Dash docset
    exit /b
)

if "%1" == "clean" (
    rmdir /s /q html
    rmdir /s /q docset
    rmdir /s /q xml
    exit /b
)

if "%1" == "html" (
    %PYTHON% build_min_docs.py
    exit /b
)

if "%1" == "docset" (
    %PYTHON% build_min_docs.py --docset
    exit /b
)

echo Unknown target: %1
exit /b 1

