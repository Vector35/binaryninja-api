@echo off
set PYTHON=uv run --locked python

if "%1" == "help" (
    echo Please use `make <target>` where <target> is one of
    echo   clean    to clean the folders
    echo   html     to make standalone HTML files
    echo   docset   to make a Dash docset
    exit /b
)

if "%1" == "clean" (
    for %%d in (html docset xml) do (
        if exist "%%d" rmdir /s /q "%%d"
        if exist "%%d" exit /b 1
    )
    exit /b 0
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
