child_process = require('child_process');

function run(result)
{
    if (!result)
        return;

    if (process.platform == "darwin")
        child_process.spawn("/usr/bin/open", ["build/html/index.html"])
    else if (process.platform == "linux")
        child_process.spawn("/usr/bin/xdg-open", ["build/html/index.html"])
    else
        child_process.spawn("start", ["build\\html\\index.html"])
}

if ((process.platform == "darwin") || (process.platform == "linux"))
{
    matchStr = "(?<file>[\\/0-9a-zA-Z\\._]+):(?<line>\\d+):(?<col>\\d+):\\s+(?<message>.+)";
    module.exports = {
        cmd: "make html",
        name: "build and show",
        sh: true,
        cwd: "{PROJECT_PATH}",
        errorMatch: matchStr,
        postBuild: run,
        targets: {
            "html": {
                cmd: "make html",
                sh: true,
                cwd: "{PROJECT_PATH}",
                errorMatch: matchStr,
            },
            "dummy": {
                cmd: "make dummy",
                sh: true,
                cwd: "{PROJECT_PATH}"
            }
        }
    };
}
else
{
    matchStr = "(?<file>.+)\\((?<line>\\d+)\\): (?<message>.+)";
    module.exports = {
        cmd: "make.bat html",
        name: "build and show",
        sh: true,
        cwd: "{PROJECT_PATH}",
        errorMatch: matchStr,
        postBuild: run,
        targets: {
            "html": {
                cmd: "make.bat html",
                sh: true,
                cwd: "{PROJECT_PATH}",
                errorMatch: matchStr,
            },
            "dummy": {
                cmd: "make.bat dummy",
                sh: true,
                cwd: "{PROJECT_PATH}"
            }
        }
    };
}
