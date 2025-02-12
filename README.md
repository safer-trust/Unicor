<picture>
  <img src="unicor.png" alt="Unicor logo" width="30%" align="right">
</picture>



The recommended installation path is to use a binary form of unicor, produced by PyInstaller.
(It may be necessary to install dependencies and specifically reference PyMISP)
```
git clone https://github.com/safer-trust/unicor.git
cd unicor/src/
pyinstaller  --add-binary="/usr/local/lib/python3.9/dist-packages/pymisp:pymisp" -F  unicor.py
```
Then the binary will be readily available:
```
 ./dist/unicor 
Usage: unicor [OPTIONS] COMMAND [ARGS]...

Options:
  -c, --config FILE  Read option defaults from the specified yaml file
                     [default: /etc/unicor/config.yml]
  --help             Show this message and exit.

Commands:
  alert       Raise alerts for spotted incidents
  correlate   Correlate input files and output matches
  fetch-iocs  Fetch IOCs from intelligence sources
```

A ELF 64-bit dynamically linked version is also directly available in the [dist directory](https://github.com/safer-trust/unicor/tree/main/src/dist) of the repository.

