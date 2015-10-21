## This library is deprecated and should only be used for Lair v1

##Lair Drones##
Lair takes a different approach to uploading, parsing, and ingestion of automated tool output (xml). We push this work off onto client side scripts called drones. These drones connect directly to the database. To use them all you have to do is export an environment variable "MONGO_URL". This variable is probably going to be the same you used for installation


        export MONGO_URL='mongodb://username:password@ip:27017/lair?ssl=true'

With the environment variable set you will need a project id to import data. You can grab this from the upper right corner of the lair dashboard next to the project name. You can now run any drones.


You can install the drones to PATH with pip

        pip install lairdrone-<version>.tar.gz


#### drone-nmap options

drone-nmap is now configurable to accept both -oX and -oG report formats. To have drone-nmap gather information from grepable nmap report files, use:

        drone-nmap <pid> /path/to/nmap-grepable.txt grep

To import XML reports, use:

        drone-nmap <pid> /path/to/nmap.xml xml

or

        drone-nmap <pid> /path/to/nmap.xml

drone-nmap will always default the report format to XML.
