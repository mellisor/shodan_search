Run the setup first if you're on ubuntu
Just add your api key to the config file and the script should work.
Also add the attributes you want to the config file, comma seperated (e.g. ports,last_update)

EX:

./shodan_search net:64.233.177.105 -a latitude,longitude -f ports:80

EX:

./shodan_search net:64.233.177.105 -a all -f ports:80,443

You can also request an IP scan

EX:

./shodan_search scan:64.233.177.105

UPDATE: DON'T USE shodan_search, USE SHODAN_CLIENT, it's much more useful
