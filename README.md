Run the setup first if you're on ubuntu
Just add your api key to the config file and the script should work. Or not. It's 2AM and I'm going to bed.
Also add the attributes you want to the config file, comma seperated (e.g. ports,last_update)

EX:

./shodan_search net:64.233.177.105 -a latitude,longitude -f ports:80
