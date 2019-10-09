# Installation

If pipenv is installed, run 
`pipenv shell` 
then 
`pipenv install`

Otherwise, run
`pip3 install shodan`

# Running

First, add your api key to search.conf in place of YOUR_API_KEY

For information on how to run the client, run
`./shodan_client.py -h`

NOTE:
	Searching each individual ip takes 1 second based on api restrictions.  If you only need a list of open ports, use the **--ports** flag
