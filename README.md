# myCVT

"myCVT" , aka. "My Checkpoint Visualisation Tool" is written by myself due to the requirements 
of Checkpoint Firewall reviews, when all you are given by a client is the HTML export from the 
Checkpoint Visualisation Tool. Usually we get given the relevant Object files and the like, which 
can be run through Nipper, however, sometimes this is not the case and you are left with 
thousands of rules of which you need to manually review! :/ boring!

This tool/script aims to speed up this process by parsing and highlighting the various rules that 
may be of interest, when engaging in a IT health check.

Currently as seen in the source, it will flag on rules which have "Any" in the following areas:

* Source field
* Destination field
* Service field

And also a small amount of sensitive services such as:

* SSH
* FTP
* HTTP
* SNMP

etc. amongst others but this can be seen in the source. Please feel free to request more features 
or report bugs in the Github page, and ill be sure to update this as I use this myself during 
engagements!

## Dependencies:

* Python BeautifulSoup4 (usually python2-beautifulsoup4
* Python terminaltables (usually pip install terminaltables)
* Python lxml           (usually python-lxml)

### Usage

<img src="http://i.imgur.com/0J63KHs.png">

### Verbose output

<img src="http://i.imgur.com/fzzAxCA.png">

### Normal output, with CSV file output file

<img src="http://i.imgur.com/s9gaSTB.png">

### Commands 
```
# ./myCVT.py -f fw1.html
# ./myCVT.py -f fw1.html --csv
# ./myCVT.py -f fw1.html -v
```

Have fun and please report your thoughts if you care enough

~ x90
