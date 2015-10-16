# evs-go
An Email Validation Server written in GO language.  
It's purpose is to check each email address if it is valid by checking the MX records and by doing an actual communication with the SMTP server(no email is actually sent).  
The results are interpreted based on a list of regular expressions. If the email is valid (see known issues) you will get back a text starting with the OK wording, otherwise, you will get back the exact rejection reason, see examples for details.  

### Install  
```
# clone this repository locally (or download it) :  
$ mkdir evs-go && cd evs-go && git clone https://github.com/twisted1919/evs-go.git .  

# install go dependencies:  
$ go get github.com/julienschmidt/httprouter  
$ go get github.com/asaskevich/govalidator

# build the binary:  
$ go build -o evs-go  

# if needed, edit config.json accordingly
```

### Usage
Start the server with proper flags, use -help to see available options:
```
./evs-go -help  
```
While the server is running, you can connect to it using curl or any other programming language (see examples folder for PHP example) and start shoving emails at it and wait for results.

### Example response server/client
```bash
// server
$ ./evs-go -verbose=true -vduration=true
Worker # 2 verified idontexist@mailwizz.com in 2.157450155s
Worker # 0 verified contact@mailwizz.com in 2.212217376s
Worker # 1 verified contact@onetwist.com in 5.469096688s
```
```php
// client
[status] => success
[message] => Request completed, verified 3 emails in 5.469423314s
[emails] =>
    (
        [contact@mailwizz.com] => OK [took 2.212217376s]
        [contact@onetwist.com] => 550 5.1.1 The email account that you tried to reach does not exist. Please try [took 5.469096688s]
        [idontexist@mailwizz.com] => 550 5.1.1 <idontexist@mailwizz.com>: Recipient address rejected: User unknown in virtual mailbox table [took 2.157450155s]
    )
```

### Notes  
* command line flags take priority over the ones from configuration file  
* make sure you have RDNS records for your IP(s) running the server  
* make sure you use -email.from flag to set your from email address  
* make sure you use -server.password flag to set a password if the server listens on a public interface  
* set -verbose=true and -vduration=true in order to get some debug information
* do not abuse this tool, it can be a very useful tool but also can work against you if not used properly  

### Known issues  
Some providers, like Yahoo, might report false positives simply because they accept any emails you shove at them. Currently i don't have a workaround for this. feel free to suggest one.


Enjoy.
