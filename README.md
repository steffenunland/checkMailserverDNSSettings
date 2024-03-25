# mailserver-check

Takes a mailserver domain, checks relevant records for that domain, and returns the records as well
as whether they were found or not.


## dev usage
    `go run main.go -domain domain.tld`

# build
    `go build .`

## usage 
    `./checkMailserver
mailserver-check

Takes a mailserver domain, checks relevant records for that domain, and returns the records as well
as whether they were found or not.
Commands:  -domain string
    	The domain whose records you want to check.`

        e.g.
        `./checkMailserver -domain BesterMenschDerWelt.de`


