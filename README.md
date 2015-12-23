# mysql320
Provides a Go database driver for mysql versions 3.2 - 5

For use with the built-in Go database/sql driver. The driver name is mysql320. It will automatically choose the correct mysql protocol depending on the server version.

Connect string should be formatted as:

DBNAME/USER/PASSWD
unix:SOCKPATH*DBNAME/USER/PASSWD
unix:SOCKPATH,OPTIONS*DBNAME/USER/PASSWD
tcp:ADDR*DBNAME/USER/PASSWD
tcp:ADDR,OPTIONS*DBNAME/USER/PASSWD
cloudsql:INSTANCE*DBNAME/USER/PASSWD

