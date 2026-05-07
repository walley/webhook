#!/bin/sh

date > /tmp/syncresult

echo pushie pooshie, sleeping for a bit
#sleep 10

logger -p local6.info "running hook"

cd /var/www/git/intranet
pwd  >> /tmp/syncresult

/usr/bin/git pull 2>&1 >> /tmp/syncresult

rsync -avv --exclude '.git/' /var/www/git/intranet/ /var/www/html/test/intranet/ 2>&1 >> /tmp/syncresult
