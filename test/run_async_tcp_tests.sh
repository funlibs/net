#!/bin/sh
#
# File:   run_tests.sh.sh
# Author: seb
#
# Created on 5 mars 2017, 20:56:09
#

./async_tcp_server &
sleep 1
./async_tcp_client 100
