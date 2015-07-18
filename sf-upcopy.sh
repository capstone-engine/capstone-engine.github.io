#!/bin/bash

# example: ./sf-upcopy.sh _site/download.html 
# example: ./sf-upcopy.sh img/jar.png img

scp $1 aquynh@web.sourceforge.net:/home/project-web/capstone/htdocs/$2

