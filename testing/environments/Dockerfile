# Basic debian file with curl, wget and nano installed to fetch files
# an update config files
FROM debian:bullseye-20221219
MAINTAINER Nicolas Ruflin <ruflin@elastic.co>

RUN apt-get update && \
    apt-get install -y curl nano wget zip && \
    apt-get clean
