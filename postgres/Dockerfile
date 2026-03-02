FROM pgvector/pgvector:pg16
ADD init-multiple-databases.sh /docker-entrypoint-initdb.d/
# Ensure en_US.UTF-8 locale for consistency
ENV LANG=en_US.utf8
ENV LC_ALL=en_US.utf8
ENV LANGUAGE=en_US.utf8