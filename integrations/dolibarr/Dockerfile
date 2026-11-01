FROM php@sha256:365b7475fde2424a7c0e053aafd2453d11fb8b60e14f6f83b150e97cf624af89 AS runtime
RUN docker-php-ext-install mysqli && a2enmod rewrite
RUN printf 'display_errors=Off\nlog_errors=On\n' > /usr/local/etc/php/conf.d/reproduction.ini

FROM runtime AS buggy
COPY htdocs/ /var/www/html/
COPY conf.php /var/www/html/conf/conf.php
COPY bootstrap.php /opt/reproduction/bootstrap.php
RUN mkdir -p /var/www/documents && chown -R www-data:www-data /var/www/documents
LABEL org.temporal-auth.case="dolibarr-26066" org.temporal-auth.revision="c16313007a90010524cafba67acadcce036b6a9f"

FROM buggy AS fixed
COPY api_multicurrencies.fixed.php /var/www/html/multicurrency/class/api_multicurrencies.class.php
LABEL org.temporal-auth.revision="62ad3d12d2ee86f2f665f341565860f3e88b076a"
