FROM php:8.3-apache

RUN a2enmod rewrite

COPY pheditor.php /var/www/html/pheditor.php
COPY pheditor.php /var/www/html/index.php

RUN mkdir -p /var/www/html/.phedhistory && chown -R www-data:www-data /var/www/html

EXPOSE 80

CMD ["apache2-foreground"]
