# Use official PHP image with Apache
FROM php:7.4-apache

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Install PHP extensions required for WordPress
RUN docker-php-ext-install mysqli

# Set the working directory inside the container
WORKDIR /var/www/html

# Copy the WordPress files into the container
COPY . /var/www/html

# Set file permissions (adjust if needed)
RUN chown -R www-data:www-data /var/www/html

# Expose port 80
EXPOSE 80
