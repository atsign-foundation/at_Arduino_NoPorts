FROM nginx:1.28-alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx-router.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
EXPOSE 80
