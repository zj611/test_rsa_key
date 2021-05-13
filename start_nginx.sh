docker run --name nginx-test \
-p 8088:8081 -d \
-v /Users/junzhang/Documents/code/tyk/nginx_for_forge/files/nginx.conf:/etc/nginx/nginx.conf \
-v /Users/junzhang/Documents/code/tyk/nginx_for_forge/files:/files \
nginx:latest
