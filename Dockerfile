FROM tomcat:9.0-jdk111

COPY target/petlinic.war /usr/local/tomcat/webapps/ROOT.war

EXPSE 8080

CMD ["catalina.sh", "run"]
