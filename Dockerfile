FROM tomcat:9.0-jdk11

COPY target/petclinic.war /usr/local/tomcat/webapps/ROOT.war

EXPOSE 8080

CD ["catalina.sh", "run"]
