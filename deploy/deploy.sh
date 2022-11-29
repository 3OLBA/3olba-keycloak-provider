echo ############# start maven install ##############


cd ..

mvn clean install

cp target/transfer-0.0.1-SNAPSHOT-jar-with-dependencies.jar /Users/jaafani/Desktop/3olba_mobile/keycloak-12.0.4/standalone/deployments


echo ############# Finish maven install ############
