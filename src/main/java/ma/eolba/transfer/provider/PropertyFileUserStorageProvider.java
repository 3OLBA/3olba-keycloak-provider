package ma.eolba.transfer.provider;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ma.eolba.transfer.dtos.PersonDTO;
import ma.eolba.transfer.dtos.UserDetailsDto;
import org.jboss.resteasy.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.UnauthorizedException;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.keycloak.storage.user.UserLookupProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.*;

import static ma.eolba.transfer.constante.Constante.*;

public class PropertyFileUserStorageProvider
        implements UserStorageProvider, UserLookupProvider, CredentialInputValidator, CredentialInputUpdater {

    private final Logger logger = Logger.getLogger(PropertyFileUserStorageProvider.class);

    protected KeycloakSession keycloakSession;
    protected ComponentModel componentModel;
    protected Map<String, UserModel> loadedUsers = new HashMap();
    protected Map<String, Object> mapCredentials = new HashMap<>();

    public PropertyFileUserStorageProvider(KeycloakSession keycloakSession, ComponentModel componentModel) {
        this.keycloakSession = keycloakSession;
        this.componentModel = componentModel;
    }

    @Override
    public boolean updateCredential(RealmModel realmModel, UserModel userModel, CredentialInput credentialInput) {
        if (credentialInput.getType().equals(CredentialModel.PASSWORD))
            throw new ReadOnlyException("user is read only for this update");
        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realmModel, UserModel userModel, String s) {

    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realmModel, UserModel userModel) {
        return Collections.EMPTY_SET;

    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        boolean isSupportsCredentialType = credentialType.equals(CredentialModel.PASSWORD);
        return isSupportsCredentialType;
    }

    @Override
    public boolean isConfiguredFor(RealmModel realmModel, UserModel userModel, String s) {
        return true;
    }

    @Override
    public boolean isValid(RealmModel realmModel, UserModel userModel, CredentialInput credentialInput) {

        boolean isAuthenticated = false;
        Map<String, Object> map;
        try {
            logger.info("inside is valide");

            if (!supportsCredentialType(credentialInput.getType()) || !(credentialInput instanceof UserCredentialModel)) {
                return false;
            }

            logger.info("inside is valide before test");
            HttpRequest req = keycloakSession.getContext().getContextObject(HttpRequest.class);

            logger.info("get values ");

            PersonDTO personDTO = getParamUser(req);

            if(personDTO == null) return false;

            checkUser(personDTO);

            PersonDTO personToReturn = new PersonDTO();
            logger.info("mapCredentials => " + mapCredentials);
            logger.info("perso => " + mapCredentials.get("person"));
            if(mapCredentials != null && mapCredentials.get(PERSON) != null){
                logger.info("map is not null ");
                personToReturn = (PersonDTO) mapCredentials.get(PERSON);
                String success = (String) mapCredentials.get(SUCCESS);
                isAuthenticated = TRUE.equals(success);
                logger.info("status is ==> " + success);
            }else {
                logger.info("map or userDetails is null ");
            }
            logger.info(" ######################################### get values from UserModel #########################################");
            logger.info(String.valueOf(userModel.getAttributes().toString()));
            logger.info(String.valueOf(userModel.getAttributes().get(PERSON)));
            logger.info(String.valueOf(userModel.getAttributes().get(AUTHORITIES)));
            logger.info(String.valueOf(userModel.getAttributes().get(USERDETAILS)));
//            userModel.setEmail(personDTO.getEmail());
        } catch (Exception e) {
            logger.warn("inside Exception ");
            logger.warn(" Exception Message : " + e.getMessage());
            e.printStackTrace();
        }
        logger.info("isAuthenticated  => " + isAuthenticated);

        return isAuthenticated;

    }

    @Override
    public void close() {

    }

    @Override
    public UserModel getUserById(String id, RealmModel realmModel) {
        logger.info("GET USER BY ID");
        StorageId storageId = new StorageId(id);
        String username = storageId.getExternalId();
        logger.info("username " + username);
        return getUserByUsername(username, realmModel);
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realmModel) {
        UserModel adapter = loadedUsers.get(username);
        logger.info("getUserByUsername =>  adapter " + adapter);


        if (adapter == null) {
            logger.info("adapter is null");

            adapter = createAdapter(realmModel, username);
            loadedUsers.put(username, adapter);
        }

        return adapter;
    }

    protected UserModel createAdapter(RealmModel realm, final String username) {

        return new AbstractUserAdapter(keycloakSession, realm, componentModel) {

            @Override
            public String getUsername() {
                return username;
            }


            @Override
            public String getEmail() {
                return null;
            }


            @Override
            public Map<String, List<String>> getAttributes() {

                logger.info(" ================================== inside getAttributes ==================================");
                List<String> authorities = new ArrayList<>();
                MultivaluedHashMap userCredentials = new MultivaluedHashMap<String, Object>();

                if (mapCredentials == null || mapCredentials.get(PERSON) == null) {
                    logger.warn("mapCredentials is null ");
                    PersonDTO userDetails = null;
                    HttpRequest req = keycloakSession.getContext().getContextObject(HttpRequest.class);

                    logger.warn("get token from request");
                    if(req != null && req.getFormParameters() != null && req.getFormParameters().get("token") != null && req.getFormParameters().get("token").size() > 0){
                        logger.warn("inside get token from request");
                        String authorization = req.getFormParameters().get("token").get(0);
                        String token = authorization.replace("bearer ", "");

                        String[] split_string = token.split("\\.");
                        String base64EncodedBody = split_string[1];

                        byte[] decodedBytes = Base64.getDecoder().decode(base64EncodedBody);
                        String body = new String(decodedBytes);

                        try {
                            logger.warn("get Attriutes from token");
                            ObjectMapper mapper=new ObjectMapper();
                            Map map = mapper.readValue(body, Map.class);
                            logger.warn("constract userDetail");
                            userDetails = mapper.convertValue(map.get(PERSON), PersonDTO.class);
                            logger.warn("constract authorities");
                            authorities = mapper.convertValue(map.get("authorities"), List.class);

                        } catch (JsonProcessingException e) {
                            userDetails=null;
                            authorities=new ArrayList<>();
                        }
                    }else {
                        logger.warn("! inside get token from request");
                    }


                    userCredentials.add("authorities", authorities);
                    userCredentials.add("userDetails", userDetails);
                }
                else{
                    PersonDTO personDTO = (PersonDTO) mapCredentials.get(PERSON);
                    UserDetailsDto userDetailsDto = (UserDetailsDto) mapCredentials.get(USERDETAILS);
                    String success = (String) mapCredentials.get(SUCCESS);

                    logger.warn("mapCredentials is not null");
                    logger.info("Person =========> " + personDTO);
                    logger.info("UserDetails =========> "+ userDetailsDto);

                    userCredentials.add(AUTHORITIES, mapCredentials.get(AUTHORITIES));
                    userCredentials.add(PERSON, personDTO);
                    userCredentials.add(USERDETAILS, userDetailsDto);
                    userCredentials.add(SUCCESS, success);
                }

                logger.info("  userCredentials size " + userCredentials.size());
                logger.info("  userCredentials  " + userCredentials);
                return userCredentials;

            }
        };
    }

    @Override
    public UserModel getUserByEmail(String s, RealmModel realmModel) {
        return null;
    }

    private void checkUser(PersonDTO personDTO) {
        Map<String, Object> map = null;
        ResponseEntity<Map> response = null;
        HttpHeaders headers = new HttpHeaders();
        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<PersonDTO> request;
        try {
            headers.setContentType(MediaType.APPLICATION_JSON);
            request = new HttpEntity<>(personDTO, headers);
            logger.info("Send request");
            response = restTemplate.postForEntity(  "http://localhost:5055/login/sign-in", request, Map.class);
            logger.info("Response : "+response);

            if(response.getStatusCode().is2xxSuccessful()) {
                logger.info("response success");
                map = (Map<String, Object>) response.getBody();
                ObjectMapper mapper = new ObjectMapper();
                String success = mapper.convertValue(map.get(SUCCESS), String.class) ;
                logger.info("Status is : " + success);
                if(TRUE.equals(success)){
                    List<String> authorities = new ArrayList<>();
                    PersonDTO person = mapper.convertValue(map.get(OBJECT), PersonDTO.class);
                    UserDetailsDto userDetailsDto = new UserDetailsDto(person.getUsername(),person.getRole(),person.getEmail());
                    authorities.add(person.getRole());
                    mapCredentials.put(USERDETAILS, userDetailsDto);
                    mapCredentials.put(AUTHORITIES,authorities);
                    mapCredentials.put(PERSON, person);
                    mapCredentials.put(SUCCESS, success);
                }else{
                    mapCredentials.put(AUTHORITIES, null);
                    mapCredentials.put(USERDETAILS, null);
                }
            }else{
                logger.info("request failed with status " + response.getStatusCode());
            }
        } catch (UnauthorizedException e) {
            logger.info("failed with UnauthorizedException " + e.getMessage());
            mapCredentials.put("authorities", null);
            mapCredentials.put("userDetails", null);
            mapCredentials.put("status", "401");
            e.printStackTrace();
        } catch (Exception e) {
            logger.info("failed with Exception " + e.getMessage());
            mapCredentials.put("authorities", null);
            mapCredentials.put("userDetails", null);
            mapCredentials.put("status", "1001");
            e.printStackTrace();
        }

    }

    private PersonDTO getParamUser(HttpRequest req) throws UnsupportedEncodingException {
        List<String> passwordParam = req.getFormParameters().get(PASSWORD);
        List<String> usernameParam = req.getFormParameters().get(USERNAME);
        List<String> emailParam = req.getFormParameters().get(EMAIL);
        List<String> typeProfileParam = req.getFormParameters().get(TYPE_PROFILE);
        String username = "";
        if(passwordParam == null || emailParam == null || typeProfileParam == null){
            logger.error("Missing params");
            logger.error("email ===> " + emailParam);
            logger.error("Password ===> " + passwordParam);
            logger.error("typeProfile ===> " + typeProfileParam);
            return null;
        }

        String password = URLDecoder.decode(passwordParam.get(0), "UTF-8");
        String email = URLDecoder.decode(emailParam.get(0), "UTF-8");

        if(usernameParam == null){
            username = email.split("@")[0];
        }

        PersonDTO personDTO = new PersonDTO(email, username, password, typeProfileParam.get(0));
        logger.info(personDTO.toString());
        return personDTO;
    }
}
