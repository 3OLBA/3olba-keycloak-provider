package ma.eolba.transfer;

import com.fasterxml.jackson.databind.ObjectMapper;
import  ma.eolba.transfer.dtos.UserDetailsDto;
import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.UnauthorizedException;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LdapOIDCProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    public static final String PROVIDER_ID = "oidc-ldapProtocolMapper";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();
    private static final Logger logger = Logger.getLogger(LdapOIDCProtocolMapper.class);
    private  final Map<String, Object> mapCredentials = new HashMap<>();
    ObjectMapper mapper=new ObjectMapper();

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Ldap UserDetail/Authorities Mapper";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "some help text";
    }


    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession keycloakSession,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        try {
            UserDetailsDto userDetailsDto = null;
            List<String> authorities = null;
            HttpRequest req = keycloakSession.getContext().getContextObject(HttpRequest.class);
            String grantType = req.getFormParameters().get("grant_type").get(0);
            logger.info("#######   transformAccessToken #######  ");

            if (grantType.equals("refresh_token")) {
                logger.info("#######   in refresh_token #######  ");
                //                logger.info("#######   in refresh_token ####### : " + userSession.getUser().getFirstAttribute("userDetails"));
                //                logger.info("#######   in refresh_token ####### : " + userSession.getUser().getAttribute("userDetails"));
                ////                try {
                //                    userDetailsDto = mapper.convertValue(userSession.getUser().getAttribute("userDetails"),UserDetailsDto.class);
                //                    authorities=userDetailsDto.getAuthorities();
                //                    userDetailsDto.setAuthorities(null);
                ////                } catch (JsonProcessingException e) {
                ////                }

                authorities = (List<String>) mapCredentials.get("authorities_" + userSession.getLoginUsername());
                userDetailsDto = (UserDetailsDto) mapCredentials.get("userDetails_" + userSession.getLoginUsername());
                if (userDetailsDto == null) {
                    logger.info("#######   authorities/userDetails not found  ######");
                    return null;
                }
            } else {
                String username = req.getFormParameters().get("username").get(0);
                String codeBanque = req.getFormParameters().get("codeBanque").get(0);
                String typeProfil = req.getFormParameters().get("typeProfil").get(0);
                String canal = req.getFormParameters().get("canal") != null ? req.getFormParameters().get("canal").get(0) : "Mobile";
                String langue = (req.getFormParameters() != null && req.getFormParameters().get("langue") != null) ? req.getFormParameters().get("langue").get(0) : null;

                String urlGateway = "";
                logger.warn("values ==> username : " + username + ", code Banque : " + codeBanque + ", code lanque : " + langue + ", type Profil : " + typeProfil + ", baseUrl : " + urlGateway + ", canal : " + canal + ", langue : " + langue);

                userDetailsDto = getUserByUsername(username, codeBanque, langue, typeProfil, urlGateway, canal);
                if (userDetailsDto.getStatut() == null || !userDetailsDto.getStatut().equals("success")) {
                    logger.info("#######   Invalid user (" + userDetailsDto.getStatut() + ")##############");
                    throw new RuntimeException("#######   Invalid user ##############");
                }
                //                try {
                //                    MultivaluedHashMap userCredentials = new MultivaluedHashMap<String, Object>();
                //                    userCredentials.add("userDetails", userDetailsDto);
                //                    userSession.getUser().getAttributes().putAll(userCredentials);
                //                    userSession.getUser().setAttribute("userDetails", Arrays.asList(mapper.writeValueAsString(userDetailsDto)));
                //                } catch (JsonProcessingException e) {
                //                }
                authorities.add(userDetailsDto.getRole());
                userDetailsDto.setAuthorities(null);
                mapCredentials.put("authorities_" + username, authorities);
                mapCredentials.put("userDetails_" + username, userDetailsDto);
            }
            token.getOtherClaims().put("authorities", authorities);
            token.getOtherClaims().put("userDetails", userDetailsDto);
        } catch (Exception e) {

        }

        setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);
        return token;
    }

    public static ProtocolMapperModel create(String name,
                                             boolean accessToken, boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<String, String>();
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        mapper.setConfig(config);
        return mapper;
    }


    private UserDetailsDto getUserByUsername(String username,
                                                  String codeBanque,
                                                  String langue,
                                                  String typeProfil,
                                                  String urlGateway,
                                                  String canal) {
        Map<String, Object> map = null;
        ResponseEntity<Map> response = null;
        HttpHeaders headers = new HttpHeaders();
        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> request = null;
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

        try {

            logger.info("Constract header and params");

            headers.add("codeBanque", codeBanque);
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            params.add("username", username);
            params.add("password", "");
            params.add("codeBanque", codeBanque);
            params.add("typeProfil", typeProfil);
            params.add("canal", canal);

            request = new HttpEntity<>(params, headers);

            logger.info("Send request");

            response = restTemplate.postForEntity("http://localhost:5055/login/sign-in", request, Map.class);

            if (response.getStatusCode().is2xxSuccessful()) {

                logger.info("response success");

                map = (Map<String, Object>) response.getBody();

                ObjectMapper mapper = new ObjectMapper();
                logger.info("Befor map response");
                UserDetailsDto user = mapper.convertValue(map.get("userDetails"), UserDetailsDto.class);
                logger.info("Map response Success");

                logger.info("Status is : " + user);

//                if ("success".equals(user.getStatut())) {

                    return user;

//                } else {
//                    return null;
//                }


            } else {
                logger.info("request failed with status " + response.getStatusCode());
            }
        } catch (UnauthorizedException e) {
            logger.error("failed with UnauthorizedException " + e.getMessage());
        } catch (Exception e) {
            logger.error("failed with Exception " + e.getMessage());
        }
        return null;
    }
}
