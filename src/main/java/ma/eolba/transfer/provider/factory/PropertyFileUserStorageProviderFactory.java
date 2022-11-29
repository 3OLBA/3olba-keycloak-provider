package ma.eolba.transfer.provider.factory;


import  ma.eolba.transfer.provider.PropertyFileUserStorageProvider;
import org.jboss.resteasy.logging.Logger;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;


public class PropertyFileUserStorageProviderFactory
        implements UserStorageProviderFactory<PropertyFileUserStorageProvider> {

    Logger logger = Logger.getLogger(PropertyFileUserStorageProviderFactory.class);

    public static final String PROVIDER_NAME = "3olba-provider";

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public PropertyFileUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        logger.info("========================================== create ==========================================");
        return new PropertyFileUserStorageProvider(session, model);
    }
}
