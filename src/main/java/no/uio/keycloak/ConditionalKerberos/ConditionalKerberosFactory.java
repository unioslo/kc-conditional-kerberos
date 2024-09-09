package no.uio.keycloak.ConditionalKerberos;

import java.util.Arrays;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class ConditionalKerberosFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "conditional-auth-spnego";
    static ConditionalKerberos SINGLETON = new ConditionalKerberos();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return UserCredentialModel.KERBEROS;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Conditional Kerberos";
    }

    @Override
    public String getHelpText() {
        return "Conditionally attempt Kerberos authentication based on existence of a Negotiate header and only for tickets on the right domain.";
    }

   @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("kerberos.domain");
        property.setLabel("Kerberos domain");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("The allowed realm for Kerberos authentication.");
        configProperties.add(property);
    }


    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }    
}
