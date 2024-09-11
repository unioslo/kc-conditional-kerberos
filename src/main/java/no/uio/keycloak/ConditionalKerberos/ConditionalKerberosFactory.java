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
    public static final String PROVIDER_ID = "conditional-kerberos-login";
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
        property.setName("kerberos.logout");
        property.setLabel("Skip kerberos on new login");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("When this is set, a cookie is set after a successfull authentication. If the user logs out, the cookie will be checked when logging in to prevent kerberos authentication.");
        configProperties.add(property);
    }


    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("cookie.age");
        property.setLabel("Cookie age");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("When logging in with Kerberos, a cookie is saved to prevent a new automatic login with Kerberos. This allows for username/password login after logging out/.");
        configProperties.add(property);
    }


    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("kerberos.networks");
        property.setLabel("IP ranges for kerberos login");
        property.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        property.setHelpText("Only hosts within these IP ranges (in CIDR format) are allowed to login with Kerberos. If empty, no kerberos login will be allowed.");
        configProperties.add(property);
    }


    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("kerberos.excluded_networks");
        property.setLabel("IP ranges to exclude from Kerberos login");
        property.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        property.setHelpText("Exclude these networks from the networks above.");
        configProperties.add(property);
    }


    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }    
}
