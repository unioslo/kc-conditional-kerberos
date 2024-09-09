package no.uio.keycloak.ConditionalKerberos;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.SpnegoAuthenticator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.http.HttpRequest;
import org.keycloak.authentication.AuthenticationProcessor;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.List;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class ConditionalKerberos extends SpnegoAuthenticator {

    private static Logger logger = Logger.getLogger(ConditionalKerberos.class);

    public static final String WHITELIST_PATTERN = "XForwardedForWhitelistPattern";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
         HttpRequest request = context.getHttpRequest();
        String authorizationHeader = request.getHttpHeaders().getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        logger.info(authorizationHeader);

        String spnegoToken = "";
        
        if (authorizationHeader != null && authorizationHeader.startsWith("Negotiate ")) {
          // Extract the SPNEGO token
          spnegoToken = authorizationHeader.substring("Negotiate ".length());

            if (!isKerberosTicket(context,spnegoToken)) {
              logger.info("Skip Kerberos because of different domain.");
            //  context.attempted();
            //  return;
            }
        } else {
         //   logger.info("No kerberos ticket was sent.");
          //  context.attempted();
          //  return;
        }
        logger.info("Auttempting to authenticate with kerberos");
        
        super.authenticate(context);
    }


    public boolean isKerberosTicket(AuthenticationFlowContext context, String spnegoToken){
      try {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        GSSManager gssManager = GSSManager.getInstance();
        Oid krb5Oid = new Oid("1.2.840.113554.1.2.2");
        GSSContext gssContext = gssManager.createContext((GSSCredential) null);
        byte[] tokenBytes = java.util.Base64.getDecoder().decode(spnegoToken);
        byte[] outToken = gssContext.acceptSecContext(tokenBytes, 0, tokenBytes.length);

        if (!gssContext.isEstablished()) {
            return false; // Authentication context could not be established
        }
        GSSName clientName = gssContext.getSrcName();
        String clientPrincipal = clientName.toString();
        String kerberosPrincipal = config.getConfig().get("kerberos.domain"); 
        logger.info("Client principal: "+clientPrincipal);
        // Check if the client principal is from the expected domain
        if (clientPrincipal.endsWith("@"+kerberosPrincipal)) {
            return true; // Valid ticket from your domain
        }

    } catch (Exception e) {
        e.printStackTrace(); // Handle exceptions appropriately
    }  

       return false;
    }

}
