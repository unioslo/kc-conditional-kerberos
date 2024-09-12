package no.uio.keycloak.ConditionalKerberos;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.SpnegoAuthenticator;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import org.keycloak.authentication.AuthenticationProcessor;

import java.util.Map;
import java.util.regex.Pattern;
import java.util.List;
import java.util.Base64;

import java.net.URI;

import java.time.Instant;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.NewCookie;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.net.util.SubnetUtils.SubnetInfo;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * @author <a href="mailto:franciaa@uio.no">Francis Augusto Medeiros-Logeay</a>
 * @version $Revision: 1 $
 * Based on original code by <a href="https://github.com/slominskir/KeycloakConditionalSpnegoAuthenticator">KeycloakConditionalSpnegoAuthenticator</a>
 */
public class ConditionalKerberos extends SpnegoAuthenticator {

    private static Logger logger = Logger.getLogger(ConditionalKerberos.class);

    public static final String WHITELIST_PATTERN = "XForwardedForWhitelistPattern";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
      AuthenticatorConfigModel config = context.getAuthenticatorConfig();
      String logout = config.getConfig().get("kerberos.logout");
      Boolean allow_logout = true;
      if ((logout == null) || ((logout.equals("false"))){
          allow_logout = false;
      } 
      if (hasCookie(context) && allow_logout ){
        context.attempted();
        return;
      }

      // Check if Kerberos authentication is allowed 
      if (withinAllowedNetworks(context) && (( !hasCookie(context) && allow_logout) || (!allow_logout))) {
            super.authenticate(context);
            setCookieIfSuccessfull(context);
        } else {
                 context.attempted();
                 return;
               }
      if ((context.getStatus() == FlowStatus.SUCCESS) && allow_logout)
      { 
         setCookieIfSuccessfull(context); 
      }
    }

    public boolean withinAllowedNetworks(AuthenticationFlowContext context){
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String networks = config.getConfig().get("kerberos.networks"); 
        String ip_addr = context.getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("X-Forwarded-For");
        boolean kerberos = false;
        // check if user is allowed to use kerberos
        if (networks != null){
          String[] networks_list = networks.split("##"); 
          for (String net : networks_list){
            try 
            {
              SubnetInfo subnet = (new SubnetUtils(net)).getInfo();
              if (subnet.isInRange(ip_addr)){
                kerberos = true;
                logger.debug("IP address within allowed ranges for Kerberos authentication: "+ip_addr); 
                break;
              }
            }catch (Exception e){ logger.warn("Can't parse IP range kerberos allowed in configuration.");}
          }
        }
        //check if the user isn't allowed to use kerberos
        String exclude_networks = config.getConfig().get("kerberos.excluded_networks");
        if (exclude_networks != null){
          String[] exclude_list = exclude_networks.split("##");
          for (String net : exclude_list){
            try 
            {
              SubnetInfo subnet = (new SubnetUtils(net)).getInfo();
              if (subnet.isInRange(ip_addr)){
                kerberos = false;
                logger.debug("IP address within networks excluded for kerberos authentication: "+ip_addr); 
                break;
              }
            }catch (Exception e){ logger.warn("Can't parse IP range in exclude list configuration."); continue;  }
          }
        }
        return kerberos;
    }

    public boolean hasCookie(AuthenticationFlowContext context){
        Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get("__Secure-SKIP_KERBEROS");
        return  cookie != null;
    }

    private void setCookieIfSuccessfull(AuthenticationFlowContext context){
    
     AuthenticatorConfigModel config = context.getAuthenticatorConfig();
     int maxCookieAge = 60 * 60 * 24 ; // 1 day
     if (config != null && config.getConfig().get("cookie.age") != null) 
        {
          maxCookieAge = Integer.valueOf(config.getConfig().get("cookie.age"));
        }
      URI uri = context.getUriInfo().getBaseUriBuilder().path("realms").path(context.getRealm().getName()).build();
      String date = Instant.now().plusSeconds(maxCookieAge).toString();
      String message="true";

      HttpResponse response = context.getSession().getContext().getHttpResponse();
      NewCookie newCookie = new NewCookie.Builder("__Secure-SKIP_KERBEROS").value(message)
                                .path(uri.getRawPath())
                                .maxAge(maxCookieAge)
                                .secure(true)
                                .build();
      response.setCookieIfAbsent(newCookie); 
    }


}
