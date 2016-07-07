package org.jasig.cas.support.openid;

import java.util.Collections;
import java.util.Map;

import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.ticket.InvalidTicketException;
import org.jasig.cas.ticket.ServiceTicket;
import org.jasig.cas.ticket.TicketGrantingTicket;
import org.jasig.cas.util.ApplicationContextProvider;
import org.openid4java.message.MessageException;
import org.openid4java.message.ax.FetchResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpenIdExchangeAttributeReleaser {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    public OpenIdExchangeAttributeReleaser() {}

    /**
     * A map containing the mapping to be done between the CAS original attributes,
     * and the OpenId Attribute exchanges.
     */
    private Map<String,String> attributeMapping = Collections.emptyMap();
    
    /**
     * a map which associates the OpenId AX attribute names to their URI.
     */
    private Map<String,String> attributeUris = Collections.emptyMap();

    /**
     * Actually do the attribute release, on behalf of OpenIdv2.
     *
     * @param attributes the parameters available on the principal
     * @return the fetchResponse
     */
    public FetchResponse doRelease(Map<String, Object> attributes) {
        FetchResponse fetchResponse = FetchResponse.createFetchResponse();
            for (String key : attributes.keySet()) {
                String mapped = attributeMapping.get(key);
                if (mapped == null) {
                    logger.warn("No mapping found for key:" + key + ". Skipping attribute");
                    continue;
                }
                String attrUri = attributeUris.get(mapped);
                if (attrUri == null) {
                    logger.warn("No attribute uri found for key:" + mapped + ". Skipping attribute");
                    continue;
                }
                try {
                    fetchResponse.addAttribute(mapped, attrUri, attributes.get(key).toString());
                } catch (MessageException e) {
                    logger.error("Unable to add attribute " + mapped, e);
                }
            }
        return fetchResponse;
    }

    public void setAttributeUris(final Map<String, String> attributeUris) {
        this.attributeUris = attributeUris;
    }

    public void setAttributeMapping(Map<String, String> attributeMapping) {
        this.attributeMapping = attributeMapping;
    }
}
