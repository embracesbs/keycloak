package org.keycloak.services.util;

import org.keycloak.OAuthErrorException;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.authorization.*;
import org.keycloak.services.ErrorResponseException;

import javax.ws.rs.core.Response;
import java.util.Collections;
import java.util.HashMap;

import static org.keycloak.models.utils.RepresentationToModel.toModel;

public class ResourceServerDefaultPermissionCreator {

    protected KeycloakSession session;
    protected AuthorizationProvider authorization;
    protected ResourceServer resourceServer;

    public ResourceServerDefaultPermissionCreator(KeycloakSession session, AuthorizationProvider authorization, ResourceServer resourceServer) {
        this.session = session;
        this.authorization = authorization;
        this.resourceServer = resourceServer;
    }

    public void create(ClientModel client){
        createDefaultPermission(createDefaultResource(client), createDefaultPolicy());
    }

    private PolicyRepresentation createDefaultPolicy() {
        PolicyRepresentation defaultPolicy = new PolicyRepresentation();

        defaultPolicy.setName("Default Policy");
        defaultPolicy.setDescription("A policy that grants access only for users within this realm");
        defaultPolicy.setType("js");
        defaultPolicy.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);
        defaultPolicy.setLogic(Logic.POSITIVE);

        HashMap<String, String> defaultPolicyConfig = new HashMap<>();

        defaultPolicyConfig.put("code", "// by default, grants any permission associated with this policy\n$evaluation.grant();\n");

        defaultPolicy.setConfig(defaultPolicyConfig);

        session.setAttribute("ALLOW_CREATE_POLICY", true);

        PolicyStore policyStore = authorization.getStoreFactory().getPolicyStore();

        // validate existing:
        Policy existing = policyStore.findByName(defaultPolicy.getName(), resourceServer.getId());

        if (existing != null) {
            throw new ErrorResponseException("Policy with name [" + defaultPolicy.getName() + "] already exists", "Conflicting policy", Response.Status.CONFLICT);
        }

        // persist:
        policyStore.create(defaultPolicy, resourceServer);

        return defaultPolicy;
    }

    private ResourceRepresentation createDefaultResource(ClientModel client) {
        ResourceRepresentation defaultResource = new ResourceRepresentation();

        defaultResource.setName("Default Resource");
        defaultResource.setUris(Collections.singleton("/*"));
        defaultResource.setType("urn:" + client.getClientId() + ":resources:default");

        ResourceOwnerRepresentation owner = new ResourceOwnerRepresentation();
        owner.setId(resourceServer.getId());
        defaultResource.setOwner(owner);

        String ownerId = owner.getId();

        StoreFactory storeFactory = authorization.getStoreFactory();

        // validate already existing:
        Resource existingResource = storeFactory.getResourceStore().findByName(defaultResource.getName(), ownerId, resourceServer.getId());

        if (existingResource != null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Resource with name [" + defaultResource.getName() + "] already exists.", Response.Status.CONFLICT);
        }

        // persist:
        toModel(defaultResource, resourceServer, authorization);

        return defaultResource;
    }

    private void createDefaultPermission(ResourceRepresentation resource, PolicyRepresentation policy) {
        ResourcePermissionRepresentation defaultPermission = new ResourcePermissionRepresentation();

        defaultPermission.setName("Default Permission");
        defaultPermission.setDescription("A permission that applies to the default resource type");
        defaultPermission.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        defaultPermission.setLogic(Logic.POSITIVE);

        defaultPermission.setResourceType(resource.getType());
        defaultPermission.addPolicy(policy.getName());

        PolicyStore policyStore = authorization.getStoreFactory().getPolicyStore();

        // validate already existing:
        Policy existing = policyStore.findByName(defaultPermission.getName(), resourceServer.getId());

        if (existing != null) {
            throw new ErrorResponseException("Policy with name [" + defaultPermission.getName() + "] already exists", "Conflicting policy", Response.Status.CONFLICT);
        }

        // persist:
        policyStore.create(defaultPermission, resourceServer);

        return;
    }
}
